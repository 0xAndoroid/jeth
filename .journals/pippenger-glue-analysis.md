# pippenger bucket-add row census + fixes (block 25905781, opt-amber guest ELF, Sep 5 06:33)

Source: `llvm-objdump -d` of `jeth_core::recovery_batch::pippenger` (0x8009c088, 0x3a40 bytes) → /tmp/pippenger-glue/pippenger.asm
(raw encodings: pippenger-raw.asm). Inline row counts: /tmp/pippenger-glue/count_mulq.py (emulates
jolt-inlines/secp256k1/src/sequence_builder.rs `MulqBuilder::inline_sequence`).

## 0. Premise correction: ≈39k EC ops, not 30k; ≈570 equations, not 434

* Measured (data/25905781/profile-waveI-rows.log:17): recovery_msm = 12,466,721 real + 21,225,538 virtual.
* Per generic affine add (census below): ≈316 real + ≈545 virtual. 21,225,538 / 545 = 38.9k ops; 12,466,721 / 316 = 39.4k ops. Both agree on **N ≈ 39k**.
* 39k = 16 windows × T_half·(255/256) − 2,176 first-add copies + 4,352 reduction adds + 120 doubles ⇒ T_half ≈ 2,300 ⇒ ≈1,150 terms ⇒ **≈570 equations**.
  Reason: `crypto.rs:115 inline_ecrecover` feeds `recovery_batch::recover` for tx senders AND the ecrecover precompile (crypto.rs:100) AND EIP-7702 authority recovery, so the batch is 434 tx + ≈140 precompile/7702 recoveries.
* Consequence: real rows per add are ≈316, not ≈405; virtual ≈545, not ≈670. Total ≈ **862 rows per affine add**.

## 1. Virtual rows per inline (sequence_builder.rs, Fq = is_scalar_field=false)

| inline | emitted rows | + inline-register reset rows (materialize.rs:157, one ADDI per released inline reg) | total rows | counted real (anchor, mod.rs:1137) | virtual |
|---|---|---|---|---|---|
| MULQ (funct3 0) | 170 | 16 (a4 b4 w4 p aux r2) | 186 | 1 | 185 |
| SQUAREQ (1) | 154 | 13 (a4 w4 p aux aux2 r2) | 167 | 1 | 166 |
| DIVQ (2) | 178 | 16 | 194 | 1 | 193 |
| affine add (1 div + 1 sq + 1 mul) | | | 547 | 3 | **544** |

Shifts are also virtual sequences (jolt-program/src/expand/shifts/): `srl`/`sll` = 2 rows (bitmask + op), `slli`/`srli`/`srai` = 1 row.
Digit extraction costs ~1.5 virtual rows/term-window; `dbl()` in `double()` costs 7 shift rows (only 120 doubles) → both negligible.
No emitted kind inside MulqBuilder is source-only (grammar.rs:391 list), so no nested expansion; LD/SD/MUL/MULHU/ADD/SLTU/LUI/advice/asserts are 1 row each.

## 2. Real-row census of one generic bucket add (non-top window loop, 0x8009cb1e–0x8009d5da)

Branch model: limb-3 compare decides in 1–2 rows; “b > a → add p” taken with prob ½; add carry/≥p correction prob ½.
Fq sub (ark `sub_assign`, montgomery_backend.rs:112) = compare 1–2 + [add p: 16 rows incl. c.j, ×½] + sub_with_borrow 20 = **≈29.5**.
Fq add (montgomery_backend.rs:99 `add_with_carry` + `subtract_modulus_with_carry`) = 21 sum/check + 4 carry test + [15 subtract p ×½] = **≈32.5**.

| category | rows | where (asm addr) |
|---|---|---|
| loop/term bookkeeping: s9 stride, `biased>>shift` (1 or 2 limbs, srl/sll), mask, digit==0 test, abs(digit), bounds check, `buckets[idx]` addr, select point/negated (slti, slli, add) | 24 | cb1e–cb36, cb3a–cb60, cb64–cb80, cb94–cba4 |
| is_infinity(self): 4 ld + 3 or + bnez; is_infinity(other): addr 2 + 4 ld + 3 or + bnez; x1==x2: 1 bne | 19 | cb84–cba6, cbc2–cbdc, cbf4 |
| load self.y + other.y | 8 | cf02–cf1e |
| Fq sub y1−y2 (+4 sd numerator → 0x208) | 33.5 | cf22–cfea |
| reload other.x (4 ld) + addi | 5 | cfee–cff8 |
| Fq sub x1−x2 (+4 sd denominator → 0x228) | 33.5 | cffc–d092 |
| DIV glue: 4× `sd zero` (the `let mut e=[0u64;4]` in sdk.rs:272) + addi4spn + anchor | 6 | d096–d0a0 |
| canonical check of s (ld + bne taken) | 2 | d0a4–d0a6 |
| move s → square input: 4 ld + 4 `sd zero` + 4 sd + addi4spn + anchor | 14 | d0c0–d0dc |
| canonical check of s² (4 ld reused + bne) | 5 | d0e0–d0e8 |
| reload self.x (4 ld) + reload other.x (4 ld) + constants | 10 | d0fc–d118 |
| Fq add x1+x2 | 32.5 | d11c–d198 |
| Fq sub s²−(x1+x2) → x3 in regs | 29.5 | d19a–d232 |
| Fq sub x1−x3 (+3 `and rd,rs,-1` no-ops, 4 `sd zero`, 4 sd operand) | 42 | d236–d2ea |
| MUL glue: 2 addi + anchor | 3 | d2ee–d2f4 |
| canonical check of product (4 ld + bne) | 5 | d2f8–d300 |
| reload self.y (4 ld) | 4 | d314–d320 |
| Fq sub prod−y1 (+2 spill reloads / jal) | 32.5 | d324–d366, cab0–cafc |
| bucket write-back 8 sd | 8 | cafe–cb1a |
| **total real** | **≈316** | |

Roll-up per add: 6 software Fq add/sub ≈ **183 rows (58% of real)**; memory glue ≈ **88** (16 operand sd, 12 zero-fill sd, 8 copy s, 16 redundant reloads, 12 result ld, 8 write-back, 16 initial ld); bookkeeping 24; infinity/eq 19 (incl. 8 loads reused later); canonical checks ≈4 branches; anchors 3.
Grand total ≈ 316 real + 544 virtual + ~1.5 virtual (shifts) ≈ **862 rows**; 39k ops × 862 ≈ 33.6M ✓ (measured 33,692,259).
First-add copy path (bucket infinite): ≈60 rows (cf5e: 8 ld + 8 sd + bookkeeping); ≈2.2k of them → 0.13M rows, ignore.
Top-window loop (d628–…) and reduction loop (e126–…) are the same inlined `add` with identical glue (e.g. reduction: e1da 4× `sd zero` before DIV at e1ec).

## 3. Fixes, ranked (N = 39k generic ops on 781; phase = 33.7M rows = 5.2% of 628M block)

1. **Fused affine-add inline `ADDPTQ` (jolt worktree; funct3 0x03 is “RESERVED” in secp256k1/src/lib.rs:6).** Advice = (λ, x3, y3); sequence checks three mulq-style identities with the quotient absorbing p-multiples: λ·(x1−x2) ≡ y1−y2, λ² ≡ x3+x1+x2, λ·(x1−x3) ≡ y3+y1. Cost estimate: 3 × (16 partial products ×3.5 + w·p′ 4 mac ≈ 28 + asserts ≈ 10) ≈ 280; five 4-limb add/sub chains without modular correction ≈ 5×20 = 100; 16 ld + 8 sd; canonical range check of x3,y3 ≈ 10; ~25 reset rows ⇒ **≈440 rows** vs today’s 547 virtual + ~250 real glue. Caller keeps only infinity/equality/bookkeeping (~45 rows) and the inline writes the bucket slot directly. Per op ≈ 862 → ≈490: **−370 rows × 39k ≈ −14M rows on 781 (≈ −42% of phase, ≈ −2.3% of block; conservative −10M if the sequence lands at 550)**. Effort: 2–3 days (builder + advice fn + host reference/tests + `register_inlines!` in host.rs + fixture/parity-hash regen + sdk wrapper `add_nonzero_into` + jeth call sites). Needs ≥24 inline vregs live at peak; stream operands through memory if the pool is 16.
2. **Merge duplicate `key` terms (jeth-only, recovery_batch.rs:151).** Same sender ⇒ same Q; sum the (λ·r) scalars before `pippenger` (Fr add ≈ 40 rows) and drop 2 half-terms × 16 windows ≈ 32 bucket adds ≈ **27k rows per repeated key**. Repeat rate unmeasured (senders not decodable here); 10–15% repeats of ≈570 ⇒ 55–85 dups ⇒ **−1.5 … −2.3M rows**. Effort 1–2 h (sort/merge by point limbs). Measure first: count distinct `key` in the batch.
3. **`MaybeUninit` output buffers in secp256k1/src/sdk.rs mul/square/div (jolt-side, no registration/fixture change).** Removes 12 zero-fill rows/op (d096, d0c8, d2b8 etc.) and lets the compiler reuse the DIV output as SQUARE input (−8 copy rows): **−12…−20 rows × 39k ≈ −0.5…−0.8M**. Effort 30 min.
4. **Glue restructure in jolt-inlines/sdk/src/ec.rs `add`** (compute `x1+x2`, `x1−x2`, `y1−y2` first while limbs are in registers; pass `&mut` result slots): cuts the 16 redundant reloads and 3–4 `and -1` artifacts ⇒ ≈ −15 rows/op ≈ **−0.6M**. Effort 1 h, compiler-dependent.
5. **`add_nonzero` / skip other.is_infinity when the term is known finite (jeth, ec.rs):** saves 2 addr + 3 or + 1 bnez ≈ 6 rows/op (the 4 ld of other.x are needed anyway) ≈ **−0.23M**. Trivial, but tiny.
6. **Window width:** w=9 ⇒ 15 windows: 15×2,300 − 15×256 + 15×2×256 = 38.6k ops vs 39.1k at w=8 (−1.3%); w=7 worse. Not worth it.
7. **Fq add/sub/neg `.insn` inlines — REJECT.** Virtual sequences are straight-line (no branches, no carry flag, no cmov): 4-limb add = 17 rows, +2^256−p test 10, mask-select 13, 8 ld + 4 sd, ~12 resets ⇒ **≈65 rows** vs the compiled branchy add at 25–39 (avg 32.5) and sub at 21–38 (avg 29.5). Same for sub/neg. Only a fused multiply-accumulate (fix 1) beats software because the quotient advice absorbs the modular correction.
8. **Negated-point precompute / Term layout:** per-term select is 3 rows; precompute costs ≈2,300×38 ≈ 0.09M once. Keep. Term is 160 B (point 0x00, negated 0x40, biased 0x80, top 0x90); hot fields fit one cache line; no gain.

Decision: do 3 (30 min, safe) + 2 (after counting repeats) now; 1 is the only fix that changes the phase materially and should be a jolt-side lane.
