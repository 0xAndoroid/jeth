# ADDPTQ — fused secp256k1 affine point add inline (design spec)

Worktree: /Volumes/Dev/worktrees/jolt/jolt-amber (branch jolt-amber). All paths relative to it unless noted.
Notation: p = secp256k1 Fq modulus = 2^256 − p′, p′ = 2^32 + 977 (`sequence_builder.rs:198` LUI (1<<32)+977). Limbs LE u64, x[0] lowest.

## 0. Verdict (census correction)

| item | census (/tmp/pippenger-glue/analysis.md §3.1) | this spec |
|---|---|---|
| per-identity engine cost | ≈93 rows ("16 partial products ×3.5 + w·p′ + asserts") | **157 (mul) / 145 (square)** — MULQ emits 170 = 12 ld/advice + 1 LUI + 157 engine (`sequence_builder.rs:162-383`; fixture row_count 186 = 170 + 16 resets, `jolt-inlines/fixtures/fixtures/registered_inline_expand_parity_hashes.jsonl` SECP256K1_MULQ). Census forgot the 16 mulhu half-products and counted 3.5 instead of 4 rows/mac (`mac_low_w_carry` = 4 rows, :427-433) |
| ADDPTQ rows | ≈440 | **697** (653 emitted + 44 resets; table §3) |
| rows per generic add | 862 → ≈490 | 862 → **≈743** (697 + ≈46 caller) |
| saving on block 25905781 | −370 × 39k ≈ −14M (−2.3%) | **−119 × 39k ≈ −4.6M** (−14% of the 33.7M recovery_msm phase, **−0.74% of 628M**); +≈0.5M if the 7 lookup adds/recovery in jeth `crypto.rs:263-268` (≈4k adds) also switch → ≈ −5.1M |

Sound (§4), implementable in ≈20–24 h (§6), but 3× less payoff than advertised. The floor is algebraic: an affine add needs 3 modular products, each ≈157 rows on RV64 (32 mul/mulhu + carry chains, no add-with-carry op); ADDPTQ wins only the software Fq add/sub (183 real rows → 5 in-engine addends 60 + chains 72) and the memory glue (88 → 0).

## 1. Instruction semantics

Encoding: `.insn r INLINE_OPCODE(0x0B), funct3=0x03, funct7=0x05, rd=out, rs1=P, rs2=Q` — funct3 0x03 is the documented free slot (`jolt-inlines/secp256k1/src/lib.rs:6`); no other crate uses funct7 0x05 (`jolt-inlines/*/src/lib.rs`: 0x00 sha2, 0x01 keccak, 0x02 blake2, 0x03 blake3, 0x06 grumpkin, 0x07 p256). Uniqueness is machine-checked by `linked_inline_registration_keys_are_unique` (`jolt-inlines/fixtures/src/lib.rs:252`).

| operand | register | memory | contract |
|---|---|---|---|
| P = (x1, y1) | rs1 | 8 × u64 at rs1+0..56 (x1 limbs 0..3, y1 limbs 4..7) | canonical (< p), on curve, ≠ ∞ |
| Q = (x2, y2) | rs2 | 8 × u64 at rs2+0..56 | canonical, on curve, ≠ ∞, **x2 ≠ x1** |
| R = P + Q | rs3 (= rd) | 8 × u64 written at rs3+0..56 | canonical x3, y3; **may alias rs1 or rs2** (all 16 loads precede all 8 stores, same rule as DIVQ `sequence_builder.rs:384-393`) |

Preconditions and who guarantees them: the SDK wrapper (`jolt-inlines/sdk/src/ec.rs:183-201 AffinePoint::add`) keeps its existing branches — `is_infinity` ×2, `x1 == x2 && y1 == y2 → double()`, `x1 == x2 → infinity()` — and calls ADDPTQ **only in the generic else-branch**. Recommended over in-inline asserts because (i) doubling/infinity cannot be expressed by the chord formula, so an assert could only abort, never compute; (ii) the branches already exist (19 real rows, census §2) and are the same trust model as DIVQ's `div_assume_nonzero` (`secp256k1/src/sdk.rs:264-289`, `host.rs:123-130` WARNING). Canonical inputs are the `ECField::from_u64_arr_unchecked` invariant (`ec.rs:20-28`). If violated by a guest bug: x1 = x2 makes identity (a) vacuous → **unsound**, therefore the wrapper branch is mandatory, not optional. Operand order is free (x1 > x2 not required; §2 chains handle both).

Advice consumed (24 words, in this VirtualAdvice order, `tracer/src/instruction/inline.rs:339-351` pops the queue in emission order): λ[0..3], x3[0..3], y3[0..3], w_a[0..3], w_b[0..3], w_c[0..3].

### Identities checked (all over the integers, engine form A·B + ΣD_j + w·p′ = 2^256·w + C ⇔ A·B + ΣD_j = w·p + C)

| id | A | B | addends D | C | meaning |
|---|---|---|---|---|---|
| (a) | λ | dx = (x1 − x2) mod p | y2 | y1 | λ·(x1−x2) ≡ y1 − y2 |
| (b) | λ | λ (square engine) | nx1 = p − x1, nx2 = p − x2 | x3 | λ² ≡ x1 + x2 + x3 |
| (c) | λ | dx3 = (x1 − x3) mod p | ny1 = p − y1 | y3 | λ·(x1−x3) ≡ y1 + y3 |

Subtraction handling: never subtract inside the accumulator. Differences are pre-computed as canonical residues with a wrapping 4-limb subtract + borrow-driven correction (§2 `sub_mod_p`, 26 rows), negations as p − x (§2 `neg_p`, 10 rows), sums as extra addends (3 rows/limb, `MulAccExt::adc_w_carry`, `jolt-inlines/sdk/src/host.rs:556-562`). y1, y2 enter (a)/(c) without any pre-computation.

Range checks: x3 < p and y3 < p **mandatory** (6 rows each, §2 `range_lt_p`): (b)/(c) fix them only mod p; a non-canonical output breaks `limbs_eq`/`is_infinity` and the MULQ operand contract (`ec.rs:20-28`). λ: **no range check** — any representative of λ mod p satisfies (a),(b),(c) (congruences), λ < 2^256 is automatic for 4 advice words, and the bounds below hold for any λ < 2^256. Inputs: not re-checked (contract, as MULQ).

Bounds (honest prover; w_i is the exact quotient): A, B, C, D_j < 2^256; dx, dx3 ∈ [0, p) (dx ≠ 0 given x1 ≠ x2); nx_i, ny1 ∈ (0, p].
- (a) λ·dx + y2 − y1 ≡ 0 and > −p ⇒ ≥ 0 ⇒ w_a = (λ·dx + y2 − y1)/p < (p² + p)/p = p + 1 < 2^256 → fits 4 limbs (`nbiguint_to_field_limbs` asserts ≤ 4, `sdk/src/host.rs:72-78`).
- (b) w_b = (λ² + 2p − x1 − x2 − x3)/p < (p² + 2p)/p = p + 2.  (c) w_c = (λ·dx3 + p − y1 − y3)/p < p + 1.
- LHS = 2^256·w + C < 2^256·(p + 2) + p < 2^512: no wrap in the honest trace; the engine's limb-7 `assert_lte aux, r1` (`sequence_builder.rs:379-383`) rejects any wrapped trace, so the checked equality is exact over ℤ. Per-limb carry accumulators hold ≤ 12 carries (≪ 2^64).
- Malicious λ ∈ [p, 2^256): LHS ≤ (2^256)² + 3·2^256 + 2^289; exactness still forced by the no-wrap assert, and any accepted tuple satisfies the three congruences (§4).

## 2. Sequence (pseudo-ops, MULQ per-op costs)

Row costs: ld/sd/advice/lui/mul/mulhu/add/sub/sltu/and/or/xor/assert_* = 1 row each (`count_mulq.py`; no source-only kinds, `crates/jolt-program/src/expand/grammar.rs:391-420`). Reset rows: one `ADDI r, x0, 0` per **distinct** inline register allocated (`crates/jolt-program/src/expand/materialize.rs:157-171`, `allocator.rs:177-185`) — so registers are reused across phases. Pool: 80 inline registers (`allocator.rs:5-13`: 96 − 8 reserved − 8 instruction = 80; census's "pool may be 16" is wrong). Row cap 65535 (`materialize.rs:20`).

Registers (44 distinct → 44 reset rows): x1[4] y1[4] x2[4] y2[4] λ[4] x3[4] y3[4] w[4] d[4] | consts P′ P0 MAX ONE | aux aux2 | r[2].
P0 = p limb 0 = 0xFFFFFFFEFFFFFC2F; p limbs 1..3 = MAX (`secp256k1/src/sdk.rs:15-21`).

Helpers (all straight-line):
```
sub_mod_p(d ← a − b)                                   26 rows   // result = (a − b) mod p, a,b < p
  k0: sub d0,a0,b0 ; sltu br,a0,b0                                          2
  k1,k2: sub t,ak,bk ; sltu t2,ak,bk ; sltu aux,t,br ; sub dk,t,br ; or br,t2,aux   2×5
  k3: same 5 (keeps borrow-out br = [a < b])                                5
  correction (d + br·p ≡ d − br·p′ mod 2^256):  sub m,x0,br ; and t,m,P′    2
    sltu br,d0,t ; sub d0,d0,t                                              2
    k1,k2: sltu t2,dk,br ; sub dk,dk,br ; (br←t2)                           2×2
    k3: sub d3,d3,br                                                        1
neg_p(n ← p − x)  (x < p ⇒ n ∈ (0,p])                  10 rows
  k0: sub n0,P0,x0 ; sltu br,P0,x0                                          2
  k1,k2: sub t,MAX,xk ; sltu t2,t,br ; sub nk,t,br ; (br←t2)                2×3
  k3: sub t,MAX,x3 ; sub n3,t,br                                            2
range_lt_p(x)                                           6 rows   // x < p ⇔ ¬(x1=x2=x3=MAX ∧ x0 ≥ P0)
  and t,x1,x2 ; and t,t,x3 ; sltu m,t,MAX ; sltu u,x0,P0 ; or v,m,u ; assert_eq v,ONE
engine(A,B|square, addends D[..] at limbs 0..3, C regs, w regs)   157 (mul) / 145 (square) + 12 per addend
  = MulqBuilder::inline_sequence loop (sequence_builder.rs:200-383) with: `sd rs3,rk` → `assert_eq rk,Ck` (k<4);
    after the first mac of limb k<4 insert adc_w_carry(rk_next, rk, Dk, aux) per addend (3 rows; never first,
    so the carry form is always right); k≥4 unchanged (assert_eq rk,w[k−4]; final mulhu/add/assert_eq/assert_lte).
```

| # | step | rows |
|---|---|---|
| 1 | `ld` x1,y1 ← rs1+0..56 ; x2,y2 ← rs2+0..56 | 16 |
| 2 | `advice` λ0..3, x3_0..3, y3_0..3 | 12 |
| 3 | `lui` P′, P0, MAX, ONE | 4 |
| 4 | range_lt_p(x3) ; range_lt_p(y3) | 12 |
| 5 | sub_mod_p(d ← x1 − x2) | 26 |
| 6 | `advice` w0..3 (= w_a) | 4 |
| 7 | engine mul A=λ B=d, D={y2}, C=y1 | 157+12 = 169 |
| 8 | neg_p(d ← p − x1) ; neg_p(y2 ← p − x2) (y2 dead after 7) | 20 |
| 9 | `advice` w0..3 (= w_b) | 4 |
| 10 | engine square A=λ, D={d, y2}, C=x3 | 145+24 = 169 |
| 11 | sub_mod_p(d ← x1 − x3) | 26 |
| 12 | neg_p(y1 ← p − y1) in place (sltu before sub per limb) | 10 |
| 13 | `advice` w0..3 (= w_c) | 4 |
| 14 | engine mul A=λ B=d, D={y1}, C=y3 | 169 |
| 15 | `sd` x3 → rs3+0..24 ; y3 → rs3+32..56 | 8 |
| | emitted | **653** |
| | resets (44 registers) | 44 |
| | **ADDPTQ total** | **697** |

Cross-check of the engine model: MULQ 12 + 1 + 157 = 170 emitted ✓ (fixture 186 − 16 resets); SQUAREQ 8 + 1 + 145 = 154 ✓ (167 − 13).
Optional −8: replace range_lt_p(y3) by asserting the borrow-out of neg_p(y3) = 0 (y3 ≤ p; y3 = p is then rejected by (c) since secp256k1 has no 2-torsion) — needs (c) to use D = p − y3, C = y1 instead. Not recommended (subtle for 8 rows).

Per-add accounting (census §2 real-row table): removed ≈270 real rows (6 Fq add/sub 183, glue 88 incl. 8 write-back, 3 canonical checks, 2 anchors); remaining caller ≈46 (bookkeeping 24, infinity/x-eq 19, anchor 1, pointer setup ≈2). 743 vs 862 → **−119 rows/add**; 39.1k adds → **−4.65M rows**; 33.7M phase → 29.0M (−14%); block 628M → −0.74%. Uncertainty ±10 rows/add (compiler glue) → −4.3…−5.0M.

## 3. Row model vs. today

| | virtual (inline) rows | real (caller) rows | total |
|---|---|---|---|
| today: DIVQ 194 + SQUAREQ 167 + MULQ 186 (fixture row_counts, incl. resets) | 547 (+≈1.5 shifts) | ≈316 | 862 |
| ADDPTQ | 697 | ≈46 | ≈743 |
| Δ | +150 | −270 | **−119** |

Where the 3 engines go: 3 × ~157 partial-product/reduction rows = 471 (68%); chains 72; addends 60; range 12; ld/sd/advice/const 64; resets 44 — nothing below the engines is worth optimizing further; the engine cost is set by RV64 (32 mul/mulhu + 3-row carry adds per 64-bit half, `MulAccExt` `sdk/src/host.rs:423-571`).

## 4. Soundness

Setting: guest code (wrapper) is honest and fixed; the prover controls only the 24 advice words. Inputs satisfy the contract (§1). Each engine enforces an exact integer identity: limbs 0..3 of the accumulator equal C, limbs 4..7 equal w (VirtualAssertEQ rows), and limb 7 has no wrap (`assert_lte`), so A·B + ΣD + w·p′ = 2^256·w + C over ℤ ⇔ A·B + ΣD = w·p + C ⇒ A·B + ΣD ≡ C (mod p). Carries are exact (≤ 12 per limb).

Uniqueness / any accepted advice is the true sum:
1. (a): λ·dx ≡ y1 − y2 with dx = (x1 − x2) mod p ≠ 0 (contract x1 ≠ x2, p prime) ⇒ λ ≡ (y1 − y2)·dx⁻¹ — the chord slope, unique mod p. λ's representative is irrelevant for (b),(c) (congruences only).
2. (b): x3 ≡ λ² − x1 − x2 and 0 ≤ x3 < p (range_lt_p) ⇒ x3 is the unique canonical x of P+Q.
3. dx3 is a deterministic function of (x1, x3) computed in-sequence (`sub_mod_p`, no advice); (c): y3 ≡ λ·(x1 − x3) − y1 and y3 < p ⇒ unique canonical y of P+Q.
Malicious advice: any deviation in λ, x3, y3 or a w_i makes some `assert_eq`/`assert_lte` row fail → trace aborts (`tracer/src/instruction/virtual_assert_eq.rs`-family `assert!`), no proof exists; the VirtualAssert rows are part of the proven bytecode, so the verifier rejects any trace that skips them.
Completeness: honest advice (§5) satisfies the identities with quotients in [0, p+2) ⊂ [0, 2^256) and LHS < 2^512 (§1 bounds), so all asserts pass; sub_mod_p/neg_p produce exactly the residues used by the host advice (dx = x1 − x2 or x1 − x2 + p; identical for x1 > x2 and x1 < x2).
Edge cases: P + (−2P) (x3 = x1, dx3 = 0) → (c) reduces to p − y1 ≡ y3 ✓; x1 < x2 handled by the correction branch of sub_mod_p; aliasing rs3 = rs1/rs2 safe (loads first). y3 = 0 never occurs on secp256k1 (no point of order 2); x3 = 0 is a legal canonical value and passes range_lt_p.

## 5. Native (host) implementation and parity

- Guest (riscv64, `not(feature="host")`): `.insn r` wrapper (pattern `secp256k1/src/sdk.rs:186-205`), result read back from memory; no canonical check needed (in-inline range checks) → `from_u64_arr_unchecked`.
- Host (`feature="host"`, jeth native gate: jeth `crates/core/Cargo.toml:70` enables `host`): unchanged arkworks path — `AffinePoint::add` generic branch computes with `Secp256k1Fq::div/square/mul` (`sdk.rs:213-221, 255-261, 320-328`). Hook returns `false` → software path; identical canonical output ⇒ run-native parity by construction.
- Trace-side advice (host emulator), new fn in `sequence_builder.rs` next to `division_advice` (:132-161), using `InlineAdviceContext` (`tracer/src/instruction/inline.rs:61-67`) + `load_field_element_limbs` (`sdk/src/host.rs:58-70`):
```
x1,y1 ← load(rs1+0), load(rs1+32); x2,y2 ← load(rs2+0), load(rs2+32)        // InlineAdviceError on bad pointers
Fq: dx = x1−x2 ; assert dx ≠ 0 ("ADDPTQ: x1 == x2, wrapper contract violated" — panic like host.rs:146-153 zero inverse)
λ = (y1−y2)·dx⁻¹ ; x3 = λ² − x1 − x2 ; dx3 = x1 − x3 ; y3 = λ·dx3 − y1     (all canonical via into_bigint)
ℤ (NBigUint): w_a = (λ·dx + y2 − y1) / p ; w_b = (λ² + (p−x1) + (p−x2) − x3) / p ; w_c = (λ·dx3 + (p−y1) − y3) / p
debug_assert each division exact; AffineAddAdvice{λ,x3,y3,w:[w_a,w_b,w_c]}.into_runtime_advice() = [λ,x3,y3,w_a,w_b,w_c] (24 words)
```
`InlineAdvice` impl pattern: `ModularDivisionAdvice` (`sdk/src/host.rs:155-159, 217-226`).

## 6. Wiring

| file | change |
|---|---|
| `jolt-inlines/secp256k1/src/lib.rs:6,21-32` | doc line 0x03 → ADDPTQ; `SECP256K1_ADDPTQ_FUNCT3 = 0x03`, `SECP256K1_ADDPTQ_NAME = "SECP256K1_ADDPTQ"` |
| `jolt-inlines/secp256k1/src/sequence_builder.rs` | `AddptqBuilder { asm, regs… }` with `sub_mod_p`, `neg_p`, `range_lt_p`, `engine(...)`; factor the k-loop of `MulqBuilder::inline_sequence` (:200-383) into a shared engine taking `addends: [&[u8]; 4]` and `c: [u8;4]` so MULQ/SQUAREQ/DIVQ keep byte-identical output (fixture hashes must not change for them); `pub struct Secp256k1AddPtQ; impl InlineOp` (Advice = AffineAddAdvice; pattern :557-577) |
| `jolt-inlines/sdk/src/host.rs:150-232` | `pub struct AffineAddAdvice { lambda, x3, y3: FieldElementLimbs, quotients: [FieldElementLimbs; 3] }` + `InlineAdvice` impl |
| `jolt-inlines/secp256k1/src/host.rs:9-17` | add `Secp256k1AddPtQ` to `register_inlines!` ops (order irrelevant to lookup; fixture sorts by key, `fixtures/src/lib.rs:95-108`) |
| `jolt-inlines/sdk/src/ec.rs:32-45` | `CurveParams::fused_add(out: *mut u64, p: *const u64, q: *const u64) -> bool { false }` default; `#[repr(C)]` on `AffinePoint` (:49) so `&self as *const _ as *const u64` addresses x then y |
| `jolt-inlines/sdk/src/ec.rs:182-201` | new `pub fn add_assign(&mut self, other: &Self)`: same branch ladder; generic arm: `if C::fused_add(self as *mut _ as *mut u64, self.., other..) { return }` else software; `add` = clone + add_assign |
| `jolt-inlines/secp256k1/src/sdk.rs:92,667-678` | `#[repr(C)]` on `Secp256k1Fq`; `impl CurveParams for Secp256k1Curve`: `fused_add` = `.insn r` with rd=out, rs1=p, rs2=q under `cfg(all(not(feature="host"), any(target_arch="riscv32", target_arch="riscv64")))`, returns true; host/non-riscv: false |
| `jolt-inlines/fixtures/fixtures/registered_inline_expand_parity_hashes.jsonl` | regen: `JOLT_UPDATE_INLINE_EXPANSION_FIXTURES=1 cargo nextest run -p jolt-inlines-fixtures --cargo-quiet` (`fixtures/src/lib.rs:223-236`), then re-run without the env var; check the 4 new SECP256K1_ADDPTQ rows (normal/compressed/rd_zero/aliased_operands) all report row_count 697 and that the 28 existing secp rows are byte-identical |
| jeth `crates/core/src/recovery_batch.rs:224,238,244,245` | `buckets[idx] = buckets[idx].add(pt)` → `buckets[idx].add_assign(pt)`; `sum.add_assign(bucket); result.add_assign(&sum)` (rs3 = bucket slot, no write-back copy) |
| jeth `crates/core/src/crypto.rs:263-268` | lookup-table adds (7/recovery) → same API (optional, ≈+0.5M) |

Tests (`jolt-inlines/secp256k1/src/tests.rs`, pattern :13-38 and :207-227):
1. `assert_addptq_trace_equiv(P, Q)`: `InlineMemoryLayout::two_inputs(64, 64, 64)` (`tracer/src/utils/inline_test_harness.rs:52-69`), `load_input64(P 8 limbs)`, `load_input2_64(Q)`, `execute_inline(create_default_instruction(0x0B, 0x03, 0x05))`, `read_output64(8)` == `(ark Affine P + Q)` limbs. Random: 10k pairs from `ark_secp256k1::Projective` scalar muls of G (seeded StdRng), skipping x1 == x2. Edge: x1 < x2 and x1 > x2 explicit, P + (−2P) (x3 = x1), P + (−P) is **not applicable** (wrapper returns infinity before the inline), doubling excluded, G + φ(G) (endomorphism point, `sdk.rs:754-766`).
2. Aliased output: layout with `output_base: DRAM_BASE` (rs3 = rs1) and `DRAM_BASE + 64` (rs3 = rs2), as `assert_div_trace_equiv_aliased`.
3. Tampered advice `#[should_panic]`: `INLINE::inline_sequence(&cpu.vr_allocator)`, flip one bit of the k-th `Instruction::VirtualAdvice(va).advice` for k ∈ {λ0, x3_0, y3_0, w_a0, w_b0, w_c0} (patch loop as `inline.rs:339-351`), `harness.execute_sequence(&rows)` → VirtualAssert panic. Also `x3 = true_x3 + p` (when < 2^256) must panic (range check).
4. Wrapper: `Secp256k1Point::add_assign` on host equals `add` for random pairs (exercises the branch ladder; inline itself is not reached on host).
5. Row-count golden: fixture jsonl (above) + `linked_inline_registration_inventory_matches_fixture` (`fixtures/src/lib.rs:239`).
6. E2E: jeth block 25905781 row profile (`data/25905781/profile-waveI-rows.log` method) — expect recovery_msm ≈ 33.7M → ≈29M.
Gates: `cargo clippy --all --features host -q --all-targets -- -D warnings` (+`,zk`), `cargo fmt`, `cargo nextest run -p jolt-inlines-secp256k1 --features host`, `-p jolt-inlines-fixtures`; reinstall `cargo install --path . --locked` before rebuilding the jeth guest (CLAUDE.md "After pulling changes").

## 7. Effort and risks

| step | hours |
|---|---|
| engine refactor (shared k-loop with addend/C hooks, byte-identical for MULQ/SQUAREQ/DIVQ) + AddptqBuilder + helpers | 7 |
| advice fn + `AffineAddAdvice` | 2 |
| registration, consts, fixture regen, row-count reconciliation vs this table | 1.5 |
| tests 1–5 | 4 |
| SDK: repr(C), `fused_add` hook, `add_assign`, secp `.insn` impl | 3 |
| jeth call sites, guest rebuild, block-781 row profile, compare | 3 |
| clippy/fmt/docs/PR | 1.5 |
| **total** | **≈22 h (2.5–3 days)** |

Risks: (1) payoff is −4.6…−5.1M rows (−0.7…−0.8% of block), not −14M — re-rank before spending 3 days. (2) Engine refactor must not perturb MULQ/SQUAREQ/DIVQ row order (fixture hashes) — or implement the ADDPTQ loop as a copy and accept duplication. (3) Advice order: VirtualAdvice rows are consumed strictly in emission order and counted exactly (`inline.rs:341-360` panics on too few/many) — emit w advice immediately before each engine. (4) `#[repr(C)]` is required on `AffinePoint` and `Secp256k1Fq` before passing point pointers; PhantomData is zero-sized (fine). (5) Aliasing: keep all 8 stores after the last assert (DIVQ WARNING `sequence_builder.rs:384-387`). (6) Non-canonical or x1 = x2 inputs are unsound-by-contract exactly like DIVQ's zero divisor; the wrapper branch ladder is the enforcement point — don't add a "generic-only" public API without it. (7) Row model ±10; verify against the regenerated fixture before quoting savings. (8) `double_and_add` (`ec.rs:205-233`, used by jeth `crypto.rs:274` and ecdsa) is not covered — a separate DBLADDQ would be a second 3-day lane with similar per-op economics.
