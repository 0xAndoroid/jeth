# Lane B-blake2f — BLAKE2F (0x09) with arbitrary round counts and 128-bit counters on custom round inlines

Branch `inlines-b-blake2f` (base `inlines-b` @ 6557a40 = amber-nolane + Phase A + jolt repin). Jolt pin `jolt-inlines-b`
(read-only, untouched). Builds in the worktree's `target/` (host binaries `target/release/{jeth,synth}`, guests
`target/guest-*` = final tree, `target/guest-off-*` = same tree with `blake2f-inline` removed from the guest's jeth-core
features). Jolt CLI `/Volumes/Dev/worktrees/jolt/jolt-inlines-b/target/release/jolt`. Scratch + block-input copies +
harness `/Volumes/Dev/jeth-scratch/inlines-b-blake2f/` (`opcg/`: evm.py / runner.py repointed, `cases_blake2f.py`,
`blake2f_ref.py`, `edge_blake2f.py`; `blocks/<b>/input.bin`).

Kill bar stated up front: the round inlines must cut BLAKE2F rows/round by ≥ 10% against the software compress
(253 rows/round asymptote, r1000 = 232 c/g); expected ≈ 88 rows/round (−65%). The ten-block set carries no BLAKE2F
call, so its gate is "rows/hashes/perms unchanged".

## Op family (crate `crates/inlines/blake2f`, package `jeth-inlines-blake2f`, opcode 0x2B)
`Blake2bRounds<R>` for `R ∈ {10, 1, 2, …, 9}`: `R` BLAKE2b rounds with sigma rows `0..R` over the 16-word working
state at rs1 with the 16 message words at rs2. rd = x0. Encoding `funct7 = 0x02 + (R % 10) / 8`,
`funct3 = (R % 10) % 8`:

| R | funct7 | funct3 | name | rows |
|---|---|---|---|---:|
| 10 | 0x02 | 0 | BLAKE2B_ROUNDS_10 | 880 |
| 1..=7 | 0x02 | R | BLAKE2B_ROUNDS_R | 80·R + 80 |
| 8 | 0x03 | 0 | BLAKE2B_ROUNDS_8 | 720 |
| 9 | 0x03 | 1 | BLAKE2B_ROUNDS_9 | 800 |

Rows = 16 LD (v) + 16 LD (m) + 80 per round (8 G × (add, add, xorrot32, add, xorrot24, add, add, xorrot16, add,
xorrot63)) + 16 SD (v) + 32 inline-register resets. The G emission is the stock `jolt-inlines/blake2`
sequence_builder's (same fused `VirtualXORROT{32,24,16,63}` rows); the stock 12-round inline is 1067 rows for the
whole compression (960 round rows + 107 init/fold/load/store/reset rows).

Memory contract: rs1 → `v[0..16]` (128 bytes, 8-aligned) read then written; rs2 → `m[0..16]` (128 bytes, 8-aligned)
read only. All 32 loads precede the 16 stores, so rs1 == rs2 is well defined (R rounds of `v` with `m = v`; tested).
No advice, no asserts, no branches: the row sequence is straight-line and total on every 64-bit input.

## Guest routing (`crates/core/src/crypto.rs`, `Crypto::blake2_compress`, feature `blake2f-inline` ⊃ `blake2-inline`)
- `rounds == 12 && t[1] == 0` → the stock 12-round inline (1067 rows; unchanged from Phase A).
- everything else → `jeth_inlines_blake2f::compress(rounds, h, m, t, f)`: `v = h ‖ IV`, `v12 ^= t0`, `v13 ^= t1`,
  `v14 = !v14` iff `f` (software, 16 words), `rounds / 10` × `Blake2bRounds<10>`, then `Blake2bRounds<rounds % 10>`
  if `rounds % 10 > 0`, then `h[i] ^= v[i] ^ v[i+8]` (software). `rounds == 0` = init + fold only.
- 12-round calls with `t[1] != 0` take FULL10 + PREFIX_2 = 1120 inline rows + software init/fold — measured below
  (`BLAKE2F/r12-t1`) against the stock inline's `r12` to settle which path 12-round calls should take.
- Native (`run-native`) keeps revm's software compress (the override is `target_arch = "riscv64"`-only).

## Soundness
Claim: for every `rounds ≥ 0`, every `t ∈ (u64)²`, every `h, m`, both flags, the guest computes
`revm::precompile::blake2::algo::compress(rounds, h, m, t, f)`.
1. Each op is deterministic straight-line code over ADD (wrapping), `VirtualXORROTn` (= `rotr64(x ^ y, n)`), LD, SD;
   every row's semantics is total on all 64-bit register values, so the sequence computes exactly
   `rounds_reference(v, m, R)` (RFC 7693 §3.2 round loop with `SIGMA[i % 10]`, `i = 0..R`) on ALL inputs — the input
   domain is all of `(u64^16)²`, there is no invalid input, no advice, no dishonest-prover degree of freedom.
   Checked through the tracer harness (`spec.rs`): 10 000 random `(v, m)` per op + 7 edge cases (all-zero, all-ones,
   mixed, IV-derived states with t = 3 / t = 2^64−1 and both flags, sign-bit patterns) + the aliased rs1 == rs2 case,
   and the golden row count for three operand-register choices.
2. Composition: `rounds = 10q + r`. revm's round `i` uses `SIGMA[i % 10]`; after `q` FULL10 ops (rows 0..9 each) the
   next revm round index is `10q ≡ 0 (mod 10)`, and PREFIX_r applies rows `0..r` = `SIGMA[(10q + j) % 10]` for
   `j = 0..r`. Init and fold are revm's own statements (`v[12] ^= t[0]; v[13] ^= t[1]; if f { v[14] = !v[14] }`,
   `h[i] ^= v[i] ^ v[i+8]`) with the same IV. Checked natively (`crypto.rs` tests, where the ops are the reference
   function the harness pins the rows to): rounds `0..=13, 19, 20, 21, 100, 1000` × 24 (h, m, t, f) cases with
   `t0, t1 ∈ {0, 1, 2^64−1, random}` against revm's `compress`; IV and SIGMA equal revm's tables; EIP-152 vectors 4–8
   (rounds 0, 12, 12, 1, 2^24).
3. The stock 12-round path keeps its Phase A argument (rows 10, 11 of the inline's SIGMA = rows 0, 1; `t1 = 0` only).
4. In-guest: the forged block below SSTOREs every precompile output and reverts on mismatch with an independent Python
   reference; trace `block_hash == run-native block_hash`.

## Numbers
Host + guests built from the committed tree (cb2028d); "before" = the same tree with `blake2f-inline` removed from
`crates/guest/Cargo.toml` (guests `target/guest-off-*`), host binary identical.

### Synth harness (per-tx method: Δ(K − K/2 units), unit = 5×DUP + GAS + STATICCALL(warm 0x09) + POP; study input shape
h = IV[0]×8, m = 0, t = 0, f = 1; `r12-t1` sets t1 = 1; K = 1000 (r0..r20), 400 (r100), 200 (r1000))
| config | gas/unit | rows/unit before | rows/unit after | Δ rows | c/g before → after |
|---|---:|---:|---:|---:|---|
| BLAKE2F/r0 | 119 | 6,826.5 | 6,855.5 | +29.0 | 57.37 → 57.61 |
| BLAKE2F/r1 | 120 | 7,042.3 | 6,970.3 | −72.0 | 58.69 → 58.09 |
| BLAKE2F/r10 | 129 | 9,318.1 | 7,691.1 | −1,627.0 | 72.23 → 59.62 |
| BLAKE2F/r12 (t1 = 0, fixed inline both) | 131 | 7,779.1 | 7,779.1 | 0 | 59.38 → 59.38 |
| BLAKE2F/r12-t1 (t1 = 1) | 131 | 9,822.0 | 7,931.0 | −1,891.0 | 74.98 → 60.54 |
| BLAKE2F/r13 | 132 | 10,071.3 | 8,007.3 | −2,064.0 | 76.30 → 60.66 |
| BLAKE2F/r20 | 139 | 11,836.5 | 8,561.5 | −3,275.0 | 85.15 → 61.59 |
| BLAKE2F/r100 | 219 | 32,084.1 | 15,625.1 | −16,459.0 | 146.50 → 71.35 |
| BLAKE2F/r1000 | 1,119 | 259,755.8 | 94,976.8 | −164,779.0 | 232.13 → 84.88 |
Per round (r1000 − r100)/900: software 252.97 rows, inlines 88.17 rows (−65.1%; FULL10 = 880 rows + ≈ 1.7 rows of loop).
Kill bar (≥ 10%) cleared by 6.5×. Adversarial 60M-gas block of r1000 units: 13.93 G → 5.09 G rows; single 2^24-round calls
(EIP-7825 tx gas cap) asymptote 88.2 rows/gas → 5.29 G rows. Worst real block ≈ 1.43 G → the BLAKE2F bound drops from
9.7× to 3.6–3.7× of it.
12-round decision: fixed inline 7,779.1 vs round inlines 7,931.0 rows/unit (+151.9: 1120 inline rows + software init/fold
against 1067) → `rounds == 12 && t[1] == 0` keeps the fixed inline; 12-round calls with `t1 != 0` (before: software,
9,822.0) take the round inlines. `r0` costs 29 rows more than revm's zero-round compress (the `rounds / 10` loop and
`rounds % 10` dispatch around an identical init/fold) — left as is.

### Ten-block set (final tree, `blake2f-inline` on; inputs copied from /Volumes/Dev/jeth-inputs)
| block | rows | inlines-b baseline | Δ | block_hash == record | keccak perms |
|---|---:|---:|---:|---|---:|
| 25905781 | 601,992,101 | 601,992,101 | 0 | yes | 115,373 (= baseline) |
| 25905782 | 715,141,963 | 715,141,963 | 0 | yes | 124,117 |
| 25905783 | 333,107,908 | 333,107,908 | 0 | yes | 61,886 |
| 25905784 | 250,985,973 | 250,985,973 | 0 | yes | 51,424 |
| 25905785 | 628,588,538 | 628,588,538 | 0 | yes | 121,623 |
| 25905786 | 291,810,444 | 291,810,444 | 0 | yes | 59,024 |
| 25905787 | 395,621,866 | 395,621,866 | 0 | yes | 70,085 |
| 25905788 | 92,464,391 | 92,464,391 | 0 | yes | 19,238 |
| 25905789 | 676,244,012 | 676,244,012 | 0 | yes | 133,642 |
| 25905790 | 432,649,242 | 432,649,242 | 0 | yes | 90,051 |
Gas-weighted c/g unchanged at 13.763942 (no block in the set calls BLAKE2F). Perms equal the Phase A ledger on all ten.

### Block 25905781 attribution (`jeth profile --rows --top 40`, feature off vs on)
Both 601,992,101 trace rows / 247,410,852 real instructions; all 40 top symbols identical row-for-row (only the
`jeth_core[...]` crate-hash suffix differs). `jeth opcodes`: INLINE(custom-0) 229,567 executions / 311,923,142 rows both
ways; no opcode-0x2B (custom-1) execution — the block has no BLAKE2F call. The lane's delta on the ten-block set is 0.

### Forged / edge block (`edge_blake2f.py`: one tx per vector; the contract STATICCALLs 0x09 with bounded forwarded gas,
SSTOREs ok | returndatasize<<8 and both output words, and reverts if any differs from the Python F reference in calldata)
30 vectors, 30/30 txs successful (software == Python reference incl. the three failure cases), native `block_hash`
0x388340da6258963247dd3bdafd0dda708f80b33052d7f97c29533b158b19efc3 == trace `block_hash`, 99,921,875 rows:
EIP-152 vectors 3 (final flag 2 → failure), 4 (r0), 5 (r12 f1), 6 (r12 f0), 7 (r1), 8 (rounds 2^32−1 → out of gas →
failure, consumes the forwarded gas); `big/r2^20` (1,048,576 rounds = 104,857 FULL10 + PREFIX_6, random h/m/t);
random h/m/t for rounds 0, 1, 9, 10, 11, 12, 13, 100, 1000; r12 with t1 = 0 (f = 0 and 1) and t1 = 1; counter
t0 = t1 = 2^64−1 at r12/r13/r1000; all-0xff h/m at r12 (t1 = 0 and t1 = 1), r7, r10, r23; all-zero r19; lengths 212/214
(fail before the hook). The Python reference is checked against EIP-152 vectors 3–7 before use.

### Tests / gates
- `cargo nextest run --cargo-quiet --release --workspace --features jeth-host/secp-inline`: 44 passed (7 new: 4 in the
  inline crate — every op vs reference on 10k random + 7 edges + aliased operands + golden rows, 10+2 rounds = 12
  reference rounds on the EIP-152 state, encoding injective/in range, SIGMA permutations + IV; 3 in jeth-core — round
  inlines vs revm compress (18 round counts × 24 cases), tables == revm, EIP-152 vectors 4–7).
- Pre-commit on cb2028d: fmt + clippy (`--all --all-targets -D warnings`) green; typos clean on every changed file
  (`DISABLE_TYPOS=1` only for the pre-existing RESULTS.md / zeth_trie.rs hits). The hook's clippy ran with
  `CARGO_TARGET_DIR` set to this worktree's `target/` for that one command (the committed `.cargo/config.toml` still
  points at the wiped shared dir).

## Files
- new `crates/inlines/blake2f/{Cargo.toml, src/lib.rs, sdk.rs, host.rs, sequence_builder.rs, spec.rs}`
- `Cargo.toml` (member + workspace dep), `Cargo.lock`, `crates/guest/Cargo.lock`
- `crates/core/Cargo.toml` (feature `blake2f-inline`, optional dep, dev-dep), `crates/core/src/crypto.rs` (routing +
  3 tests), `crates/host/Cargo.toml` + `crates/host/src/trace.rs` (host registration), `crates/guest/Cargo.toml`
  (feature on)
- unsafe added: one `asm!` block (`sdk.rs::round_op`, the `.insn` with two pointers to 8-aligned `[u64; 16]`).
No jolt-repo edits, no new lookup tables or instruction kinds, MAX_SUFFIXES untouched, no advice.

## Open questions
- A 20-round op (FULL20, one more registration slot) would amortize the 80 load/store/reset rows over 20 rounds:
  r1000 94,977 → ≈ 90,977 rows/unit (84.9 → 81.3 c/g), −4.2% on the bound. Not built (complexity budget; the encoding
  would need a slot outside the `R % 10` rule).
- The residual ≈ 6,850 rows/call outside the rounds (revm's byte-wise input parse + STATICCALL glue + init/fold) now
  dominates calls below ~30 rounds; only a vendored revm-precompile would move it (Phase A note).
