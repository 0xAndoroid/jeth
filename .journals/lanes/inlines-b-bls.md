# Lane B-bls — BLS12-381 Fq multiplication inlines (MULP / SOPP2 / FP2MUL)

Branch `inlines-b-bls` (base `inlines-b` @ 6557a40). Jolt pin: `/Volumes/Dev/worktrees/jolt/jolt-inlines-b`
(read-only; `InlineExtension::External`). Verdict: **BUILT** — G2MSM −13.9%, pairing −13.0%, POINTEVAL −12.5% rows per call (bar: ≥ 12%);
ten regular blocks unchanged (no BLS calls), hashes = records; Aztec block 25694235 −1.34%.

## Pre-gate (compiled ark-ff 0.5, synth G2MSM k=1 block, 9,925,627 rows per precompile call)

| symbol (ark-ff, N=6) | rows/call | calls per G2MSM op | share of op |
|---|---:|---:|---:|
| `sum_of_products` (M=2) | 1,182.7 | 4,116 | 49% |
| `mul_assign` | 713.7 | 3,372 | 24% |
| Fp2 `mul_assign` glue (copy, negate, 2 sops) | 200.9 | 2,058 | 4% |
| Fp2 `square_in_place` glue | 134.0 | 1,684 | 2% |
| Fp `square_in_place` | 581 | rare | — |

Inline model (incl. one ADDI reset row per touched inline register): MULP 647 (−9.4% vs 713.7),
SOPP2 957 (−19%), fused FP2MUL 1,875 vs 2×1,182.7 + 200.9 = 2,567 (−27%). Projected G2MSM saving
−11.6% (MULP+SOPP2) → ≈ −16.6% with FP2MUL ⇒ GO for all three. Fp squaring stays compiled
(581 < 647). Optional later: fused FP2SQR (≈1,380 vs ≈1,772 compiled, ≈ −6.6% more).

## Operations (opcode 0x2B, funct7 0x01; rs1 → a, rs2 → b, rd → out; addresses, 8-byte aligned)

| funct3 | name | in (u64 words) | out | rows | inline regs |
|---|---|---|---|---:|---:|
| 0x0 | `BLS12_381_MULP` | a[6], b[6] | out[6] = a·b·R⁻¹ mod p | 647 | 27 |
| 0x1 | `BLS12_381_SOPP2` | a[12] = [a₀,a₁], b[12] = [b₀,b₁] | out[6] = (a₀b₀ + a₁b₁)·R⁻¹ mod p | 957 | 39 |
| 0x2 | `BLS12_381_FP2MUL` | a[12] = a₀ + a₁u, b[12] | out[12] = a·b in Fq[u]/(u²+1) | 1,875 | 46 |

R = 2³⁸⁴, elements are little-endian Montgomery limbs `< p`; results are canonical (`< p`).
Every LD precedes every SD, so `out` may alias `a` or `b` (and `a` may equal `b`).

### Sequence (crates/inlines/bls12-381/src/sequence_builder.rs)

Product scanning over 12 columns. Column k accumulates lo(aᵢbⱼ) (i+j=k), hi(aᵢbⱼ) (i+j=k−1) and
the same halves of mᵢ·pⱼ into a (value, carry) register pair (`mul/mulhu; add; sltu` = 3 rows for the
first term, 4 afterwards, 2 in the last column). For k < 6: mₖ = valueₖ·INV mod 2⁶⁴ is stored in
place of xₖ; since valueₖ + lo(mₖp₀) ≡ 0 (mod 2⁶⁴), lo(mₖp₀) is never computed — its carry is
exactly (valueₖ ≠ 0), one `sltu x0`. Columns 6..11 are t = (Σaᵢbᵢ + m·p)/R. Then a branch-free
conditional subtraction: d = t − p with borrow chain, mask = d₅ >> 63 (arithmetic), out = d ⊕
((t ⊕ d) ∧ mask), stored with SD. FP2MUL: pass 1 computes c₁ = a₀b₁ + a₁b₀ (stored at out+48),
negates b₁ in place (p − b₁), pass 2 computes c₀ = a₀b₀ + a₁(p − b₁) (stored at out+0).
No advice rows, no branches: the row sequence is identical for every input.

Register plan (of the 80 inline registers): MULP a6 b6 p6 inv x6 t0 aux = 27; SOPP2 + a₁6 b₁6 = 39;
FP2MUL 4×6 inputs + p6 inv x6 t0 t1 aux d6 = 46. All released before `finalize`.

### Soundness

* **Bounds.** With a, b < p: ab + mp < p² + Rp ⇒ t < p(p/R + 1) < 1.125p < 2p, so one conditional
  subtraction yields the canonical residue. SOPP2/FP2MUL: Σ < 2p² ⇒ t < 1.25p. Even a single
  non-canonical operand (one factor < p, the other < 2³⁸⁴) keeps t < 2p (ab < pR); FP2MUL's
  negated b₁ = 0 gives p as an operand, covered by this case. Two non-canonical operands are outside
  the contract (never produced: see reachability).
* **Column carries.** Column 6 is the fullest: MULP 11 product halves + 11 reduction halves = 22
  terms, SOPP2/FP2MUL 22 + 11 = 33; the carry register counts one unit per 64-bit overflow plus the
  incoming carry (≤ 33, maximum observed 18, < 2⁶) — no overflow.
* **Zero-check trick.** lo(mₖp₀) = 2⁶⁴ − valueₖ when valueₖ ≠ 0 (since mₖp₀ ≡ −valueₖ), so the
  addition valueₖ + lo(mₖp₀) is 2⁶⁴ (carry 1) or 0 (carry 0): carry = (valueₖ ≠ 0), added to the
  next column; hi(mₖp₀) is accumulated normally.
* **Conditional subtraction.** t < 2p < 2³⁸² and p < 2³⁸¹ ⇒ t − p ∈ (−2³⁸¹, 2³⁸¹): the top limb's
  sign bit of the 384-bit difference is exactly the borrow, so SRAI 63 of d₅ is the select mask.
* **Reachability of inputs ≥ p.** ark-ff `Fp` values are canonical by construction (`from_bigint`,
  deserialization and every arithmetic op reduce; `new_unchecked` is only used with reduced
  constants), and revm's precompile decoders reject field elements ≥ p before constructing `Fq`.
  The hook is reached only through `Fp::mul_assign` / `sum_of_products` / `QuadExtField::mul_assign`
  on such values.
* **Determinism / advice.** None; `VirtualAdvice` is not used.
* **Aliasing.** `out == a`, `out == b`, `a == b`, all three equal: tested (`tests::aliasing`).
* **Edge inputs tested** (`spec.rs`): 0, 1, R mod p, p−1, p−2, (p−1)/2, 2⁶⁴−1, 2³²⁰, 2³²⁰−1,
  [MAX×5, p₅−1], [0…, p₅], 1-in-every-limb, plus as a single MULP operand p, p+1, 2³⁸⁴−1, 2³⁸³,
  2³⁸⁴−2³²⁰; all pairs → 13 × 18 × 2 MULP cases, 169 SOPP2/FP2MUL cases; 10,000 random cases per
  op vs the big-integer reference; 1,000 random MULP cases vs arkworks `Fq` multiplication;
  constants (MODULUS, INV, R, R²) asserted against `ark_bls12_381::FqConfig`. The crate's dev-dep
  `ark-ff` resolves to the vendored copy through `[patch.crates-io]` (native code byte-identical to
  the registry crate: the hook is `cfg(riscv64)`), so the arkworks cross-checks exercise the same
  software path the native gate runs.

## Hook (vendored ark-ff 0.5.0, feature `jolt-bls12-381-inline`, `target_arch = "riscv64"` only)

* `crates/vendor/ark-ff` = registry crate byte-for-byte (commit `chore(vendor)`), then:
  `Cargo.toml` (+ optional path dep, feature), `src/lib.rs` (+ module), `src/jolt_bls12_381.rs`
  (dispatch glue, 4 `unsafe` blocks), `montgomery_backend.rs` (`JOLT_BLS12_381_FQ` const on
  `MontBackend<T, N>` = N == 6 ∧ MODULUS == p; if-arms in `mul_assign` and `sum_of_products` M == 2),
  `quadratic_extension.rs` (if-arm in `MulAssign` when `is_fq2::<P>()`: base field size 48,
  extension size 96, c0/c1 offsets 0/48, degree-1 base field, characteristic p, NONRESIDUE −1;
  `MontBackend` is the only `FpConfig` in the graph, so that base field is the Montgomery form).
  `JOLT_BLS12_381_FQ` = modulus p ∧ `size_of::<Fp>() == 48` ∧ limbs at offset 0 (compile-time; a
  different layout simply leaves the compiled path).
* `[patch.crates-io] ark-ff` in the root and guest manifests; the a16z arkworks fork used by
  jolt-sdk is a different source and stays. jeth-core feature `bls12-381-inline` (guest on;
  native `run-native` keeps the software path). Host registers the inline via
  `jeth-inlines-bls12-381/host` + `extern crate` in `crates/host/src/trace.rs`.

## Gates (before = same tree, guest feature `bls12-381-inline` off; after = on; both ELF pairs
built from HEAD; `jeth trace` proven run; host `target/release/jeth` registers the inline)

### Synth configs (rows per precompile call, per-tx Δ method)

| config | gas/call | rows/call before | rows/call after | Δ | rows/gas before → after |
|---|---:|---:|---:|---:|---:|
| BLS_G1ADD | 493 | 129,963 | 129,043 | -0.7% | 264 → 262 |
| BLS_G2ADD | 718 | 181,641 | 173,614 | -4.4% | 253 → 242 |
| BLS_G1MSM/k1 | 12,118 | 3,448,785 | 3,280,877 | -4.9% | 285 → 271 |
| BLS_G1MSM/k8 | 70,006 | 13,100,576 | 12,487,596 | -4.7% | 187 → 178 |
| BLS_G2MSM/k1 | 22,618 | 9,925,612 | 8,542,744 | -13.9% | 439 → 378 |
| BLS_G2MSM/k8 | 143,398 | 31,239,492 | 26,890,368 | -13.9% | 218 → 188 |
| BLS_PAIRING/k1 | 70,418 | 20,818,507 | 18,120,306 | -13.0% | 296 → 257 |
| BLS_PAIRING/k2 | 103,018 | 27,441,924 | 23,854,532 | -13.1% | 266 → 232 |
| BLS_MAP_FP_TO_G1 | 5,618 | 1,664,688 | 1,610,511 | -3.3% | 296 → 287 |
| BLS_MAP_FP2_TO_G2 | 23,918 | 5,039,926 | 4,569,074 | -9.3% | 211 → 191 |
| POINTEVAL | 50,118 | 37,923,831 | 33,186,684 | -12.5% | 757 → 662 |

synth blocks:
- bls-00: rows 162,215,227 → 155,195,803 (-4.33%), hash equal: True
- bls-01: rows 817,174,629 → 708,565,127 (-13.29%), hash equal: True
- bls-02: rows 602,450,412 → 533,506,987 (-11.44%), hash equal: True

### Blocks (jeth trace, proven ELF; hash vs record; keccak perms of the proven run)

| block | rows before | rows after | Δ | hash == record | perms before → after |
|---|---:|---:|---:|---|---:|
| 25905781 | 601,992,101 | 601,992,101 | +0.00% | True | 115373 → 115373 |
| 25905782 | 715,141,963 | 715,141,963 | +0.00% | True | 124117 → 124117 |
| 25905783 | 333,107,908 | 333,107,908 | +0.00% | True | 61886 → 61886 |
| 25905784 | 250,985,973 | 250,985,973 | +0.00% | True | 51424 → 51424 |
| 25905785 | 628,588,538 | 628,588,538 | +0.00% | True | 121623 → 121623 |
| 25905786 | 291,810,444 | 291,810,444 | +0.00% | True | 59024 → 59024 |
| 25905787 | 395,621,866 | 395,621,866 | +0.00% | True | 70085 → 70085 |
| 25905788 | 92,464,391 | 92,464,391 | +0.00% | True | 19238 → 19238 |
| 25905789 | 676,244,012 | 676,244,012 | +0.00% | True | 133642 → 133642 |
| 25905790 | 432,649,242 | 432,649,242 | +0.00% | True | 90051 → 90051 |
| 25694235 | 1,426,158,765 | 1,407,097,112 | -1.34% | True | 193806 → 193806 |

### Forged / edge blocks (guest hash == native hash)

| block | cases | native hash | before rows / hash eq | after rows / hash eq |
|---|---:|---|---|---|
| forged-00 | 40 | 0x643ef9133ea8… | 28,609,915 / True | 28,343,736 / True |
| forged-01 | 40 | 0xcdd171db8863… | 103,907,900 / True | 97,116,730 / True |
| forged-02 | 40 | 0x4fb0e2c34090… | 296,034,109 / True | 260,362,955 / True |
| forged-03 | 40 | 0x035a04ecb901… | 73,876,799 / True | 70,045,078 / True |
| forged-04 | 39 | 0x53264c500059… | 294,789,632 / True | 261,840,687 / True |

Forged blocks = 199 single-call cases (EIP-2537 official vectors incl. every `fail-*` vector ≤ 4 G2
pairs / 3 pairings, plus hand-made: G1/G2 infinity encodings, coordinates = p / p+1, padding bit,
scalars 0 / r / r−1 / 2²⁵⁶−1, (r−1)·G + 1·G, MSM k = 0 and duplicated points, pairings with infinity
operands, KZG valid / wrong proof / wrong commitment / wrong versioned hash / z = r / z = 2²⁵⁶−1 /
y = r / infinity commitment (zero polynomial) / commitment 0xff… / lengths 191 and 193). Each case
SSTOREs the STATICCALL success flag, the output words and RETURNDATASIZE.

### Block 25905781 attribution (`jeth profile --rows`, off vs on)

Identical: the block makes no BLS12-381 / KZG precompile call (every `ark_bls12_381` symbol has 0
entries; the ark-ff rows in the block are bn254 `sum_of_products::<2>` 10,451,336 rows / 1.74% from
ecpairing). Top symbols off = on: `recovery_batch::pippenger` 4.81%, handler execution 3.77%, memcpy
3.77%, `decode_node_zc_into` 2.59%. Rows 601,992,101 both.

### Block 25694235 (Aztec, 671 txs, 1.43 G rows) attribution

Rows 1,426,158,765 → 1,407,097,112 (−1.34%); hash = chain hash
`0x1a8f8e57…a0659e`; keccak perms 193,806 both. The block is dominated by bn254 (ecpairing:
`MontBackend<bn254>` mul/sop 6.19% + 3.75% + 2.78% + …, the bn254 lane's target); its BLS12-381
share (`ark_bls12_381`/kzg symbols in the top-60) goes 125,142,262 rows (8.77%) → 99,812,538 (7.09%),
−20%. Calls: 4 `pairing_check`, 4 `verify_kzg_proof`, 4 G1 + 4 G2 `mul_bigint`.

| symbol (before → after) | calls | rows before | rows after |
|---|---:|---:|---:|
| `Fp<bls12_381>::sum_of_products::<2>` | 61,840 (+90) | 73,134,016 (1,183/call) | inlined into callers |
| `MontBackend<bls12_381>::mul_assign` | 27,800 + 6,342 | 19,829,468 + 4,524,776 | inlined into callers |
| `Fq2<bls12_381>::mul_assign` | 28,224 | 5,638,208 (glue only) | 55,488,384 (1,966/call, FP2MUL + glue) |
| `Fq2<bls12_381>::square_in_place` | 8,772 | (below top-60) | 12,421,152 (1,416/call, 2 MULP + glue) |
| pairing `ZipEq` loop (G1-side Fp muls inlined) | 12 | — | 7,306,788 |
| `MontBackend<bls12_381>::square_in_place` | 5,540 + 8,566 | 4,997,058 + 3,230,644 | unchanged (compiled) |
| `MontBackend<bls12_381>::add_assign` / `sub_assign` | 100,732 / 81,524 | 7,247,840 / 6,540,252 | unchanged |

### Workspace tests / hooks

`cargo nextest run --cargo-quiet --release --workspace --features jeth-host/secp-inline`: 47 passed
(incl. the 10 inline-crate tests); pre-commit (fmt, clippy) green on every commit (`DISABLE_TYPOS=1`
only for the repo's pre-existing typos in RESULTS.md / zeth_trie.rs; the lane's files are typo-clean).

## Harness (`.journals/lanes/inlines-b-bls/`, run from `/Volumes/Dev/jeth-scratch/inlines-b-bls/opcg` with
the opcode-max-cg `evm.py`/`runner.py`)

`build_guest_side.sh <side>` builds the four guest ELF flavours (validate_block ± pertx ± compute_advice)
into `target/guest-<side>-*`; `bls_gate.py build|measure <side>|blocks <side>|report` (synth configs,
real blocks); `bls_forged.py build|native|trace <side>|report` (199 forged cases); `profile_block.sh
<side> <block>`; `bls_report.py` assembles the tables above; `bn254_gate.py <side> <tag>` measures the bn254
ECPAIRING k=1 synth block (`results-bn254-<tag>.json`).

## Notes / open questions

* Fp squaring stays compiled (581 rows < MULP 647); a fused FP2SQR (≈1,380 rows vs the 2 MULP + glue
  ≈1,416 measured on the Aztec block) is the next step on G2/pairing paths (≈ −6% more on G2MSM).
* G1 paths gain little (G1ADD −0.7%, G1MSM −4.9%): Fp-only arithmetic where MULP saves 9% per
  multiplication and add/sub/decoding dominate.
* The bn254 lane edits the same four vendored files (`Cargo.toml`, `lib.rs`, `montgomery_backend.rs`,
  `quadratic_extension.rs`); merging both hooks is a mechanical conflict resolution (independent
  if-arms and consts).
* Vendoring ark-ff as a path dependency surfaces two upstream `#[must_use]`-on-trait-method warnings
  in host builds (unchanged upstream code).
* History: the earlier `.cargo/config.toml` edit was dropped from this branch and the file removed in
  8dd5e6f (orchestrator instruction; matches inlines-b 3c8658c).

## Rebase onto inlines-b (bn254 + blake2f lanes merged)

Rebased onto a40f122; the duplicate vendor commit and the `.cargo/config.toml` removal were dropped
as already applied. Conflicts resolved as unions: workspace `members` / `[workspace.dependencies]`
(both inline crates, one `jolt-inlines-sdk` line), one `[patch.crates-io] ark-ff` block (comment
names both hooks) in the root and guest manifests, vendored `Cargo.toml` (both features, both
optional deps), `lib.rs` (both `mod` lines), `montgomery_backend.rs` (both consts; the bn254 N == 4
arm and the BLS12-381 N == 6 arm as consecutive if-arms in `mul_assign` and `sum_of_products`),
`quadratic_extension.rs` (both Fq2 arms), jeth-core features (`bn254-inline`, `bls12-381-inline`),
guest feature list, host deps + both `extern crate` lines; both lockfiles regenerated from the
inlines-b versions. Review fix (compile-time layout guard in `JOLT_BLS12_381_FQ`) applied cleanly.

Workspace nextest on the rebased tree: 71 passed. Guest rebuilt (`target/guest-validate_block` +
`-compute_advice`); the ELF carries the bn254 (funct7 0x00), BLAKE2b and BLS12-381 (funct7 0x01)
inline words. Traces (hash == record for every block; perms of the proven run):

| block | rows feature-off | rows bls-only | rows union (bn254 + bls) | union vs off | hash == record | perms (off / bls / union) |
|---|---:|---:|---:|---:|---|---:|
| 25905781 | 601,992,101 | 601,992,101 | 596,202,724 | -0.96% | True | 115373 / 115373 / 115373 |
| 25905782 | 715,141,963 | 715,141,963 | 703,571,840 | -1.62% | True | 124117 / 124117 / 124117 |
| 25905783 | 333,107,908 | 333,107,908 | 327,442,400 | -1.70% | True | 61886 / 61886 / 61886 |
| 25905784 | 250,985,973 | 250,985,973 | 250,985,973 | +0.00% | True | 51424 / 51424 / 51424 |
| 25905785 | 628,588,538 | 628,588,538 | 624,144,707 | -0.71% | True | 121623 / 121623 / 121623 |
| 25905786 | 291,810,444 | 291,810,444 | 291,810,444 | +0.00% | True | 59024 / 59024 / 59024 |
| 25905787 | 395,621,866 | 395,621,866 | 392,228,863 | -0.86% | True | 70085 / 70085 / 70085 |
| 25905788 | 92,464,391 | 92,464,391 | 92,464,391 | +0.00% | True | 19238 / 19238 / 19238 |
| 25905789 | 676,244,012 | 676,244,012 | 671,810,582 | -0.66% | True | 133642 / 133642 / 133642 |
| 25905790 | 432,649,242 | 432,649,242 | 432,649,242 | +0.00% | True | 90051 / 90051 / 90051 |
| 25694235 | 1,426,158,765 | 1,407,097,112 | 1,381,243,122 | -3.15% | True | 193806 / 193806 / 193806 |

Ten regular blocks: 4,418,606,438 → 4,383,311,166 rows (-0.80%, all bn254 lane); 25905781
union 596,202,724 (bn254 lane reported 596,202,738 on its own tree — 14 rows apart, same hash).
Aztec 25694235: feature-off 1,426,158,765 → bls-only 1,407,097,112 → union 1,381,243,122 (−3.15%;
record 1,430,619,793 on the older amber-nolane tree), hash 0x1a8f8e57…a0659e, perms 193,806.

## Fq2 guard follow-up (proof-gate finding)

The proof-gate lane found that in a Jolt example guest `is_fq2` ran at run time — the
`characteristic() == &MODULUS[..]` slice compare became a 48-byte `memcmp` (627 rows with that
guest's byte-wise memcmp) and `NONRESIDUE == -ONE` a run-time negation + copy (84 rows) — so FP2MUL
saved ≈ 0 rows there (2,631 hooked vs 2,632 compiled). In the jeth guest the same guard cost ≈ 103 rows
per Fq2 multiplication (word-wise memcmp ≈ 57 rows + ≈ 46 rows of negation/compare inside the symbol),
which is why G2MSM still measured −13.9%: FP2MUL netted ≈ −540 of the possible ≈ −650 rows per Fq2 mul.

Fix: `is_fq2` is a `const fn` over compile-time constants only — element/extension sizes and offsets,
`size_of::<BasePrimeField::BigInt>() == 48`, the base prime field's `MODULUS` limbs == p and
`P::NONRESIDUE` limbs == `MINUS_ONE` (p − R mod p, new crate constant asserted against `-Fq::ONE` and
`Fq2Config::NONRESIDUE`), both read through const raw-pointer casts after the size checks — bound to
the associated const `QuadExtField::<P>::JOLT_BLS12_381_FQ2`, so the arm folds at monomorphization
like the `MontBackend` consts. No run-time memcmp, negation or copy remains.

Fold proof (`jeth profile --rows --entries`, same synth blocks, pre-fix → post-fix):

* bls-01 (G2MSM k1/k8 + PAIRING k1/k2): `memcmp` 630,677 → 274,608 calls (−356,069 = the block's Fq2
  multiplications), 35,100,982 → 14,701,801 rows; `memcpy` unchanged (831,902 calls); block
  708,565,127 → 671,810,196 rows (−5.2%). `Fq2::mul_assign` no longer appears as a symbol: with a
  constant guard the body is small enough that LLVM inlines it into its callers.
* bls-00 (G1ADD, G2ADD, G1MSM): `memcmp` 143,568 → 141,982 calls; block 155,195,803 → 155,031,469.

Re-measured synth configs (per-tx Δ method; off = feature off; old after = run-time guard; new after
= constant guard):

| config | rows/call off | old after (Δ vs off) | new after (Δ vs off) | old → new |
|---|---:|---:|---:|---:|
| BLS_G1ADD | 129,963 | 129,043 (-0.7%) | 129,043 (-0.7%) | +0.0% |
| BLS_G2ADD | 181,641 | 173,614 (-4.4%) | 170,920 (-5.9%) | -1.6% |
| BLS_G1MSM/k1 | 3,448,785 | 3,280,877 (-4.9%) | 3,280,877 (-4.9%) | +0.0% |
| BLS_G1MSM/k8 | 13,100,576 | 12,487,596 (-4.7%) | 12,487,596 (-4.7%) | +0.0% |
| BLS_G2MSM/k1 | 9,925,612 | 8,542,744 (-13.9%) | 8,114,948 (-18.2%) | -5.0% |
| BLS_G2MSM/k8 | 31,239,492 | 26,890,368 (-13.9%) | 25,494,906 (-18.4%) | -5.2% |
| BLS_PAIRING/k1 | 20,818,507 | 18,120,306 (-13.0%) | 17,141,281 (-17.7%) | -5.4% |
| BLS_PAIRING/k2 | 27,441,924 | 23,854,532 (-13.1%) | 22,611,960 (-17.6%) | -5.2% |
| BLS_MAP_FP_TO_G1 | 1,664,688 | 1,610,511 (-3.3%) | 1,610,511 (-3.3%) | +0.0% |
| BLS_MAP_FP2_TO_G2 | 5,039,926 | 4,569,074 (-9.3%) | 4,449,400 (-11.7%) | -2.6% |
| POINTEVAL | 37,923,831 | 33,186,684 (-12.5%) | 31,672,325 (-16.5%) | -4.6% |

- bls-00: off 162,215,227 → old 155,195,803 → new 155,031,469; hash equal: True
- bls-01: off 817,174,629 → old 708,565,127 → new 671,810,196; hash equal: True
- bls-02: off 602,450,412 → old 533,506,987 → new 512,265,023; hash equal: True

Blocks (constant guard): 25905781 596,202,724 rows, hash 0xf691da3f…, perms 115,373 (unchanged — no
BLS calls); 25694235 (input copied from /Volumes/Dev/jeth-top50-data) 1,375,135,731 rows (feature-off
1,426,158,765 → bls-only 1,407,097,112 → union 1,381,243,122 → now −3.58% vs off), hash
0x1a8f8e57…a0659e, perms 193,806. Workspace nextest: 71 passed.

## bn254 Fq2 guard follow-up (review N2 + N1)

Reviewer finding: `jolt_bn254::is_fq2` was still a run-time fn (`characteristic()` slice compare + raw
pointer read of `NONRESIDUE`). LLVM happened to fold it in the jeth guest (810 rows per bn254 Fq2 mul =
FP2MULQ 797 + two conditional subtractions), but the dispatch must not depend on a fold.

Change: `is_fq2` is a `const fn` mirroring the BLS guard — `size_of::<BaseField>() == 32`,
`align_of::<BaseField>() == 8`, `size_of::<QuadExtField>() == 64`, `offset_of!(c0, c1) == 0, 32`,
`size_of::<BasePrimeField::BigInt>() == 32`, then the prime field's `MODULUS` limbs == q and the
`NONRESIDUE` limbs == `BN254_MINUS_ONE` (crate constant already asserted against `-Fq::ONE` and
`Fq2Config::NONRESIDUE` in the bn254 crate tests) through const raw-pointer reads — bound to
`QuadExtField::<P>::JOLT_BN254_FQ2`; the `MulAssign` arm tests the const and the
`extension_degree()`/`characteristic()` path is gone. N1: `align_of == 8` added to the BLS `is_fq2`
pre-checks and to `MontBackend::JOLT_BLS12_381_FQ`.

Codegen proof (riscv64imac release rlib of a probe crate on the vendored ark-ff with both hook
features; `ark_bn254::Fq2 *= Fq2`, `ark_bn254::Fq *= Fq`, `ark_bls12_381::Fq2 *= Fq2`;
`llvm-objdump -d -r`): bn254 Fq2 mul = the FP2MULQ word `00b5352b` + two conditional subtractions
(ld/sltu/sub/bltu against the modulus constant pool), no calls; bn254 Fq mul = MULQ `00b5052b` + one
subtraction; BLS Fq2 mul = FP2MUL `02b5252b` + `ret`. No memcmp/bcmp relocation anywhere in the rlib.

Measurements (guest rebuilt from this tree; pre-fix ELF = 92a1093 tree; `bn254_gate.py`, per-tx Δ
method, K = 8 vs 4 calls):

| | pre-fix | post-fix |
|---|---:|---:|
| BN254_PAIRING/k1 rows/call | 9,551,488.5 | 9,551,488.5 |
| bn254-00 block rows | 126,855,692 | 126,855,692 (hash 0xee98a00d… equal) |
| 25905781 rows / hash / perms | 596,202,724 / 0xf691da3f… / 115,373 | unchanged |

The bn254 lane reported 9,544,692 rows/call for the same config on its own tree; the +6,796 here is the
merged (bn254 + BLS12-381 + blake2f) code layout, identical before and after this change. Workspace
nextest: 71 passed.
