# Lane B-bn254 — bn254 Fq Montgomery inlines (MULQ, SOPQ2, FP2MULQ) hooked into ark-ff

Branch `inlines-b-bn254` off `inlines-b` @ 6557a40 (Phase A + jolt repin). Jolt pin `/Volumes/Dev/worktrees/jolt/jolt-inlines-b` (read-only). Opcode 0x2B, funct7 0x00, extension `InlineExtension::External`.
Build dirs: worktree `target/` (the tracked `.cargo/config.toml` target-dir override is dropped in 92018e0), `JETH_GUEST_TARGET_DIR=target/guest-{off,on}`, `JOLT_PATH=/Volumes/Dev/worktrees/jolt/jolt-inlines-b/target/release/jolt`; inputs + scratch under `/Volumes/Dev/jeth-scratch/inlines-b-bn254/{data,logs,opcg,edge}`.

## 0. Pre-gate (jeth profile --rows --entries, feature off, guest = this tree)

`jeth profile --rows --top 400 --entries mul_assign,square_in_place,sum_of_products` counts entries (PC == symbol start) and exact self rows per symbol. Two monomorphized copies of every Fq routine exist (revm-precompile and jeth-core instantiations); the table sums both.

| block | symbol (`ark_bn254 FqConfig, 4`) | calls | self rows | rows/call |
|---|---|---:|---:|---:|
| 25905781 (601,992,115 rows) | `Fp::sum_of_products::<2>` | 28,133 (7,504 + 20,629) | 14,252,924 (10,451,336 + 3,801,588) | **506.6** |
| | `MontBackend::mul_assign` | 17,556 (5,712 + 11,844) | 5,449,785 (3,675,867 + 1,773,918) | **310.4** |
| | `MontBackend::square_in_place` | 4,573 | 1,174,992 | 256.9 |
| | Fq2 `square_in_place` (calls Fq mul/sop) | 4,589 (2,852 + 1,737) | 954,108 (self) | 207.9 |

| 25905785 (628,588,538 rows) | `Fp::sum_of_products::<2>` | 19,360 | 9,809,128 | 506.7 |
| | `MontBackend::mul_assign` | 29,044 | 9,017,826 | 310.5 |
| | `MontBackend::square_in_place` | 17,639 | 4,534,641 | 257.1 |
| 25905789 (676,244,012 rows) | `Fp::sum_of_products::<2>` | 19,323 | 9,789,360 | 506.6 |
| | `MontBackend::mul_assign` | 28,924 | 8,981,967 | 310.5 |
| | `MontBackend::square_in_place` | 17,521 | 4,504,584 | 257.1 |

`square_in_place` (ark's dedicated squaring, 257 rows) is cheaper than MULQ + canonicalization (≈ 280) and is left compiled.

Design rule (`.journals/bn254-fq-inline-design.md` §5): mul_assign ≥ 305 ✓ (310.4), sop2 ≥ 515 ✗ (506.6) → GO only as the package with the fused FP2 op. NO-GO test: projected 781 saving (§2) ≈ 0.5–0.65 % ≥ 0.4 %, adversarial BN254 pairing drop ≈ 15 % ≥ 8 % → not NO-GO. **Decision: build MULQ + SOPQ2 + FP2MULQ.**

## 1. Design choice per op: deterministic Montgomery vs advice quotient

Row accounting facts (verified in jolt-program `expand/materialize.rs`): every inline register touched costs one `ADDI rd, x0, 0` reset row at the end of the sequence (BIGINT256_MUL fixture 141 = 130 body + 11 resets); `LUI` and `VirtualMULI` take full 64-bit immediates; each 64-bit half-term of a multi-limb product costs `mul|mulhu; add; sltu; add` = 4 rows (3 for the first of a column, 2 when no carry-out is possible).

| candidate | rows/op (incl. resets) | why |
|---|---:|---|
| p256-style advice quotient, plain product `a·b = w·q + c` | n/a | ark stores Montgomery forms: the hook must return `a·b·R⁻¹ mod q`; the plain product gives `x·y·R²`. Not a drop-in. |
| advice Montgomery: `a·b + m·q = t·2^256`, m advised | ≈ +16 vs deterministic | m is unique (≡ −ab·q⁻¹ mod 2^256): advice buys nothing; the four `lo(m_k·q_0)` terms (16 rows) + 4 `advice` + 4 `assert_eq` replace 4 `muli` + 4 zero-checks (12 rows). |
| advice canonical output `a·b + m·q = (c + s·q)·2^256`, c, s advised + `c < q` range check | ≈ +40 | c + s·q costs ≈ 20 rows, the 256-bit range check ≈ 18 (borrow chain + assert), plus the assert rows. |
| **deterministic product-scanning Montgomery, output t ∈ [0, 2q), canonicalization by ark's compiled `subtract_modulus`** | MULQ 273 · SOPQ2 415 · FP2MULQ 797 | 60 (92, 2×92) half-terms, `m_k` via `VirtualMULI` by INV, the `lo(m_k·q_0)` term replaced by the carry `[column ≠ 0]`; the compiled `if t ≥ q { t −= q }` costs ≈ 6–7 dynamic rows (top-limb compare decides in all but ~2⁻⁶² of cases; the subtraction runs ≈ 5 % of the time) vs 30 rows for a branch-free in-inline select. |

The advice-quotient style pays only when `2^256 − q` has structure (P-256: limbs 1 and −1; secp256k1: 977·2^32+1) or when a non-canonical output is acceptable; bn254 q has four dense limbs and ark requires canonical limbs (`PartialEq`/`is_zero` are limb compares). Decision: deterministic for all three ops; no advice, no assert rows.

## 2. Spec

### Encoding / memory contract (R-type `.insn r 0x2B, funct3, 0x00, rd, rs1, rs2`; u64 limbs little-endian, 8-byte aligned; all loads precede all stores so `rd` may alias `rs1`/`rs2`)
| funct3 | name | reads | writes | semantics |
|---|---|---|---|---|
| 0x0 | BN254_MULQ | a = rs1[0..32), b = rs2[0..32) | rd[0..32) | t = (a·b + m·q)/2^256, m = −a·b·q⁻¹ mod 2^256 |
| 0x2 | BN254_SOPQ2 | a0,a1 = rs1[0..64), b0,b1 = rs2[0..64) | rd[0..32) | t = (a0·b0 + a1·b1 + m·q)/2^256 |
| 0x3 | BN254_FP2MULQ | a0,a1 = rs1[0..64), b0,b1 = rs2[0..64) | rd[0..64): c0 at 0, c1 at 32 | c1 = REDC(a0·b1 + a1·b0), c0 = REDC(a0·b0 + a1·(q − b1)) |

Domain: every input limb vector < q (ark's `Fp` invariant; `q − b1` ∈ [1, q] is fine). Then t < q(1 + 2q/2^256) < 1.378q (< 2q, all the caller's conditional subtraction needs) and < 2^255: column 7 has no carry-out and the caller's single conditional subtraction canonicalizes. Outside the domain (values ≥ q) the sequence still computes (Σ + m·q) mod 2^512 ≫ 256 exactly, i.e. the REDC value truncated to 256 bits — deterministic, never reachable from ark.

Constants: q = [0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029], INV = −q⁻¹ mod 2^64 = 0x87d20782e4866389 (= ark `FqConfig::INV`).

### Register plan (reset rows = registers touched)
MULQ 19: a[4] b[4] q[4] m[4] r[2] aux. SOPQ2 27: a[8] b[8] q[4] m[4] r[2] aux. FP2MULQ 27 (b1 is negated in place between the two products; r/aux double as borrow temps).

### Row budget (golden numbers asserted in `crates/inlines/bn254/src/tests.rs`)
| op | LD | LUI | columns | SD | extra | resets | total |
|---|---:|---:|---:|---:|---:|---:|---:|
| MULQ | 8 | 4 | 238 | 4 | – | 19 | **273** |
| SOPQ2 | 16 | 4 | 364 | 4 | – | 27 | **415** |
| FP2MULQ | 16 | 4 | 2×364 | 8 | 14 (q − b1) | 27 | **797** |
Column rows (terms n per column: first 3, others 4, column 7 terms 2, plus `muli` + zero-check 3 for k ≤ 3): MULQ 3/22/38/54/55/39/23/4; SOPQ2 7/34/58/82/83/59/35/6.

Compiled counterparts (781 measurements): mul_assign 310.4, sop2 506.6; an Fp2 mul = 2 sop2 + `neg_in_place` + array copies ≈ 1,060.

## 3. Soundness argument

- **No advice, no assert rows.** Each op is a fixed straight-line list of ordinary constrained instructions (`LD SD LUI MUL MULHU ADD SUB SLTU OR VirtualMULI`) executed by the tracer; the proof covers every row through the standard instruction lookups exactly as for compiled code. Nothing prover-chosen enters the computation, so soundness reduces to the correctness of the sequence.
- **REDC identity.** Product scanning accumulates column k of `Σ aᵢbᵢ + m·q` with `m = Σ mₖ2^{64k}`, `mₖ = rₖ·INV mod 2^64` (`INV = −q⁻¹ mod 2^64`). By construction column k ≤ 3 becomes ≡ 0 mod 2^64, hence `lo(mₖ·q₀) = 2^64 − rₖ` when `rₖ ≠ 0` and `0` otherwise: the low half of that product is never formed, its effect on the carry is exactly `[rₖ ≠ 0]` (`sltu carry, x0, rₖ`). Columns 4–7 are the output limbs `t = (Σ aᵢbᵢ + m·q)/2^256`.
- **Bounds.** In-domain inputs are canonical (`< q`, ark's `Fp` invariant, maintained by every constructor). MULQ: `ab < q²`; SOPQ2/FP2MULQ: `a₀b₀ + a₁b₁ < 2q²` (for c0, `q − b₁ ∈ [1, q]` so `a₁(q − b₁) ≤ (q−1)q`). Then `t < (2q² + 2^256 q)/2^256 = q(1 + 2q/2^256) < 1.378q` (tight; `< 2q` is what the caller's single conditional subtraction needs) and `t < 2^255` because `q < 2^254`. So the exact integer `Σ + m·q = t·2^256 < 2^511`: column 7 has no carry-out and dropping it is exact. Every intermediate column sum is held as (lo, hi) with hi a small carry count (≤ number of terms), never overflowing 64 bits.
- **Canonical result.** `t ∈ [0, 1.378q) ⊂ [0, 2q)`; the hook applies ark's own `subtract_modulus` (`if t ≥ q { t −= q }`) — the same post-condition ark's compiled CIOS `mul_assign` relies on — so every value handed back is canonical and `PartialEq`/`is_zero` limb compares stay valid.
- **Fq2 semantics.** `(a₀ + a₁u)(b₀ + b₁u) = (a₀b₀ − a₁b₁) + (a₀b₁ + a₁b₀)u` for `u² = −1`; `is_fq2::<P>()` checks at runtime (const-folded) that `P::NONRESIDUE` is `−1` in Montgomery form, the base field characteristic is q, and the `{c0, c1}` layout is two 32-byte fields at offsets 0/32.
- **Out of domain.** Limbs ≥ q are unreachable from ark. If they were supplied, the sequence still evaluates `(Σ + m·q) mod 2^512 ≫ 256` deterministically (tested against the software model in `out_of_domain_inputs_match_model`); no UB, no trap.
- **Aliasing and memory.** All loads precede all stores, so `rd` may alias `rs1`/`rs2` (tested `rd == rs1` and `rd == rs1 == rs2`); only the documented 32/64-byte ranges are read/written; ark's `Fp`/`QuadExtField` are 8-byte aligned `[u64; 4]`/`[[u64; 4]; 2]` blocks (size checks are asserted, `offset_of!` for the pair).
- **Register hygiene.** Every inline register is released before `finalize`; the materializer resets each one (`ADDI r, x0, 0`) at the end of the sequence, so nothing leaks between invocations and the guest never observes virtual registers.
- **Rust `unsafe` (all inside `crates/vendor/ark-ff/src/jolt_bn254.rs`).** Pointer casts `&mut Fp → *mut u64` (Fp's only non-ZST field is `BigInt<4> = [u64; 4]`, `size_of == 32` asserted), `&QuadExtField → *const u64` (offsets asserted), `MaybeUninit<Fp>` fully written by SOPQ2 before `assume_init`, `*mut u64 → &mut BigInt<4>` for `subtract_modulus`; the `.insn` asm blocks in `crates/inlines/bn254/src/sdk.rs` (`options(nostack)`, pointers passed by register). The arms in `montgomery_backend.rs`/`quadratic_extension.rs` contain no `unsafe`.

## 4. Gates (before = same tree, `bn254-inline` removed from the guest manifest; after = feature on; same host binary e0de510)

Ten-block set — before column reproduces the inlines-b baseline rows exactly and every hash equals the amber-nolane record; keccak census (`keccak[post_validation] perms`) identical before/after.

| block | before rows | after rows | Δ | Δ % | hash == record | perms |
|---|---:|---:|---:|---:|---|---:|
| 25905781 | 601,992,101 | 596,202,738 | -5,789,363 | -0.962 % | yes | 115,373 |
| 25905782 | 715,141,963 | 703,571,854 | -11,570,109 | -1.618 % | yes | 124,117 |
| 25905783 | 333,107,908 | 327,442,414 | -5,665,494 | -1.701 % | yes | 61,886 |
| 25905784 | 250,985,973 | 250,985,987 | +14 | +0.000 % | yes | 51,424 |
| 25905785 | 628,588,538 | 624,144,721 | -4,443,817 | -0.707 % | yes | 121,623 |
| 25905786 | 291,810,444 | 291,810,458 | +14 | +0.000 % | yes | 59,024 |
| 25905787 | 395,621,866 | 392,228,877 | -3,392,989 | -0.858 % | yes | 70,085 |
| 25905788 | 92,464,391 | 92,464,405 | +14 | +0.000 % | yes | 19,238 |
| 25905789 | 676,244,012 | 671,810,596 | -4,433,416 | -0.656 % | yes | 133,642 |
| 25905790 | 432,649,242 | 432,649,256 | +14 | +0.000 % | yes | 90,051 |
| total | 4,418,606,438 | 4,383,311,306 | -35,295,132 | -0.799 % | gas-weighted c/g 13.763942 → 13.653998 | |

Synth configs (`.journals/opcode-max-cg` per-tx method, Δ(K − K/2) units, `jeth txprofile`; K = 200/100/100/20/15/8/4 units):

| config | before rows/unit | before c/g | after rows/unit | after c/g | Δ rows/unit | Δ % |
|---|---:|---:|---:|---:|---:|---:|
| BN254ADD (G + 7G) | 61,534.6 | 228.75 | 61,138.6 | 227.28 | -396.0 | -0.6 % |
| BN254MUL/full-scalar (n − 1) | 790,027.0 | 129.11 | 745,722.0 | 121.87 | -44,305.0 | -5.6 % |
| BN254MUL/scalar2 | 113,410.2 | 18.53 | 112,824.2 | 18.44 | -586.0 | -0.5 % |
| BN254PAIRING/k1 | 11,872,924.9 | 150.06 | 9,544,691.9 | 120.64 | -2,328,233.0 | -19.6 % |
| BN254PAIRING/k2 | 16,398,981.3 | 144.97 | 13,093,035.3 | 115.75 | -3,305,946.0 | -20.2 % |
| BN254PAIRING/k4 | 26,755,439.8 | 147.72 | 21,338,704.8 | 117.82 | -5,416,735.0 | -20.2 % |
| BN254PAIRING/k8 | 48,843,570.5 | 154.02 | 38,935,487.5 | 122.78 | -9,908,083.0 | -20.3 % |

Forged / edge blocks (`/Volumes/Dev/jeth-scratch/inlines-b-bn254/edge/edge_bn254.py`): one block, 62 txs, three contracts that STATICCALL 0x06/0x07/0x08 with bounded gas and SSTORE `(ok << 24 | returndatasize << 8)` plus both output words, so every result (including failures and gas) lands in the state root. Native hash `0x0ef415463b5d2af4dbe84120eec8e72ca8451483ffaed8ccc666f8e4071307e0`; guest hash equal with the feature off (251,030,841 rows) and on (203,894,661 rows, −18.8 %); no guest panic. Vectors: ecadd G+G, G+2G, G+(−G)=O, G+O, O+O, (1,3) invalid, x=q, x=q+1, y=2²⁵⁶−1, x=y=2²⁵⁶−1, (0,1), truncated 64 B / 100 B, empty, extra bytes, 5G+7G, (−G)+(−G); ecmul G×{0,1,2,3,n,n+1,n−1,2²⁵⁶−1,2²⁵⁵,q}, O×5, invalid point, x=q, 7G×random, (−G)×(n−1), truncated 64/32 B, empty, extra bytes; pairing empty, e(G,G2), e(3G,G2), e(G,−G2), k2/k4 identities (incl. 2·G2 and −2G), k3 with O, (O,G2), (G,O2), G2 off-twist, G2 on twist but outside the r-torsion (x = 1 + 0u), G1 invalid, G1 x ≥ q, G2 coordinate ≥ q, swapped re/im, lengths 191/193/64, the study's k8/k4 vectors.

Workspace `cargo nextest run --cargo-quiet --release --workspace --features jeth-host/secp-inline`: 50 passed (incl. the 13 inline-crate tests: golden rows 273/415/797, 10k random ×3 ops, edge cartesian ×3 ops, 20k model-vs-ark, aliasing, out-of-domain).

781 attribution (`jeth profile --rows`, symbols build; totals identical to the plain ELF: 601,992,101 / 596,202,738, Δ −5,789,363 = −0.96 %). With the feature on the hook is `#[inline(always)]`, so inline rows land in the caller's symbol; `mul_assign`/`sum_of_products` disappear as symbols and the callers grow — read the totals, not single rows.

| symbol (`ark_bn254`, both monomorphized copies) | before calls | before self rows | after calls | after self rows |
|---|---:|---:|---:|---:|
| `MontBackend::mul_assign` | 17,556 | 5,449,785 | – (inlined MULQ, 280 rows incl. canonicalization) | – |
| `Fp::sum_of_products::<2>` | 28,133 | 14,252,924 | – (FP2MULQ / inlined SOPQ2) | – |
| `QuadExtField<Fq2>::mul_assign` | – (compiled, inlined into callers) | – | 12,781 | 10,352,848 (810.0/call) |
| `QuadExtField<Fq2>::square_in_place` | 4,589 | 954,108 | 4,589 | 3,458,368 (its two Fq muls now in-symbol) |
| `MontBackend::square_in_place` | 4,573 | 1,174,992 | 4,573 | 1,174,992 |
| `Bn::ell` | | 685,340 | | 933,620 |
| `Projective<G1>::add_assign` / `double_in_place` | | 216,063 / 302,889 | | 948,440 / 875,988 |
| `CubicExtField<Fq6>::mul_assign` | 383 | 969,316 | 383 | 721,762 |
| `Fq12::cyclotomic_square_in_place` | 189 | 849,495 | 189 | 706,665 |

Blocks without bn254 precompile traffic (784, 786, 788, 790) move by exactly +14 rows: ELF layout, not inline rows (same effect the bigint lane saw with the opposite sign).

## 5. Result, files, decisions

**Verdict: built.** Ten blocks −35,295,132 rows (−0.80 %, c/g 13.763942 → 13.653998), 781 −0.96 %, pairing configs −20 %, BN254MUL −5.6 %, all hashes and keccak censuses unchanged, forged block guest == native, nextest 50/50 green, pre-commit (fmt + clippy `-D warnings`) green on every commit; typos skipped (`DISABLE_TYPOS=1`) only for pre-existing repo typos (RESULTS.md, zeth_trie.rs, vendored ark-ff tests) — changed files are typos-clean.

Commits on `inlines-b-bn254` (base `inlines-b` @ 6557a40): 93e28db docs pre-gate · e11b444 `chore(vendor): ark-ff 0.5.0 for guest field hooks` (byte-identical to the registry crate) · e0de510 `feat(inlines): bn254 Fq Montgomery inlines hooked into ark-ff` · 92018e0 `chore: drop the repo-level cargo target-dir override` (same content as inlines-b 3c8658c) · this journal.

Files (e0de510): `crates/inlines/bn254/{Cargo.toml, src/{lib,sdk,exec,host,sequence_builder,spec,tests}.rs}` (new crate `jeth-inlines-bn254`, workspace member); `crates/vendor/ark-ff/{Cargo.toml (+optional dep, feature jolt-bn254-inline), src/lib.rs (+mod), src/jolt_bn254.rs (new), src/fields/models/fp/montgomery_backend.rs (const modulus check + two cfg'd arms), src/fields/models/quadratic_extension.rs (one cfg'd arm)}`; `Cargo.toml` (+member, `[patch.crates-io] ark-ff`), `crates/core/Cargo.toml` (feature `bn254-inline`, optional dep), `crates/guest/Cargo.toml` (feature on jeth-core, `[patch.crates-io]`), `crates/host/Cargo.toml` + `src/trace.rs` (`extern crate` to register the ops), both lockfiles. `cargo tree`: in the guest graph the vendored ark-ff is the only ark-ff for revm-precompile, jeth-core, ark-bn254/ark-ec/ark-poly/ark-bls12-381; the a16z fork is reached only by its own ark-ec/ark-poly/ark-secp256k1 and jolt-inlines-secp256k1. Jolt pin untouched.

Decisions / kill list: advice-quotient (p256 style) rejected for Montgomery-form fields (§1); in-inline branch-free canonicalization rejected (+23 rows vs the compiled conditional subtract); `square_in_place` hook rejected (compiled 257 < MULQ 280); an `N == 6` arm is the BLS lane's to add (the `if` chain in `montgomery_backend.rs` is shaped for it).

Open questions: (1) the remaining 2,571 stand-alone `sum_of_products::<2>` calls on 781 (Fq2 squaring / G1 formulas) could take a 3-term or `a·b + c·d` variant only if a caller with ≥ 3 terms shows up — none does today; (2) `subtract_modulus` runs on the caller side (~7 rows/op); folding it into the inline costs 30 rows, so it stays out unless a future lookup makes a 256-bit compare cheap; (3) `getrandom` blocks a plain `cargo check --target riscv64imac-unknown-none-elf` of the guest (jolt's build sets the backend), so the riscv compile gate is the `jeth`-driven build.

## 6. Review follow-ups and rebase

Review (APPROVE with should-fixes) → a0e6462 `fix(inlines): review follow-ups`: sequences (not the model) vs upstream ark-ff on 20k random quadruples and every ordered adversarial triple ({0, 1, R, R², q−1, q−2, (q−1)³, −1, 2, 1⁻¹, 2ᵏ low/top limb, saturated limbs}, 22³ = 10,648 triples × 3 ops, one reused harness per op → 11 s), a structural pass over the emitted rows (every rd virtual, LD bases ∈ {rs1, rs2}, SD base = rs3 with virtual data, last LD before first SD, zero advice/assert rows, reset set == written set), the extreme-operand bound check; `size_of`/`M` guards are `assert!` (const-folded when true); the edge element `[q₀−1, MAX, MAX, q₃]` (≥ q) became the in-domain corner `[q₀−1, q₁, q₂−1, q₃]` and moved to the out-of-domain test; `is_fq2` documents its const folding; the bound is stated tight (t < 1.378q).

Rebased onto `inlines-b` @ 82f8912 (blake2f lane merged, `.cargo/config.toml` removal 3c8658c, per-worktree guest/jolt defaults fe3359f); the duplicate target-dir commit dropped out; unions in the workspace members, host deps + `extern crate`s, guest features; lockfiles re-resolved from the inlines-b versions. Rebased tree: fmt/typos(changed files)/clippy green, nextest 61/61, guest rebuilt into `target/guest` — ten blocks reproduce the pre-rebase rows to the row (781 596,202,738 … 790 432,649,256; total 4,383,311,306, c/g 13.653998), hashes == records, perms equal: blake2f contributes Δ0 on this set.
