# Lane B-bn254 — bn254 Fq Montgomery inlines (MULQ, SOPQ2, FP2MULQ) hooked into ark-ff

Branch `inlines-b-bn254` off `inlines-b` @ 6557a40 (Phase A + jolt repin). Jolt pin `/Volumes/Dev/worktrees/jolt/jolt-inlines-b` (read-only). Opcode 0x2B, funct7 0x00, extension `InlineExtension::External`.
Build dirs: `CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-inlines-b-bn254`, `JETH_GUEST_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-inlines-b-bn254-guest`; inputs + scratch under `/Volumes/Dev/jeth-scratch/inlines-b-bn254/{data,logs}` (cargo-target was wiped externally at 23:27 — everything there is disposable).

## 0. Pre-gate (jeth profile --rows --entries, feature off, guest = this tree)

`jeth profile --rows --top 400 --entries mul_assign,square_in_place,sum_of_products` counts entries (PC == symbol start) and exact self rows per symbol. Two monomorphized copies of every Fq routine exist (revm-precompile and jeth-core instantiations); the table sums both.

| block | symbol (`ark_bn254 FqConfig, 4`) | calls | self rows | rows/call |
|---|---|---:|---:|---:|
| 25905781 (601,992,115 rows) | `Fp::sum_of_products::<2>` | 28,133 (7,504 + 20,629) | 14,252,924 (10,451,336 + 3,801,588) | **506.6** |
| | `MontBackend::mul_assign` | 17,556 (5,712 + 11,844) | 5,449,785 (3,675,867 + 1,773,918) | **310.4** |
| | `MontBackend::square_in_place` | 4,573 | 1,174,992 | 256.9 |
| | Fq2 `square_in_place` (calls Fq mul/sop) | 4,589 (2,852 + 1,737) | 954,108 (self) | 207.9 |

(785 / 789: see §0.1 — re-run pending after the cargo-target wipe.)

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

Domain: every input limb vector < q (ark's `Fp` invariant; `q − b1` ∈ [1, q] is fine). Then t < 2q < 2^255: column 7 has no carry-out and the caller's single conditional subtraction canonicalizes. Outside the domain (values ≥ q) the sequence still computes (Σ + m·q) mod 2^512 ≫ 256 exactly, i.e. the REDC value truncated to 256 bits — deterministic, never reachable from ark.

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
