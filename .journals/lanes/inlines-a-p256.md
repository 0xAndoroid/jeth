# Lane A-p256 — P256VERIFY (RIP-7212, 0x100) through the Jolt P-256 inline

Branch `inlines-a-p256` off `inlines-a` @ 60283c9 (amber-nolane + synth tool). Jolt pin jolt-amber-nolane @ a0d7b74baa (read-only, untouched).
Build dirs: `/Volumes/Dev/cargo-target/jeth-inlines-a-p256{,-guest-*}` (seeded by APFS clone from jeth-inlines-a / amber-nolane dirs; stale ELFs deleted before every build).
Harness: `/tmp/opcg-p256/` (evm.py/runner.py from `.journals/opcode-max-cg/` repointed); lane scripts copied to `.journals/lanes/inlines-a-p256/` — they hard-code `/tmp/opcg-p256` (binaries in `bin/`, cases in `cases/`, blocks in `blocks/`); re-create that tree (or edit the paths) before re-running.

## What changed (files)
- `Cargo.toml`: workspace dep `jolt-inlines-p256` (path, default-features = false).
- `crates/core/Cargo.toml`: feature `p256-inline = ["dep:jolt-inlines-p256"]`; dev-deps `jolt-inlines-p256/host`, `p256 0.13 (ecdsa)` for the differential tests.
- `crates/core/src/p256.rs` (new): `verify(msg, sig, pk) -> bool` + 5 differential tests against `revm_precompile::secp256r1::verify_impl` (r/s/pk/msg edges, message reduction, z = 0 with Q = ±G, ±2G, 3G and a generic key incl. the ±Q cross-check, RIP-7212 daimo vectors ± high-s, and a seeded xorshift run: 200 random keys/msgs with bit-flipped sig/pk/msg and z = 0 twins + 200 garbage inputs).
- `crates/core/src/crypto.rs`: `Crypto::secp256r1_verify_signature` override, `#[cfg(all(feature = "p256-inline", target_arch = "riscv64"))]` — native `run-native` stays on revm's `p256` software path.
- `crates/core/src/lib.rs`: `mod p256` under `any(all(p256-inline, riscv64), test)` — `cargo nextest run -p jeth-core` (no features) runs the tests through the dev-deps.
- `crates/host/Cargo.toml` + `src/trace.rs`: `jolt-inlines-p256/host` + `extern crate jolt_inlines_p256 as _` (inventory registration of the P256_* handlers; host features unchanged).
- `crates/guest/Cargo.toml`: `jeth-core` features += `p256-inline`. Lockfiles: `jolt-inlines-p256` (+ `ark-secp256r1` from the already-vendored a16z arkworks git rev, host only).
No jolt-repo edits. No new lookup tables, MAX_SUFFIXES untouched.

## Semantics: software accept set == inline accept set
Software (revm-precompile 34 `verify_signature`, `p256` 0.13 / `ecdsa` 0.16): input len 160 (checked before the hook);
`Signature::from_slice` ⇒ r,s < n (`ScalarPrimitive::from_slice`) and r,s ≠ 0; `VerifyingKey::from_encoded_point` on the
untagged 64 bytes ⇒ `FieldElement::from_repr` (x,y < p) and y² = x³ − 3x + b (identity is only reachable through the
SEC1 identity tag, never from 64 bytes; (0,0) fails the curve equation); `verify_prehashed`: z = reduce(msg) mod n (any 256-bit
value, z = 0 allowed), R = u1·G + u2·Q, accept iff R ≠ O and R.x mod n == r. No low-s rule.

`p256::verify` mapping:
| condition | software | inline path |
|---|---|---|
| x ≥ p or y ≥ p | reject | `P256Point::from_u64_arr` → `InvalidFqElement` → false |
| (x,y) off curve | reject | `AffinePoint::new` → `NotOnCurve` → false |
| (0,0) | reject (0 ≠ b) | passes `from_u64_arr` (infinity is "on curve" there) → explicit `q.is_infinity()` → false |
| r or s ≥ n | reject | `P256Fr::from_u64_arr` → `InvalidFrElement` → false |
| r = 0 or s = 0 | reject | `ecdsa_verify` → `ROrSZero` (z ≠ 0 path) / `ZeroMessageHash` or `ROrSZero` (z = 0 path: z' = r resp. −r is 0) → false |
| msg ≥ n | reduce | one conditional subtraction (n > 2^255 ⇒ 2^256 − 1 < 2n) — exact |
| z = 0 | accept iff (r/s)·Q ≠ O and x mod n == r | rewritten (below) |
| z ≠ 0 | R = u1·G + u2·Q | `ecdsa_verify(z, r, s, q)`: u1 = z/s, u2 = r/s, R1 = u1·G, R2 = u2·Q from Fake-GLV advice, each bound by its own 2×128 Shamir |
| R = O | reject (x(O) = 0 ≠ r) | `r_sum.is_infinity()` → `RxMismatch` → false |
| x(R) ≥ n | x − n (p < 2n) | same single subtraction |

z = 0 rewrite: software checks R = (r/s)·Q. `ecdsa_verify` rejects z = 0 (`ZeroMessageHash`), so verify the identical point as
`ecdsa_verify(z' = r, r, s, q' = Q − G)` ⇒ R' = (r/s)·G + (r/s)·(Q − G) = (r/s)·Q; when Q = G (Q − G = O is not a valid key)
use `ecdsa_verify(z' = n − r, r, s, q' = 2G)` ⇒ −(r/s)·G + (r/s)·2G = (r/s)·G. z' ≠ 0 because r ∈ [1, n−1]; q' is on-curve by the
group law and ≠ O (Q ≠ G resp. ord(G) = n > 2); the final `r1.add(&r2)` handles r1 == r2 (Q = 2G) via doubling. Cost: one extra
affine add (~1 div + 1 mul + 1 square). Exercised in unit tests (Q = G, 2G, 3G, generic) and in the guest by the edge block.
Inline-only failure modes that are NOT input rejections: every `spoil_proof()` in `verify_ecdsa_inner` (bad advice: off-curve R_i,
b_i·u_i ≠ a_i, b_i = 0, Shamir ≠ O) — only a dishonest prover reaches them; the tracer's advice is arkworks + half-GCD.
Adversarial u1/u2: u1 = z/s ≠ 0 and u2 = r/s ≠ 0 always hold on the inline path (z' ≠ 0, r ≠ 0), so the advice never sees s·P = O.

## Numbers
### Synth harness (per-tx method, Δ(K − K/2 units), gas/unit 7019 incl. glue; STATICCALL to 0x100 with the study vector, Osaka gas 6900)
| config | state | units | rows/unit | c/g |
|---|---|---:|---:|---:|
| P256VERIFY/k200 | before (this tree, guest `p256-inline` off) | 100 | 3,784,285.6 | 539.15 |
| P256VERIFY/k200 | after (e468741 / review fixes) | 100 | 502,089.6 / 501,978.6 | 71.53 / 71.52 |
| P256VERIFY (study config, K=1676) | before (study, amber-nolane) | 838 | 3,784,035.4 | 539.11 |
| P256VERIFY (study config, K=1676) | after (e468741 / review fixes) | 838 | 501,867.3 / 501,756.3 | 71.50 / 71.49 |
Before k200 raw: tx A 757,100,239 rows / 3,624,030 gas, tx B 378,671,682 / 2,922,130 → Δ 378,428,557 / 701,900 (study-config before = study run).
Per verify: 3.78M → 0.50M rows (−86.7%, 7.54×); the review fixes (N1: two `is_zero` checks dropped) shave 111 rows/verify. Adversarial 60M-gas block (rows/unit × 60M/7019): 32.35B → 4.29B rows
(3.0× the worst real block 1.43B; below the pure-opcode maximum ≈5.9B for KECCAK256). Reference: deferred ecrecover ≈10.5k rows in-tx
+ ≈230k batched; P-256 pays ≈2× that because Fake GLV binds R1 and R2 with two independent 2×128 Shamir MSMs (no endomorphism).

### Where the 502k rows per verify go
`jeth profile --rows` on the k200 synth block at e468741 (301 verifies: 200 + 100 + verify tx; 153,709,462 rows total; −111 rows/verify after the review fixes):
| symbol | rows | per verify |
|---|---:|---:|
| `jeth_core::p256::verify` (ecdsa_verify + both 2×128 Shamirs + field inlines, all inlined) | 137,917,297 | 458,197 |
| `memcmp` (P256Field `==` / `is_infinity` on `[u64; 4]` inside the Shamir loops) | 11,729,125 | 38,967 |
| `memset` | 543,956 | 1,807 |
| `fake_glv_scalar_mul` (advice loads) | 74,347 | 247 |
| revm STATICCALL/precompile dispatch, journal, gas (rest of the Δ) | — | ≈2,900 |
The Fake-GLV inline costs ≈2× the secp256k1 GLV recovery (≈230k) by construction: two independent 128-step Shamir MSMs (each step a
`double_and_add` = 1 div + 1 mul + 2 squares on the P-256 inline) plus two on-curve checks; there is no endomorphism to halve the work.
The 39k-row `memcmp` share is the P-256 sdk comparing limbs through `[u64; 4] == [u64; 4]` — the secp256k1 sdk on this jolt branch already
has the limb-compare / `MaybeUninit` treatment; porting it to `jolt-inlines-p256` is a ~8% jolt-side follow-up (not done here: no jolt edits).

### Ten-block set (jeth trace, final tree)
Inputs cloned to `/tmp/opcg-p256/blocks/<b>/input.bin` (trace writes its summary next to the input; `data/` is read-only). Guest = final tree, `p256-inline` on.

| block | rows after | rows baseline (prompt) | Δ | block_hash == data/ summary | keccak perms after |
|---|---:|---:|---:|---|---:|
| 25905781 | 603,187,849 | 603,187,863 | -14 | yes | 115,373 |
| 25905782 | 721,922,331 | 721,922,345 | -14 | yes | 124,117 |
| 25905783 | 333,212,703 | 333,212,717 | -14 | yes | 61,886 |
| 25905784 | 251,155,760 | 251,155,774 | -14 | yes | 51,424 |
| 25905785 | 629,550,097 | 629,550,111 | -14 | yes | 121,623 |
| 25905786 | 291,932,998 | 291,933,012 | -14 | yes | 59,024 |
| 25905787 | 401,722,255 | 401,722,269 | -14 | yes | 70,085 |
| 25905788 | 92,465,028 | 92,465,042 | -14 | yes | 19,238 |
| 25905789 | 677,090,260 | 677,090,274 | -14 | yes | 133,642 |
| 25905790 | 432,652,892 | 432,652,906 | -14 | yes | 90,051 |
| total | 4,434,892,173 | 4,434,892,313 | -140 | 10/10 | 781 = 115,373 (baseline 115,373) |

Gas-weighted 13.814672 c/g over 321,027,690 gas (baseline 13.814672): unchanged to 6 decimals. Every block is exactly −14 rows vs the prompt baseline
(`data/` summaries of 781/788 already carry the −14 value); no P256VERIFY call occurs in any of them (one call would move a block by ≈ −3.28M rows).

### Block 25905781 attribution
`jeth profile --rows --top 50` on 781, same tree, guest `p256-inline` OFF vs ON: both 603,187,849 rows; 48 top symbols identical
row-for-row (513,326,195 rows covered; only the jeth_core crate hash differs). `jeth opcodes` on 788 OFF vs ON: 92,465,028 rows both,
INLINE(custom-0) 52,157 execs / 54,554,050 rows both. No P256_* inline executes in these blocks (no P256VERIFY call); the lane's delta on the
ten-block set is exactly 0 rows. The −14 rows vs the prompt baseline is already present with the feature OFF (base tree state), not this lane.

### Forged / edge inputs (`edge_p256.py`: one block, one tx per vector; contract SSTOREs ok<<24 | 1<<16 | returndatasize<<8 | word and reverts if ≠ the python-side software expectation)
Block `edge-after`: 38 txs, native block_hash 0xcf9ebb710ba2489c5d7b877cf61365bacee8914bd39387724f7f47a6e18eff51 == trace block_hash (MATCH); 16,364,534 rows at e468741, 16,365,316 after the review fixes (re-run `edge-after2`, hash match again); every tx succeeded (software result == expected word in calldata).

Software accepts (14): `valid/study`, `valid/rip7212-1`, `valid/rip7212-2`, `valid/high-s`, `valid/msg>=n`, `valid/msg=2^256-1`, `valid/msg=n-1`, `valid/msg=0`, `valid/msg=n`, `valid/msg=0/high-s`, `valid/msg=0/Q=G`, `valid/msg=0/Q=2G`, `valid/msg=0/Q=3G`, `valid/msg=1/Q=G`.
Software rejects (24): `invalid/rip7212-wrong-msg`, `r=0`, `s=0`, `r=n`, `s=n`, `r=n-1`, `r=2^256-1`, `s=2^256-1`, `pk.x=p`, `pk.x>=p`, `pk.y>=p`, `pk-off-curve`, `pk=(0,0)`, `pk=-Q`, `pk=(1,1)`, `invalid/msg>=n`, `invalid/msg=0/wrong-s`, `invalid/msg=0/wrong-key`, `invalid/msg=0/Q=G-wrong-r`, `invalid/msg=0/Q=2G-wrong-r`, `invalid/msg=0/Q=3G-wrong-r`, `len159`, `len161`, `len0`.
(`valid/*` = signatures made with `p256_math.py`; `rip7212-*` = daimo reference vectors; `msg>=n` presents z + n; `msg=0`/`msg=n` are z = 0 with Q = G, 2G, 3G and a generic key; `len*` are handled before the hook.)

## Gates
1. Synth before/after: exact rows, same tree/harness/K — table above (k200 before 3,784,285.6 → after 502,089.6 rows/unit; study config after 501,867.3).
2. Ten blocks: 10/10 block_hash == `data/<b>/trace-summary.json`; 781 perms 115,373 == baseline; rows −14 per block (table above).
3. 781 attribution: see section above (`jeth opcodes` + `jeth profile --rows`). Review fixes changed the guest ELF (validate_block sha256 26e3964d… → 1a5b9fc3…, compute_advice 2d79617c… → c753cfae…): 781 re-traced at 603,187,849 rows, block_hash 0xf691da3f…b529, perms 115,373 — unchanged.
4. `cargo nextest run --cargo-quiet --release --workspace --features jeth-host/secp-inline`: 29 passed; `cargo nextest run --release -p jeth-core` (no features): 13 passed — the 5 p256 differential tests run in both. Pre-commit on every commit: fmt + clippy (`--all --all-targets -- -D warnings`) green; typos green on every changed file (`DISABLE_TYPOS=1` only for the pre-existing RESULTS.md / zeth_trie.rs hits).
5. Forged/edge block: native hash == trace hash, 38/38 vectors (table above); truncated 159 B, 161 B and empty inputs included.

## Decisions / kill list
- Verify synchronously inside the hook (no deferred batch like ecrecover): the precompile output is state-visible immediately and the
  Fake-GLV inline already carries its own soundness checks; a P-256 batch would need a new Pippenger lane for ~2× fewer rows/verify
  at most — out of budget.
- `z = 0` handled by instance rewriting rather than duplicating the inline's Shamir code or editing the jolt crate.
- Native build keeps revm's p256 path (override is riscv64-only) so `run-native` remains the independent reference; the unit tests
  exercise the inline path with the crate's host arithmetic (arkworks) against `verify_impl`.
- Did not rerun the K=1676 software "before" (≈1h of tracer time on a shared machine); K=200 reproduces the study to 0.04 c/g.
