# Lane PROOF-GATE — real Jolt proofs through the three custom inline families

Jolt worktree `/Volumes/Dev/worktrees/jolt/jolt-inlines-b` (branch `jolt-inlines-b`, base 3158917254, remote `private`);
jeth worktree `/Volumes/Dev/worktrees/jeth/inlines-b` @ 89ee6b3 read-only (crates `jeth-inlines-{bn254,bls12-381,blake2f}`,
vendored `crates/vendor/ark-ff`). Machine: Apple M4, 16 GiB, macOS; jolt CLI = the worktree's `target/release/jolt` (315891725).

## Verdict

Every inline family proves and verifies with the legacy prover behind `jolt-sdk` (`#[jolt::provable]`, Dory, RV64IMAC_JOLT_ALL_INLINES):

| op | guest function | cycles (hooks) | cycles (compiled) | padded T | prove | verify | peak RSS | result |
|---|---|---:|---:|---:|---:|---:|---:|---|
| bn254 pairing e(P, Q), k = 1 (MULQ / SOPQ2 / FP2MULQ) | `bn254_pairing(0xc0ffee, 0xbeef)` | 8,621,982 | 10,495,866 (−17.9 %) | 2^24 | 173.7 s | 0.60 s | 7.77 GiB (time -l 8.34 GB) | **PASS** |
| bn254 e(P, Q)·e(−P, Q) == 1, k = 2 multi-pairing | `bn254_pairing_check(0xc0ffee, 0xbeef)` | 11,548,881 | 15,028,695 (−23.2 %) | 2^24 | 201.2 s | 0.26 s | 4.71 GiB (time -l 5.05 GB) | **PASS** |
| BLS12-381 G2 add Q1 + Q2 and 2-term a·Q1 + b·Q2 (MULP / FP2MUL) | `bls12_381_g2(0x1f3a7, 0x29c51)` | 2,931,348 | — (3,702,508 vs 3,766,911 on the census inputs, −1.7 %) | 2^22 | 69.7 s | 0.27 s | 3.07 GiB (time -l 3.30 GB) | **PASS** |
| BLAKE2F r = 12 (EIP-152 vector 5 → FULL10 + PREFIX_2) | `blake2f(12, h, m, [3, 0], true)` | 6,892 | n/a | 2^13 | 1.0 s | 0.08 s | 0.23 GiB | **PASS** (output == EIP-152 known answer) |
| BLAKE2F r = 13 (FULL10 + PREFIX_3) | `blake2f(13, …)` | 6,972 | n/a | 2^13 | 1.1 s | 0.09 s | | **PASS** |
| BLAKE2F r = 20 (FULL10 × 2, t1 ≠ 0, f = false) | `blake2f(20, dense m, [0x1122334455667788, 1], false)` | 9,066 | n/a | 2^14 | 1.0 s | 0.10 s | | **PASS** |

PASS = `jolt_verifier::verify(...)` accepted the proof AND the proven output equals the reference (native ark-bn254 / ark-bls12-381
pairing and G2 arithmetic in the host, the group law `Q1 + Q2 == (a+b)·G`, `a·Q1 + b·Q2 == (a²+b²)·G`, an RFC 7693 §3.2 compression
written independently in the host for BLAKE2F, and the EIP-152 vector-5 known answer for the 12-round call) with `program_io.panic == false`.
Timings are uncontended single-process runs (`RUST_LOG` default, release host without LTO); the final sequential re-run with the committed
binary is in §7. No prover, verifier or tracer failure on any inline sequence — no lane is blocked.

## 1. What the example is

`examples/jeth-inlines-proof-gate/` on `jolt-inlines-b` — two standalone workspaces, neither a member of the jolt workspace:

* `guest/` (`jeth-inlines-proof-gate-guest`, own `[workspace]`): `#[jolt::provable]` functions `bn254_pairing`, `bn254_pairing_check`,
  `bls12_381_g2`, `blake2f`, plus three multiplication chains for the per-op cost (`bls12_381_fq2_mul_chain`, `bls12_381_fq_mul_chain`,
  `bn254_fq2_mul_chain`). Depends on registry `ark-bn254 / ark-bls12-381 / ark-ec / ark-ff 0.5.0` and `jeth-inlines-blake2f` (absolute path);
  `[patch.crates-io] ark-ff = { path = ".../jeth/inlines-b/crates/vendor/ark-ff" }`; feature `inline-hooks` (default) =
  `ark-ff/jolt-bn254-inline + ark-ff/jolt-bls12-381-inline`. `cargo tree --target riscv64imac-unknown-none-elf -i ark-ff`: the vendored
  ark-ff is the only ark-ff in the guest graph (ark-bls12-381, ark-bn254, ark-ec, ark-poly, the guest), with features
  `[jolt-bls12-381-inline, jolt-bn254-inline]` and both jeth inline crates as its dependencies. No a16z-fork ark-* in the riscv graph.
* `.` (`jeth-inlines-proof-gate`, own `[workspace]` with `exclude = ["guest"]`): depends on `jolt-sdk` (host), the guest with
  `default-features = false` (so the fork ark-ff never sees the hook feature names), the three jeth inline crates with `host` (registered via
  `extern crate … as _;`), and replicates the jolt root `[patch.crates-io]` (ark-bn254/ff/ec/serialize → a16z fork) plus `ark-bls12-381` from
  the same fork so the prover stack resolves exactly as in the main tree. The jolt workspace itself is untouched (no member added, no patch
  changed, root `Cargo.lock` unchanged).
* Host flow per gate: `set_current_dir(guest/)` (so `jolt build -p …` from `compile_*` runs in the guest workspace and its patch), `JOLT_PATH`
  defaults to the worktree CLI, `compile_*` → `execute` (cycles) → `preprocess_shared/prover/verifier_*` → `build_prover_*` → prove →
  `build_verifier_*` → verify → compare with the reference → table with cycles, cycles without hooks, prove/verify seconds, PASS/FAIL,
  `getrusage` peak RSS. Guest targets under `examples/jeth-inlines-proof-gate/target/guest/…` (never `/tmp`, no `CARGO_TARGET_DIR`).
  Modes: `blake2f | bls | bn254 | bn254-check` (proofs), `census` (rows with/without hooks + per-inline executions from the trace),
  `bench` (rows per chained field multiplication), `hot` (rows per function from a symbol-preserving build).

## 2. Evidence the proven traces contain the inline sequences

Static: custom-1 sites in the hooked ELFs (`opcode_census.py`, here in the scratch dir): bn254 guest 31 × MULQ, 1 × SOPQ2, 1 × FP2MULQ
(5 in the check variant); BLS guest 6 × MULP, 2 × SOPP2, 1 × FP2MUL; BLAKE2F guest all ten round ops (funct7 0x02 funct3 0–7, 0x03 funct3
0–1). The `--no-default-features` ELFs have zero 0x2B sites.

Dynamic (`census`, inputs 0xc0ffee / 0xbeef; rows attributed by the expanded rows' source address, executions = rows with
`virtual_sequence_remaining == 0`):

| function | executions × inline (rows each = golden) | inline rows / total |
|---|---|---:|
| `bn254_pairing` | 1,870 × MULQ (273), 15 × SOPQ2 (415), 5,261 × FP2MULQ (797) | 4,709,752 / 8,621,982 (55 %) |
| `bn254_pairing_check` | 3,338 × MULQ, 15 × SOPQ2, 6,905 × FP2MULQ | 6,420,784 / 11,548,881 (56 %) |
| `bls12_381_g2` | 962 × MULP (647), 692 × FP2MUL (1,875); SOPP2 never executes (the fused op covers every Fq2 product) | 1,919,914 / 3,702,508 (52 %) |

Rows per inline execution equal the crates' golden numbers (273 / 415 / 797, 647 / 1,875), so the tracer expanded the registered
sequences and the prover proved them (the whole trace is what Dory commits to and the sumchecks cover).

## 3. Finding: the BLS12-381 FP2MUL hook saves nothing per call (guard cost)

`bench` (1,000 chained multiplications, rows(1000) − rows(0)):

| chain | rows/op with hooks | rows/op compiled | inline share |
|---|---:|---:|---|
| `bn254_fq2_mul_chain` (Fq2 × Fq2) | **819.5** | 1,151.1 | FP2MULQ 797 + 2 conditional subtractions + loop (−28.8 %) |
| `bls12_381_fq_mul_chain` (Fq × Fq) | 655.0 | 671.6 | MULP 647 (−2.5 %) |
| `bls12_381_fq2_mul_chain` (Fq2 × Fq2) | **2,631.1** | 2,631.8 | FP2MUL 1,875 + **627 rows `memcmp` + 84 rows `memcpy`** per call (±0 %) |

`hot` (symbol-preserving build, rows per function): the BLS Fq2 chain spends 627.0 rows/op in `memcmp` and 84.1 in
`compiler_builtins::mem::memcpy`; the bn254 chain has no such rows. Cause: `jolt_bls12_381::is_fq2::<P>()` (vendored
`ark-ff/src/jolt_bls12_381.rs`) is evaluated at run time — `P::BaseField::characteristic() == &MODULUS[..]` lowers to a 48-byte `memcmp`
call (≈13 rows/byte in the guest's byte-wise memcmp) and `P::NONRESIDUE == -P::BaseField::ONE` materializes a negation and copies — whereas the
bn254 `is_fq2` folds to a constant (limb reads through a const-friendly cast). The guard costs ≈ 710 rows per Fq2 multiplication, i.e. the whole
FP2MUL gain (compiled Fq2 mul ≈ 2,632 rows vs inline 1,875). Consequence in this guest: BLS G2 arithmetic is −1.7 % with the hooks
(3,702,508 vs 3,766,911 rows), essentially the MULP saving alone; the lane's −13.9 % G2MSM / −13 % pairing numbers should be re-checked
against a hot-function profile of the jeth guest. Fix (jeth side, not made here — read-only): make the BLS guard const-evaluable like the
bn254 one (compare `P::MODULUS`/`P::NONRESIDUE` limbs through a `const fn` on the config constants instead of `characteristic()` slice
equality and a runtime negation), or gate on an associated const of `MontBackend` as `JOLT_BLS12_381_FQ` already does for `mul_assign`.
Same LTO regime either way (measured with `lto = "fat"` and jeth's `lto = "thin"`, `codegen-units = 1`: −17.8 / −23.1 / −1.7 %).

## 4. Profile / registration path

* `crates/jolt-riscv/src/profile.rs`: `InlineExtension::External` is in `RV64IMAC_JOLT_ALL_INLINES.inline_extensions`; the legacy
  `Program::new` uses `instruction_profile: RV64IMAC_JOLT_ALL_INLINES` (`crates/jolt-prover-legacy/src/host/program.rs`), and the tracer's
  `TracerInlineExpansionProvider::expand_inline` gates on `profile.supports_inline(registration.extension)` — accepted. `INLINE::inline_sequence`
  (runtime tracing) also expands with `RV64IMAC_JOLT_ALL_INLINES`.
* `profile.fingerprint()` is only consumed by the `field-inline` bytecode metadata (feature-gated); no other prover/verifier check of the
  profile or the registered inline set exists (`supports_inline`, `inline_extensions`, `fingerprint` grep: tracer/inline.rs, jolt-tracer-x86
  cache key, jolt-program field_inline). The verifier works from the expanded bytecode in the shared preprocessing and needs no registry.
* `cargo nextest run -p jolt-inlines-fixtures --features host`: 3/3 pass (`linked_inline_registration_keys_are_unique`,
  `registered_inline_expansions_match_golden_fixture`, `linked_inline_registration_inventory_matches_fixture`). The fixture binary links only
  the eight upstream inline crates, so the External registrations are not enumerated and the golden file is untouched; linking the jeth
  crates into that test would require regenerating `fixtures/registered_inline_expand_parity_hashes.jsonl` (new `External` entries), which was
  not done.

## 5. Sizing and limits

* `bn254_pairing` (one Miller loop + final exponentiation, tiny scalar multiplications for P and Q) is 8.62 M rows → padded 2^24; the k = 2
  check is 11.55 M rows → 2^24. Both proved on 16 GiB (peak RSS 7.8 GiB / 4.7 GiB). Attributes: `stack_size = 262144`,
  `heap_size = 4194304`, `max_trace_length = 16777216`.
* BLS G2 gate 2.93 M rows → 2^22 (`max_trace_length = 4194304`); BLAKE2F ≤ 9.1 k rows.
* Guest inputs are postcard-encoded; outputs are fixed arrays of canonical limbs (`[[u64; 4]; 12]` Fq12, `[[u64; 6]; 4]` × 2 G2 affine,
  `[u64; 8]` h) — no ark-serialize in the guest.

## 6. Reproduce

```sh
cd /Volumes/Dev/worktrees/jolt/jolt-inlines-b && cargo build --release -p jolt   # CLI, if target/release/jolt is missing
cd examples/jeth-inlines-proof-gate
cargo build --release                      # host + native guest (fork arkworks); ~10 min cold
./target/release/jeth-inlines-proof-gate blake2f       # 3 proofs, ~15 s
./target/release/jeth-inlines-proof-gate bls           # 2^22, ~75 s
./target/release/jeth-inlines-proof-gate bn254         # 2^24, ~3 min, ~8 GiB
./target/release/jeth-inlines-proof-gate bn254-check   # 2^24, ~3.5 min
./target/release/jeth-inlines-proof-gate census        # rows with/without hooks + inline executions (no proof)
./target/release/jeth-inlines-proof-gate bench         # rows per chained field multiplication
./target/release/jeth-inlines-proof-gate hot           # rows per function (symbolized build)
cargo nextest run -p jolt-inlines-fixtures --features host --cargo-quiet   # from the jolt root
```
Each gate builds the guest through the `jolt` CLI (`JOLT_PATH` overrides the worktree binary) into
`examples/jeth-inlines-proof-gate/target/guest/`. Logs of this run: `/Volumes/Dev/jeth-scratch/proof-gate/logs/`.

## 7. Final sequential re-run (committed binary, gates in separate processes, machine otherwise idle)

Correctness re-confirmed with the committed binary (c0e9fb845f), one process per gate, `/usr/bin/time -l`. The machine was NOT idle
this time (load average 33–44: other agents' nightly rustc builds), so these wall times are 2–5× the uncontended ones above; RSS is also
lower under memory pressure. PASS/FAIL, cycles and outputs are identical.

| gate | cycles | w/o hooks | prove s | verify s | peak RSS (getrusage / time -l) | result |
|---|---:|---:|---:|---:|---|---|
| blake2f r12 (EIP-152 vector 5; FULL10 + PREFIX_2) | 6,892 | n/a | 1.37 | 0.160 | 0.19 GiB / 200 MB | PASS |
| blake2f r13 (FULL10 + PREFIX_3) | 6,972 | n/a | 2.09 | 0.145 | | PASS |
| blake2f r20 (FULL10 × 2, 128-bit counter, f = false) | 9,066 | n/a | 2.65 | 0.201 | | PASS |
| bls12_381_g2(0x1f3a7, 0x29c51) | 2,931,348 | 2,985,054 (−1.8 %) | 340.60 | 1.528 | 1.77 GiB / 1.90 GB | PASS |
| bn254_pairing(0xc0ffee, 0xbeef) | 8,621,982 | 10,495,866 (−17.9 %) | 319.76 | 0.568 | 3.27 GiB / 3.51 GB | PASS |
| bn254_pairing_check(0xc0ffee, 0xbeef) | 11,548,881 | 15,028,695 (−23.2 %) | 544.87 | 0.463 | 2.54 GiB / 2.73 GB | PASS |

Log: `/Volumes/Dev/jeth-scratch/proof-gate/logs/run-final.log` (earlier uncontended runs: `run-{blake2f,bls,bn254,bn254-check}.log`;
census / bench / hot: `run-census2.log`, `run-bench.log`, `run-hot.log`; fixtures: `fixtures-nextest.log`).

## 8. Files / commit

`jolt-inlines-b`: c0e9fb845f `feat(examples): proof gate for externally registered inlines` (+ 4349e92dbb `chore(examples): ignore the
guest build directory of the proof gate`), pushed to `private` (0xAndoroid/jolt-private); origin untouched. Pre-commit (typos, style
invariants, fmt, clippy) green; `cargo clippy --release -- -D warnings` green in the example workspace.

`examples/jeth-inlines-proof-gate/{Cargo.toml, Cargo.lock, .gitignore, src/main.rs, guest/{Cargo.toml, Cargo.lock, src/lib.rs, src/main.rs}}`.
Nothing under `/Volumes/Dev/worktrees/jeth` was modified; the jolt root `Cargo.toml`/`Cargo.lock` are unchanged.

## 9. Open items

* jeth: const-evaluable BLS `is_fq2` guard (§3), then re-measure the BLS lane's per-call gains and the G2MSM / pairing / POINTEVAL deltas.
* The fixture golden file will need the External entries if the jeth crates are ever linked into `jolt-inlines-fixtures`.
* The example hard-codes the absolute jeth paths (as jeth hard-codes the jolt worktree); it is private-branch material, not upstream-ready.
