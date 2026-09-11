# Per-opcode / per-precompile maximum cycles-per-gas on amber-nolane (2026-09-09)

Started 2026-09-09 17:55 ET. Tree amber-nolane @ 278c754, jolt-amber-nolane @ a0d7b74baa.
Binaries: /Volumes/Dev/cargo-target/jeth-amber-nolane/release/jeth (host, secp-inline), guest ELF
/Volumes/Dev/cargo-target/jeth-amber-nolane-guest-validate_block (built by the top-50 run).

## Plan
- No synthetic/EEST path exists in jeth (input = geth debug_executionWitness + block RLP → JEF via `repack`).
  EEST fixtures have no MPT witnesses; not usable directly.
- Harness: uncommitted `crates/host/src/bin/synth.rs` — builds a tiny full pre-state trie (sender EOA, loop
  contract(s), 4 system contracts), parent header, block with 1 tx calling the loop contract with iteration
  count in calldata; fixes header fields from native-validation errors until it passes; writes
  witness.json/block.rlp/meta.json → repack → input.bin. Then `jeth trace --skip-build`.
- Method: difference-of-counts. Same block shape with N and 2N loop iterations; Δrows/Δgas = c/g of the loop
  body. Body is a ~24 KB unrolled repeat of the op + minimal glue; glue measured separately (straight-line
  PUSH0 run fixes the stack-delta degree of freedom).
- Scratch: /tmp/opcg/<case>/{N1,N2}/...

## Progress
- 18:05 harness `crates/host/src/bin/synth.rs` (uncommitted; + `zeth-mpt.workspace = true` in crates/host/Cargo.toml) builds
  full-trie witness + block, header fixpoint via validation errors; `/tmp/opcg/evm.py` assembler + `run_block`
  (synth → repack → txprofile|trace). Smoke: 4.5 s per small block.
- 18:15 per-tx method: pertx markers via `jeth txprofile`; cases packed 10–12 per block, A(K units)+B(K/2 units)
  same code length → Δ/(K/2). Initial control design (unreachable body) showed offsets; replaced.
- 18:30 phase 1 (pure ops) done → /tmp/opcg/results-p1b.json. Phase 2 (calls/creates/cold-tiny/precompiles)
  → results-p2c.json (p2/p2b superseded: K budget bug — pre-expansion 2.2M gas + OOG; modexp Osaka GAS_DIVISOR=1).
- 18:40 phase 3 whole-block with deep pruned witnesses: synth `deep` fillers (15 siblings/level), prune.py walks
  touched paths (+siblings for deletions) → results-p3.json. Bug found/fixed: system-contract addresses 19 bytes.
- PUSH0 straight-line deep-stack anomaly (nonlinear ~25k fixed rows) — use PUSH0-POP pairs for glue instead.
- Precompile K=1 fix for MODEXP/1024-32-1024 (8.36M gas, 2 units OOG → precompile returns failure silently) → p2d.
- Profiles running: prof-extcodesize-big.log, prof-sload-deep.log, prof-calls.log (`jeth profile --rows`).
- 19:35 analysis (`/tmp/opcg/analyze.py` → analysis.json/csv) + report generator (`/tmp/opcg/report.py`) written; dry-run
  report lints clean (0 errors) with 155 configurations. Waiting on p2c block 07/08 (BLS G1MSM k128, G2, pairing, map, p256).
- Profiles: EXTCODESIZE cold 24KB code = 54% analyze_legacy (eager, 664k rows/code) + 42% keccak (520k); deep SLOAD = 78% keccak;
  warm CALL = 19% run_frame + 18% memcpy + 7% load_acc_and_calc_gas + ~9% journal.
- Headline so far: BLS_G1MSM k1 285 c/g loop, POINTEVAL 283, BLS_G1ADD 260, BLAKE2F r1000 232, BN254ADD 228, MODEXP 1024-e1 183,
  SHA256/8KB 171, BN254 pairing 150; EXTCODESIZE cold-big deep7 465 (input-cap bound ~1230/block); pure opcodes ≤ ~100 (KECCAK256 8KB 99,
  PREVRANDAO+POP 91); cold deep SLOAD 21, BALANCE 24; 21k-gas transfer 10.3.
- 19:30 DONE. All phases complete (236 configurations, all txs successful, precompile inputs verified in-block).
  Report: ~/.pika/web/reports/jeth-opcode-max-cycles-per-gas-2026-09.html (+ .csv); lint 0 errors; chart gate PASS (375/1440).
  Scripts + analysis copied to .journals/opcode-max-cg/ (evm.py assembler/driver, runner*.py, cases*.py, prune.py, analyze.py, report.py,
  vectors.json). Harness source stays uncommitted at crates/host/src/bin/synth.rs (+ host Cargo.toml dep line) — remove before any commit.
  Raw blocks/results: /tmp/opcg/cases/*, /tmp/opcg/results-*.json.
- Final top (c/g of tightest measured loop): P256VERIFY 539 · CALL/EXTCODESIZE cold 24KB code (deep7) 466 (input-cap bound ≈1,230/block)
  · BLS_G2MSM k1 439 · BLS_MAP_FP_TO_G1 296 · BLS_PAIRING k1 296 · BLS_G1MSM k1 285 · POINTEVAL 283 · BLS_G1ADD 260 · BLS_G2ADD 252
  · BN254ADD 228 · BLAKE2F 232 (→~253/round asymptote) · MODEXP 1024-e1-1024 183 · SHA256 8KB 171 · BN254 pairing 150.
  Pure opcodes: KECCAK256 8KB 99, PREVRANDAO+POP 91 (op alone 168), MULMOD 65 (op 141), DIV/MOD 256/255 50 (op 115), CALL warm 47, TSTORE new 52.
  State (whole-block, deep): SLOAD cold 21, BALANCE cold 24, SSTORE modify 18, SSTORE new 4.3, 21k transfer 10.3 (warm 4.9).
  Adversarial 60M block: P256VERIFY-filled 32.3B rows (22.6× worst real 1.43B); BLS G2MSM 26.3B; pure-opcode max ~5.9B (KECCAK256).
