# jeth inlines campaign (started 2026-09-09 19:40 ET)

Orchestrator task b974c600 · card 316 · working worktree /Volumes/Dev/worktrees/jeth/inlines-a (branch inlines-a on amber-nolane @ 278c754) · jolt pin /Volumes/Dev/worktrees/jolt/jolt-amber-nolane @ a0d7b74baa (jolt-private).
Baseline (no-lane, 10-block set): 4,434,892,313 rows, 13.814672 c/g; 781 = 603,187,863 rows / 115,373 perms; records = data/<block>/trace-summary.json.

## Playbook (verbatim from the operator brief) — checklist
- [x] Read first: RESULTS.md, .journals/opcode-max-cg-2026-09.md + .journals/opcode-max-cg/, the max-c/g report + csv, the optimizations catalog, addptq-inline-design*.md + bn254-fq-inline-design.md, the Jolt book inline chapter (book/src/how/optimizations/inlines.md) — done.
- [x] Commit synth.rs as a dev tool on the branch (f3fff9c; + JETH_GUEST_TARGET_DIR override a60d0ee; lock 60283c9).
- [ ] PHASE A — wire existing inlines (one lane per inline, or grouped if trivial): p256 → P256VERIFY (539 c/g today); sha2 → SHA256 precompile (171) and any sha256 in the guest; blake2 → BLAKE2F (~250/round); bigint → MULMOD/ADDMOD/EXP/MODEXP and the u256 arithmetic paths in the interpreter (65–183 c/g) — check what the bigint inline actually offers (mul/mulmod widths) and use it where it fits.
- [ ] Each lane: gate = synth harness configs for its ops (rows before/after, exact) + 10-block set trace (hashes = records, perms exact) + block-781 attribution; the precompile outputs must be verified against the software path on the harness inputs (forged/edge inputs incl. invalid points, identity, zero exponents). Commit per lane on a branch inlines-a stacked on amber-nolane.
- [ ] PHASE B — custom inlines for the remaining top offenders, ranked by block-average impact (bn254 pairing/ecmul = 8% of rows set-wide, BLS12-381 in 16/50 blocks) and adversarial c/g: bn254 Fq mul/add/sub + Fp2 (revive the amber design; ark_ff hooks the same way secp does), BLS12-381 Fp/Fp2 field ops (G1/G2 add, MSM, pairing all sit on them), KZG point-eval (shares BLS Fp), modexp big limbs if bigint didn't cover it.
- [ ] Each custom inline: spec (op, register/memory contract, cycle budget), soundness argument (the inline's constraint = the op's semantics on all inputs, edge cases), tests vs software reference on random + adversarial inputs, then integration and the same gates as Phase A. Branch inlines-b stacked on inlines-a.
- [ ] Deliverables per phase: PRs against amber-nolane (stacked), non-draft, with the rows/c/g table before/after for the affected ops and the 10-block c/g.
- [ ] Final: HTML report (html-report-design skill, tags jolt, jeth, benchmark) ~/.pika/web/reports/jeth-inlines-campaign-2026-09.html — per-op c/g before/after, adversarial-block bound before/after, 10-block c/g, what each inline cost (rows/call, unsafe, soundness review status).
- [ ] Reviews: every inline → fresh fable-high reviewer, presumptive-blocker bar + soundness focus, fix-then-fresh-review loop.
- [ ] Reporting: reply parent only at (1) Phase A PR open, (2) Phase B PR open, (3) blocker/decision, (4) done with report link. Track spend; flag > $400.

## Rules baked into every child prompt
worktrees only (from ~/dev/jeth; never touch ~/dev/jeth main or amber-nolane's checkout); per-lane CARGO_TARGET_DIR + JETH_GUEST_TARGET_DIR; Conventional Commits; complexity budget; generic wording; prompt files (no backticks/$(...) in --prompt); never git merge | tail; vault read-only; never push to a16z/jolt; jolt-side edits only on jolt-private branches; never raise MAX_SUFFIXES; no new lookup tables.

## Findings that shape the plan
- Inline registration: register_inlines! needs an InlineExtension variant (closed enum in crates/jolt-riscv/src/profile.rs) and tracer checks profile.supports_inline. Custom jeth inlines (opcode 0x2B) therefore need one jolt-private variant (e.g. InlineExtension::External) — Phase B decision, report as (3) if it matters.
- Fixture rows: SHA256 1900 / SHA256INIT 1864; BLAKE2 1067 (12 rounds fixed, 64-bit counter, final flag); BIGINT256_MUL 141 (256x256→512, no reduction); P256 MULQ 264 / SQUAREQ 245 / DIVQ 272 / MULR 252 / SQUARER 233 / DIVR 260 / FAKE_GLV_ADV 29.
- BLAKE2F precompile: inline covers rounds==12 && t[1]==0 only; other round counts stay software (Phase B candidate: per-round inline family).
- revm Crypto trait (revm-precompile 34) hooks: sha256, ripemd160, bn254_g1_add/mul/pairing_check, secp256k1_ecrecover, modexp, blake2_compress, secp256r1_verify_signature, verify_kzg_proof, bls12_381_*. jeth overrides in crates/core/src/crypto.rs (JoltCrypto).

## Archived wave A (2026-09-09 20:00–22:10) — PR #2 https://github.com/0xAndoroid/jeth/pull/2 (inlines-a @ 85f4fda, base amber-nolane); set 13.814672 → 13.763942; spend ≈ $95
| lane | branch | task | status |
|---|---|---|---|
| A-p256 | inlines-a-p256 @ e85b5bf | a736dfb4 done (539 → 71.5 c/g, 3.78M → 0.50M rows/verify; set delta 0) | review eeb8f17e APPROVE (3 should-fix: pin Q=-G branch, randomized differential test, cfg(test) gating; 4 nits) → fixed 91ea0ba, re-review 7d670159 APPROVE (nit pinned ae4ffb9) → merged 0cff8b9 |
| A-hash (sha2 + blake2) | inlines-a-hash @ 72b17a4 | ff624803 done (SHA256/8K 170.6 → 78.6 c/g; BLAKE2F r12 75.2 → 59.7; set −407,212 rows → 13.813403) | review 1d3edc85 APPROVE (3 nits; docstring nit applied 1d49614) → merged ff into inlines-a |
| A-bigint | inlines-a-bigint @ 45c1dc0 | fd91aeb3 done (MULMOD product via inline −19%/op; MODEXP 9..32B odd moduli ladder −57% at 32B; set −15,856,781 rows −0.36%) | review 2283cbc9 (fable-high) |

## Kill list / parked
- (none yet)

## Spend
- orchestrator so far: ~$0.5

## Index
- prompts: /tmp/inlines-prompts/
- baseline trace log (env override sanity): /tmp/inlines-a-baseline-781.log
- 20:40 A-p256 reported: 10-block rows are −14/block vs my prompt baseline on the same tree with the feature OFF → the exact baseline = data/<block>/trace-summary.json rows (781 = 603,187,849), not the RESULTS ledger. Use those for the PR table.
- Follow-up parked (jolt-side): P-256 sdk [u64;4] equality compiles to memcmp (39k rows/verify, 8%) — port the secp limb-compare/MaybeUninit treatment to jolt-inlines-p256 on jolt-private (Phase B candidate, cheap).
- 21:25 merge lesson: my union conflict resolution of crypto.rs put the p256 hook outside the impl — native tests are cfg'd out so they passed; the GUEST build failed. Fixed 57eb4b6. Rule: after every merge into inlines-a, build the guest (jeth trace on 781) before anything else.
- A-bigint incident: `jeth trace` writes trace-summary.json beside its input; the lane traced through the data symlink and overwrote amber-nolane/data/{781,788}/trace-summary.json, then restored them (verified: 603,187,863 / 92,465,042 + hashes). Lanes must copy inputs to /tmp, never trace through the symlink.
- 21:35 merged tree (57eb4b6 = hash + p256) 781: 603,149,073 rows, hash ok, perms 115,373 — equals the hash lane's number (p256 has no calls in the set) → lanes compose. My own trace also rewrote amber-nolane/data/25905781/trace-summary.json (jeth writes it beside the input) — restored to the record; inputs now copied to /tmp/inlines-a-data/<block>/input.bin for all future runs.
- review 2283cbc9 (bigint) APPROVE; S1–S3 + nits + rebase onto inlines-a delegated back to fd91aeb3.

## Current wave: B (planning 22:10)
- Targets (ranked): bn254 Fq MULQ/SOPQ2 (+Fp2) — amber design, needs custom inline registration; BLS12-381 Fp (6-limb) ops; KZG point-eval shares BLS Fp; BLAKE2F per-round inline family (r ≠ 12 adversarial bound 13.9B rows); MODEXP big limbs (1024-byte case 6.0M rows/call, 183 c/g).
- Registration decision: custom inlines need an InlineExtension variant → jolt-private branch off jolt-amber-nolane with one added variant + profile entry; the inline crates themselves live in jeth (crates/inlines/...), opcode 0x2B.

## PARKED for daemon restart (2026-09-09 22:10) — resume here
State: Phase A complete and reported (PR #2, inlines-a @ 85f4fda pushed; cards 318/319/320 human_review, program card 316). No child tasks running. Spend ≈ $95.
Phase B prep in flight:
- jolt-private worktree /Volumes/Dev/worktrees/jolt/jolt-inlines-b (branch jolt-inlines-b off jolt-amber-nolane @ a0d7b74baa). crates/jolt-riscv/src/profile.rs has the InlineExtension::External variant (enum + RV64IMAC_JOLT_ALL_INLINES + code 8) STAGED, NOT committed — the nextest/commit chain was interrupted. Next: CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jolt-inlines-b cargo nextest run -p jolt-riscv; cargo fmt --check; commit "feat(jolt-riscv): InlineExtension::External for inlines registered by downstream hosts"; push to the private remote (check git remote -v: jolt-private = git@github.com:0xAndoroid/jolt-private.git); build the CLI to /Volumes/Dev/cargo-target/jolt-cli-inlines-b (cargo build --release -p jolt) — or reuse the amber-nolane CLI (the enum change does not affect guest builds).
- Then: jeth branch inlines-b from inlines-a: sed all /Volumes/Dev/worktrees/jolt/jolt-amber-nolane paths → /Volumes/Dev/worktrees/jolt/jolt-inlines-b in Cargo.toml, crates/core/Cargo.toml, crates/guest/Cargo.toml (+ locks), trace.rs DEFAULT_JOLT_CLI; verify 781 = 601,992,101 rows / hash 0xf691… / perms 115,373 on the repin.
- Phase B lanes to spawn (fable-max each, own worktrees inlines-b-<lane>, CARGO_TARGET_DIR jeth-inlines-b-<lane>, inputs from /tmp/inlines-a-data): B-bn254 (Fq MULQ/SOPQ2 + FP2 custom inline crate in jeth crates/inlines/, opcode 0x2B, extension External, vendored ark-ff hook; pre-gate rows/call on 781: GO iff mul_assign ≥ 305 and sop2 ≥ 515, per .journals/bn254-fq-inline-design.md), B-bls (BLS12-381 Fp 6-limb MULP/SOPP2 + Fp2, same mechanism, ark-bls12-381 hook; adversarial c/g 250–440), B-blake2f (per-round inline family: ROUNDS10 full sigma cycle + single rounds r0..r9, v-state in memory; target r1000 232 → ~90 c/g). Killed: modexp big limbs (inline = 8.8 rows/partial product = compiled; no win), Fr variants, squaring. Optional small lane: port secp limb-compare/MaybeUninit to jolt-inlines-p256 on jolt-inlines-b (39k rows/verify).
- Each B lane: spec + soundness argument + InlineSpec-style tests vs software reference (random + adversarial) + row_count fixture + synth gates + 10-block gates; fresh fable-high review; then inlines-b PR against inlines-a.

## Resumed after restart (22:51) — Phase B wave spawned
- jolt-inlines-b @ 3158917254 pushed to jolt-private (InlineExtension::External); jeth inlines-b @ 6557a40 repinned (paths + DEFAULT_JOLT_CLI); CLI building to /Volumes/Dev/cargo-target/jolt-cli-inlines-b; 781 verification trace on the repin in flight (/tmp/inlines-b-781.log).
- /tmp was wiped by the restart (prompts, input copies, lane scratch gone). Persistent copies now: block inputs /Volumes/Dev/jeth-inputs/<block>/input.bin; prompts in .journals/prompts/ (committed).
| lane | branch | task | status |
|---|---|---|---|
| B-bn254 | inlines-b-bn254 @ 419da11 | d65966f1 done (MULQ 273 / SOPQ2 415 / FP2MULQ 797 rows; pairing −20%, ecmul −5.6%; set −35.3M rows → 13.653998) | review 60ff56ad APPROVE (4 should-fix: direct seq-vs-ark tests, assert! not debug_assert, edge ≥q fix, PROVING GATE observation) → fixes + rebase resumed on d65966f1 |
| B-bls | inlines-b-bls @ 00fe5f6 | 546e8ca6 done (MULP 647 / SOPP2 957 / FP2MUL 1,875 rows; G2MSM −13.9%, pairing −13.0%, POINTEVAL −12.5%; Aztec block −1.34%; set Δ0) | review 97ab05ee APPROVE (1 should-fix: layout guard into the const; nits) → fix + wait-for-bn254 + rebase resumed on 546e8ca6 |
| B-blake2f | inlines-b-blake2f @ 3fb9b6a | 675c6d21 done (FULL10 880 rows, PREFIX_r 80r+80; r1000 232 → 84.9 c/g; set Δ0) | review 3b0e30a1 APPROVE (F1 const-assert R∈1..=10 + nits applied a7532a9) → rebased + ff-merged into inlines-b @ a7532a9; 781 verification /Volumes/Dev/jeth-scratch/inlines-b-merged-781.log |
- Killed before spawning: MODEXP big limbs (BIGINT256_MUL = 8.8 rows/partial product = compiled; no lever), Fr variants, squaring inlines. Parked: jolt-inlines-p256 limb-compare port (39k rows/verify) — jolt-side, after the B lanes (shared path dep must not move under them).
- 23:27 INCIDENT: every /Volumes/Dev/cargo-target/jeth-* and jolt-cli-* dir deleted externally (~317 GiB freed; 40+ → 19 entries; not by any lane). Jolt CLI gone → guest builds blocked; rebuilding jolt-cli-inlines-b (started 23:30, /tmp/jolt-cli-inlines-b-build.log). All three lanes messaged: poll for the CLI, rebuild host, keep inputs/scratch in /Volumes/Dev/jeth-scratch/<lane>/ (never under cargo-target). Cost: ~15–25 min per lane. Inputs at /Volumes/Dev/jeth-inputs survived.
- B-bls pre-gate (before the wipe): G2MSM k1 — sop2 1,183 rows/call × 4,116 + mul 714 × 3,372 = 73% of 9.93M rows/op; inline SOPP2 918 / MULP 620 → −14.1% per op (−18% est. with fused Fp2) → GO.
- 23:30 RULE (user, 23:12): NO CARGO_TARGET_DIR anywhere — each repo/worktree builds into its own target/. Applied: jolt CLI now builds in /Volumes/Dev/worktrees/jolt/jolt-inlines-b/target/release/jolt (restarted 23:31); trace.rs defaults → <repo>/target/guest and that CLI path; prompts/common-b.md rewritten; all three lanes steered by message (JETH_GUEST_TARGET_DIR=LANE_WT/target/guest until they rebase; scratch + inputs in /Volumes/Dev/jeth-scratch/<lane>/). Lanes rebuild from scratch (~15–25 min each); bls must regenerate its opcg case inputs.
- 00:06 daemon restart #247; lanes stopped 23:56, resumed 00:07 with the in-repo build environment (CLI ready at jolt-inlines-b/target/release/jolt). Lane heads at resume: bn254 e11b444 (vendored ark-ff commit, 12 dirty) · bls dbac579 (3 dirty) · blake2f 6557a40 (10 dirty, nothing committed yet).
- 00:40 repo .cargo/config.toml (target-dir → wiped cargo-target path) removed on inlines-b (3c8658c); lanes pick it up on rebase. B-blake2f note: FULL20 op would give another −4% on r1000 — parked.
- 01:43 inlines-b @ a7532a9 (blake2f merged) 781 = 601,992,101 rows, hash ok → merge clean. bn254 pre-gate: mul 310 / sop2 507 / square 257 rows/call → fused-FP2 package (rule); square left compiled.
- 01:55 both field lanes touch the same 4 vendored ark-ff files (montgomery_backend.rs if-chain, quadratic_extension.rs arm, lib.rs mod line, Cargo.toml feature) — merge order after reviews: bn254 first (ff), then bls rebased onto it (lane agent resolves; verify 781 + Aztec block on the union). Parked follow-ups: BLS FP2SQR fused (≈ −6% more on G2/pairing), blake2f FULL20 (−4% on r1000), jolt-inlines-p256 limb compares.
- 02:00 reviewer observation (bn254 F4, repo-wide): all gates are execute-only (tracer rows + hashes); no proof has ever been generated with the custom sequences (LUI/VirtualMULI with top-bit-set 64-bit immediates — precedent in p256, low risk). Decision item for the operator at Phase B PR: prove one small synth block bearing BN254 pairing + BLS ops + BLAKE2F before merging inlines-b into amber-nolane. jeth has no prove path today.
