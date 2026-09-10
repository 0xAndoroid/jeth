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

## Current wave: A (spawned 2026-09-09 ~20:00)
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
