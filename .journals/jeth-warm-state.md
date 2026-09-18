# jeth-warm-state — repeated state access within a block (2026-09-18)

Owner question: most blocks touch the same contract state repeatedly across txs; does jeth
reach warm state cheaply (no repeated cold state-proof cost), and if not, can it?

Orchestrator ed8b8e5c. Branch `jeth-warm-state`, PR #7 (owner reviews; not merged by us).
Jolt CLI rebuilt from /Volumes/Dev/worktrees/jolt/jolt-amber-nolane @ a0d7b74baa into
/Volumes/Dev/cargo-target/jolt-cli-amber-nolane (target dir had been cleaned).

## Steps (playbook)
1. plan 1/1 — done (be5e4ede): `jeth-warm-state-plan.md` — state path map, native census (`jeth touches`),
   lever ranking. Answer: already deduplicated (DB misses == distinct keys); repeat work = revm bookkeeping.
2. implement a/2 — done (53c77bce): `jeth-warm-state-measure.md` — 4-block bucket attribution
   (witness verify 28.5% · warm-path 8.0% · EVM 23.5% · precompiles 12.3% · post-root 21.1% · other 6.3%);
   reveal 18.0% / first touch 12.4% / repeat 6.0%.
3. implement b/2 — done (b94c6cf2): `jeth-warm-state-implement.md` — A word-gather key hashing (763073a),
   B witness-bounded presizes (8696d18), C hashbrown Group::load gather (2e4c87a): 14.332 → 14.153 c/g (−1.25%).
4. review 1/3 — done (d12d2465): 3 LOW, fixed f8c5e08 + 75370e9. review 2/3 — done (54c58374): 1 LOW
   comment-only, fixed f74f125. review 3/3 — done (6cd6d2da): zero findings.
5. merge 1/1 — skip: owner reviews PR #7 himself (brief).
6. deploy 1/1 — skip: no daemon/app.
Report: https://me.andrew.ee/reports/jeth-warm-state-2026-09.html
