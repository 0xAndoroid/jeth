# jeth-warm-state — repeated state access within a block (2026-09-18)

Owner question: most blocks touch the same contract state repeatedly across txs; does jeth
reach warm state cheaply (no repeated cold state-proof cost), and if not, can it?

Orchestrator: ed8b8e5c. Branch `jeth-warm-state` (worktree ~/dev/jeth.jeth-warm-state).
Jolt CLI: rebuilt from /Volumes/Dev/worktrees/jolt/jolt-amber-nolane @ a0d7b74baa into
/Volumes/Dev/cargo-target/jolt-cli-amber-nolane (target dir had been cleaned).

## Steps (playbook)
1. plan 1/1 — investigate state path (witness load/verify, per-block vs per-access, revm cache,
   cold/warm, bytecode, SLOAD/SSTORE/BALANCE/EXTCODE) + native census of repeated touches.
2. implement a/2 — cycle attribution on 4 blocks (witness verify / state lookups / EVM / precompiles / other).
3. implement b/2 — prototype top lever, before/after on the same blocks, proofs still verify (hash gate).
4. review i/3 — fresh reviewer each round.
5. merge 1/1 — skip: owner reviews the PR (not merged by us).
6. deploy 1/1 — skip: no daemon/app.
Report: ~/.pika/web/reports/jeth-warm-state-2026-09.html
