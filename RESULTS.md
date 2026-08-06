# jeth results — Jolt-tracing full Ethereum mainnet blocks

**Headline: a mainnet block mined 2.6 minutes earlier was statelessly validated inside a
Jolt RV64IMAC guest in 2.66B trace cycles — 63.4 cycles/gas — traced in 27 s at 98 MHz.**

Run date: 2026-08-06 (~20:00 UTC). First published Jolt-zkVM full-EVM-block numbers (no
prior Jolt-EVM datapoint exists).

The guest does the complete state-transition check, not tx replay: ancestor-header chain
verification, pre-state witness reveal against the parent state root (MPT), full tx
execution under revm, receipts/bloom/gas/requests consensus checks, and
`computed_post_state_root == header.state_root`. A panic on any check is a failed run;
per-tx signatures are verified in-guest against host-recovered pubkeys (soundness-equivalent
to in-guest ecrecover, cheaper).

## Blocks traced (all fetched + traced 2026-08-06)

| block | age at trace | gas used | txs | witness (state+code) | input.bin | total trace cycles | **cycles/gas** | wall | MHz |
|---|---|---|---|---|---|---|---|---|---|
| **25698189** | **~2.6 min** | 41,932,456 | 415 | 6.1 + 4.2 MB | 10.7 MB | **2,658,081,803** | **63.4** | 27.0 s | 98.5 |
| 25697951 | ~2 h | 43,118,232 | 331 | 5.6 + 3.9 MB | 10.0 MB | 2,672,823,966 | 62.0 | 27.4 s | 97.7 |
| 25698026 | ~40 min | 31,842,749 | 483 | 5.4 + 3.0 MB | 8.7 MB | 2,299,131,033 | 72.2 | 24.6 s | 93.6 |
| 25698070 | ~25 min | 57,999,343 | 1312 | 9.3 + 3.3 MB | 13.3 MB | 4,942,946,967 | 85.2 | 58.2 s | 84.9 |
| 25698208 † | ~3 min | 56,690,935 | 1291 | 8.9 + 2.8 MB | 12.4 MB | 4,435,092,565 | 78.2 | 50.3 s | 88.2 |

† = the `jeth bench` one-command verification run (fetch→native→trace unattended).

Every run's guest output block hash matched the independent native `stateless_validation`
run bit-for-bit; every native run matched the canonical on-chain block hash.

- "Cycles" = Jolt trace rows (real RV64IMAC instructions + virtual-sequence/inline
  expansions) — the prover-relevant count returned by the streaming execute-only pass.
- Composition: mostly type-2 txs, each block carried 1–4 blob txs (type-3) and 3–6
  EIP-7702 set-code txs (type-4); no bn254-pairing-heavy outlier observed. Aug 2026
  mainnet was busy (60M gas limit; these blocks run 31.8–58M vs ~29.5M 7-day average).
- 25698026's witness came from `zeth-rpc-proxy` (Tier 2); the other three straight from
  hosted geth `debug_executionWitness` (Tier 1, QuickNode docs-demo).

## Phase breakdown (guest cycle markers)

| block | deserialize+io | sig_verify (real+virt) | validation (real+virt) | sig_verify/tx | validation cyc/gas |
|---|---|---|---|---|---|
| 25698189 | 29.5M (1.1%) | 735.8M (27.7%) | 1,892.8M (71.2%) | 1.773M | 45.1 |
| 25697951 | 24.3M (0.9%) | 588.5M (22.0%) | 2,060.0M (77.1%) | 1.778M | 47.8 |
| 25698026 | 22.6M (1.0%) | 853.3M (37.1%) | 1,423.2M (61.9%) | 1.767M | 44.7 |
| 25698070 | 42.8M (0.9%) | 2,312.9M (46.8%) | 2,587.2M (52.3%) | 1.763M | 44.6 |

Two-parameter cost model that fits all four blocks within a few percent:

```
total_cycles ≈ 1.77M × n_txs  +  ~45 × gas_used  +  ~30M fixed
              (k256 sig verify)   (execution + MPT + post-root)
```

Total cycles/gas varies 62→85 almost entirely with tx density (sig cost per gas);
the execution phase itself is a remarkably stable ~45 cycles/gas.

## Where the cycles go (PC-sampled, block 25698026, post-fix)

| share of real instrs | symbol |
|---|---|
| ~66% | k256 signature verify (ProjectivePoint::add 38.4%, ::double 12.5%, LookupTable::select 6.5%, FieldElement::square 5.2%, invert 2.6%…) |
| 11.6% | `compiler_builtins::mem::memcpy` (Jolt has no memcpy inline) |
| ~5% | zeth-mpt trie (node decode 2.2%, resolve_digests 1.6%, rlp_encoded…) |
| ~2.5% | allocator (post-fix; was **85.7%** — see below) |
| 1.0% | revm `analyze_legacy` (eager bytecode analysis at witness reveal) |
| 0.9% | `native_keccak256` shim (real-instr share only; keccak-f cost sits in inline virtual rows) |

## The allocator finding (main perf result beyond the headline)

Out of the box the run was **513 cycles/gas** (29.8B cycles for block 25698070).
PC-sampling showed ZeroOS's `linked_list_allocator` (first-fit free-list walk) consuming
**85.7% of all real instructions** (58.6% `allocate_first_fit` + 27.1% `deallocate`)
under revm/trie allocation churn.

Fix: `crates/alloc-o1` — an O(1) segregated-recycling bump allocator (pow2 size-class
free lists over a bump arena, single-hart, no locking, no search), swapped in via cargo
`[patch]` of the ZeroOS git dep in the standalone guest workspace (the read-only Jolt
worktree is untouched). Guest heap 1 GiB → 1.5 GiB for class-rounding headroom.

Effect: 29.76B → 4.94B cycles (6.0×) on 25698070; 10.79B → 2.30B (4.7×) on 25698026.
Identical guest outputs. **Any allocation-heavy Jolt no_std guest likely wants this.**

## Calibration vs published stacks

| stack | crypto accel | cycles/gas |
|---|---|---|
| zeth 1.0 (risc0 2023) | none | 130–260 |
| **jeth v1 (Jolt, this run)** | **keccak inline only + host pubkey recovery** | **62–85** |
| SP1-Reth (2024) | keccak+k256+sha2 patches | 13–22 |
| rsp (2025, n=100) | full sp1 patches | avg 16.6 |
| Ethproofs top provers (2026) | full | 5–11 |

Landed where predicted for a keccak-inline-only stack (PLAN §1.4 forecast: 30–120).
The gap to the 5–22 c/g stacks is almost entirely the ~66% k256 share: swapping
`verify_and_compute_signer_unchecked`'s k256 with Jolt's `secp256k1` inline
(`ecdsa_verify`) is the single biggest lever (~1.7M → ~0.1–0.3M?/tx), then a memcpy
inline (11.6%), then bigint/modexp inlines.

## Setup

- **Stack:** `paradigmxyz/stateless` @ `6e55612` (+ `tries`, `zeth-mpt`) over reth
  v2.1.0 / revm 38 / alloy 2.0 — zeth 0.3's pin set. Chain spec: minimal Fusaka-era
  mainnet spec (Osaka + BPO1/BPO2), no genesis JSON in-guest.
- **Trie:** `tries::zeth::SparseState` (zeth-mpt). The default reth
  `StatelessSparseTrie` rejects both geth and zeth-rpc-proxy witnesses ("prover must
  supply exclusion proof for slot …") on absent-slot reads; the zeth MPT proves absence
  from the revealed partial trie. This was PLAN risk #1, resolved without touching the guest.
- **Keccak:** `jolt-inlines-keccak256` via alloy-primitives `native-keccak` +
  a 5-line `#[no_mangle] native_keccak256` shim. No crate forks, no `[patch.crates-io]`.
- **Guest:** no_std RV64IMAC (`riscv64imac-unknown-none-elf`), 32 MiB input / 1.5 GiB
  heap / 32 MiB stack, postcard input `{block RLP, pubkeys, witness}`; plus a no-op
  `critical-section` provider and the O(1) allocator patch.
- **Tracer:** Jolt branch `merge-1717-main` @ `af1c2aef5c` (path deps; read-only
  worktree). Streaming execute-only pass — no trace materialization, `max_trace_length`
  irrelevant. Effective 85–98 MHz single-thread.
- **Machine:** Apple M4 (10-core, 16 GB), macOS 26.5.2. Emulator peak RSS ≈ flat guest
  memory ≈ 1.6 GB.
- **Witness sources (free, no server rental):** QuickNode docs-demo geth
  `debug_executionWitness` (Tier 1; BlockPI works too but emits JSON-object headers my
  fetcher skips) with `zeth-rpc-proxy` → publicnode as Tier 2 fallback.

## Reproduce

One command (fetch fresh head−8 block → native gate → guest trace):

```bash
cargo run --release -p jeth-host -- bench
```

Prerequisite (once): build the Jolt CLI from the pinned branch —
`cd /Volumes/Dev/worktrees/jolt/merge-1717-main && CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jolt-cli cargo build --release -p jolt`
(or set `JOLT_PATH` to any `jolt` binary built from `merge-1717-main`).

Individual steps: `jeth fetch [--block N]`, `jeth run-native --input data/<N>/input.bin`,
`jeth trace --input data/<N>/input.bin [--skip-build]`,
`jeth profile --input data/<N>/input.bin` (PC-sampled symbol histogram).

## Notes & caveats

- Trace length is the prover-relevant cycle count, but proving is out of scope (v1);
  a 2.7B-cycle trace is ~2^31.3 rows against Jolt's ~2^29–2^30 practical single-proof
  ceiling — segmentation/continuations would be needed to actually prove these blocks.
- `witness.keys` is ignored by the zeth trie path (as in zeth/rsp); geth includes it,
  the input carries it (~1–2 MB) — could be stripped from `input.bin` for tidiness.
- Deserialize cost is ~1% (postcard + RLP block decode in-guest) — the rkyv zero-copy
  fallback contemplated in the plan is unnecessary.
- sig_verify covers signature checks + sender derivation only; low-s/Homestead rules
  enforced as in `recover_block_with_public_keys`.
- Stretch items not attempted (per plan): secp256k1 inline swap, 3-block
  low/median/high battery beyond the four above, `TRACER_PARALLEL`, proving-feasibility memo.
