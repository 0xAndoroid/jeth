---
created: 2026-09-04
updated: 2026-09-04
tags: [jeth, benchmark]
---

# Wave 3 allocation lane — RLP presizing rejected

**Save 1,354,106 rows on 25905781 (0.030617 c/g, 0.1319%); below the 6M gate.**
The prototype and local build-path edit were reverted. No runtime change ships.
This rejects this RLP-vector prototype, not every possible allocation optimization.

Base: `6d1665ca3edf8d4a5387ca56f147b9ee44a7d4a4`; production library unchanged;
Jolt `628713fd4`. Execute-only, proven-pass rows; no proof generated.
The fresh baseline caller profiles reproduce **1,026,896,402 rows exactly**.

## Profile findings and candidate ranking

| Priority | Site | Evidence | Decision |
|---|---|---|---|
| 1 | RLP node temporary `Vec<&[u8]>` | Current `grow_one` caller profile: 1,290,675 rows; 947,024 attributed directly to `decode_node_zc`, 343,651 self-attributed | Prototype measured, rejected |
| 2 | EVM storage maps | Wave-2B flat rehash rows: U256→U256 1,214,221; U256→EvmStorageSlot 1,135,041 | Separate upstream containers; not expanded after failed gate |
| 3 | EVM transition/account maps | Wave-2B flat rehash rows: StorageSlot 535,820; Address→Account 507,338; Address→CacheAccount 441,329 | Not changed |
| 4 | CodeMap / trie lookup maps | Wave-2B flat rehash rows: storage-root index 389,513; bytecode hash table 294,004 | Not changed |
| 5 | Receipts / encoder scratch | Source inspection: receipts already use transaction-count capacity; `memoize_arena` already shares scratch | No new reuse layer |

The different profile metrics above are **not additive**. Wave-2B figures are
historical attribution supplied to this lane, not remeasured production-library
site totals.

Current production-library caller evidence:

- `size_class_alloc::alloc`: `decode_node_zc` 11,339,769 rows (82.65%, mostly node
  boxes); `RawVecInner::finish_grow` 959,170. Box allocation is not growth churn.
- `size_class_alloc::realloc`: 5,357,995 rows (94.85%) attributed to
  `RawVecInner::finish_grow`. One-level return-address attribution stops there;
  it does not assign the entire realloc pool to RLP vectors.
- `memcpy`: decode 49,595,949; memoize 16,161,760; exact-decode wrapper 4,262,544;
  realloc 1,310,516. Most copy volume is outside this presizing change.

## Rejected hint

| Site | Advice source | Clamp | Semantic dependency |
|---|---|---|---|
| RLP list item-vector reservation | Existing `compute_advice` pass scans RLP item headers and emits exact item count | `min(hint, 17)` slices; 272 requested bytes on RV64 | Allocation capacity only |

A shared local payload decoder replaced the two `Header::decode_raw` calls.
It retained the same header decoding and item traversal, reserving capacity before
pushes. The hint never controlled item count, parsing, validation, or hashing.
A false hint only wasted bounded reservation or caused normal growth; the clamp
site documented this. No JEF change or new trusted input. No hints remain.

Advice tape: **1,006,744 → 1,120,800 bytes** (+114,056; 14,257 list hints).
The new scan is in the uncounted compute pass. Per-transaction reuse was not added:
the measured reuse opportunities already had capacity/scratch support, and the
parent explicitly prohibited expanding the diff to reach the benefit threshold.

## Measurement ledger

| Block | Gas | Baseline self rows | Prototype self rows | Saved | Baseline trusted rows | Prototype trusted |
|---|---:|---:|---:|---:|---:|---|
| 25905781 | 44,227,079 | 1,026,896,402 | 1,025,542,296 | 1,354,106 | 827,710,368 | Not run |
| 25905786 | 26,354,048 | 504,204,199 | Not run | — | 403,320,374 | Not run |
| 25905788 | 6,217,605 | 163,174,014 | Not run | — | 130,189,227 | Not run |

781 self c/g: **23.218725 → 23.188108**. Keccak permutations:
**122,629 → 122,629**; final calls and bytes also unchanged (52,643; 13,396,703).
Hash unchanged:
`0xf691da3f35d6330a8bb9e1c8c589eb8694ecdc3dded0c7f57b75f9572d75b529`.
Reveal saves 947,713 rows; post-root saves 408,959; other phases net +2,566.

Baseline native validation passed **3/3**. Prototype guest/native output parity
passed **1/1** on 781. The first benefit gate failed; per the parent's subsequent
strict instruction, the prototype was reverted immediately. Remaining both-variant
traces and nextest were **not run**, not claimed as passed. There is no retained
runtime change requiring a shipping regression gate.

## Evidence and reproduction

Raw evidence remains local under `data/w3-alloc/`: four caller logs, `callers.json`, three baseline-native logs,
`presized-self-25905781.log`, its JSON summary, and source fingerprints.

Runs used `CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-w3-alloc` and
`JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-main/release/jolt`. The host's
hard-coded guest target was temporarily changed to
`/Volumes/Dev/cargo-target/jeth-w3-alloc-guest` for isolation. Exact commands and
ELF paths are in the logs. Fresh builds require the campaign's atomic
`mkdir /tmp/jeth-w3-cargo.lock` slot and isolated guest paths; do not rebuild the
reverted host and assume it retains the temporary isolation.

Caller log filenames: `baseline-sizeclassallocalloc.log`,
`baseline-sizeclassallocrealloc.log`, `baseline-memcpy.log`,
`baseline-RawVecugrowone.log`. The rejected patch is retained only as local raw
experiment evidence, not in this commit. Guest binaries in the isolated target
directory still describe the rejected prototype; do not use `--skip-build` to
validate the reverted source.

Data inputs and witnesses were read-only symlinks; metadata and summaries local
regular files. All six source input/witness SHA-256 values and mtimes unchanged.
No shared library, hashing source, input, witness, or campaign ELF was modified.
