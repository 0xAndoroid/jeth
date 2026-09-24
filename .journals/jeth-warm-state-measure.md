# jeth-warm-state · implement a/2 — cycle attribution of the in-block warm-state path (2026-09-18)

Question: does jeth reach state that an earlier tx in the block already touched cheaply, or pay a
cold state-proof cost each time? Measurement only; tree = `jeth-warm-state` @ origin/main `cc29bea`
(+ journal), Jolt pin `jolt-amber-nolane` @ `a0d7b74baa` (CLI rebuilt 01:33 from the pinned worktree).
Raw files: `/Volumes/Dev/tmp/jeth-warm-state/measure/` (logs, JSON, CSV). Bucket tool (committed):
`scripts/warm_state_buckets.py` — the RULES table there is the exact bucket definition.

## 1. Totals and gates (SELF, `jeth trace`; hash == `run-native` on 4/4)

| block | gas | rows | c/g | ladder @966b204 | Δ rows | perms (= ladder) | pertx-build rows |
|---|---:|---:|---:|---:|---:|---:|---:|
| 25905781 | 44,227,079 | 601,659,728 | 13.605 | 603,187,863 | −1,528,135 | 115,373 | 602,851,522 |
| 25905782 | 47,065,991 | 720,626,001 | 15.311 | 721,922,345 | −1,296,344 | 124,117 | 721,565,163 |
| 25905785 | 47,351,982 | 628,266,867 | 13.268 | 629,550,111 | −1,283,244 | 121,623 | 629,145,617 |
| 25905789 | 44,608,380 | 675,886,779 | 15.152 | 677,090,274 | −1,203,495 | 133,642 | 676,779,259 |

- Δ vs the RESULTS no-lane ladder: −0.18..−0.25% on every block, keccak census identical → the
  tree, not the tracer: main gained `4e5b055` (PR #1 review refactor: code-library lookup compares
  raw hashes and decodes only the hit, zeth-mpt `rlp.rs` split, `read_be_immediate` extra-word read
  only when the immediate spills, SnapCell memo column dropped) after the ladder's `966b204`.
- The pre-existing `/Volumes/Dev/jeth-inputs/25905781/trace-summary.json` (596,202,686 rows,
  written 2026-09-10 02:35) is from an experimental tree that never landed on main; not reproducible
  here (copy: `measure/trace-summary-25905781.prev.json`). All four summaries are now rewritten.
- pertx build (markers + per-tx keccak census println) costs +0.9..1.2M rows; all % below are
  against the pertx-build total of each block.
- Trusted digests, 781: **446,592,687 rows (10.10 c/g), Δ −155,067,041 (−25.8%)**; perms
  115,373 → 55,438 (−59,935 = reveal 31,032 + execution first-touch 28,875 + post-root 28) →
  2,587 rows/perm. That is exactly bucket (a)'s keccak (80.1M reveal + 74.7M exec = 154.8M).

## 2. Category table (rows, % of block; pertx build; `warm_state_buckets.py buckets`)

| bucket | 781 | 782 | 785 | 789 | 4-block rows | % | c/g (Σrows/Σgas) |
|---|---:|---:|---:|---:|---:|---:|---:|
| (a) witness verification | 182.5M (30.3%) | 187.0M (25.9%) | 182.3M (29.0%) | 198.4M (29.3%) | 750.2M | 28.5% | 4.094 |
| (b) warm-path state lookups | 52.2M (8.7%) | 53.4M (7.4%) | 51.4M (8.2%) | 52.3M (7.7%) | 209.3M | 8.0% | 1.142 |
| (c) EVM interpreter | 136.0M (22.6%) | 196.0M (27.2%) | 142.1M (22.6%) | 144.8M (21.4%) | 618.8M | 23.5% | 3.377 |
| (d) precompiles + signatures | 79.0M (13.1%) | 101.9M (14.1%) | 72.1M (11.5%) | 70.9M (10.5%) | 324.0M | 12.3% | 1.768 |
| (e) post-state root | 112.0M (18.6%) | 138.3M (19.2%) | 140.2M (22.3%) | 163.7M (24.2%) | 554.1M | 21.1% | 3.024 |
| (f) other | 38.8M (6.4%) | 43.0M (6.0%) | 39.2M (6.2%) | 44.8M (6.6%) | 165.9M | 6.3% | 0.905 |
| attributed | 99.60% | 99.74% | 99.71% | 99.73% | 2,622.5M | 99.7% | 14.311 |

Unattributed 0.3% = the per-marker `<256 rows` tail the profiler drops. 4-block gas 183,253,432.

Top sub-lines over the 4 blocks (M rows / %): (e) keccak post-root node hashing 428.7 / 16.3 ·
(a) keccak reveal 403.0 / 15.3 · (a) keccak exec first-touch authentication 227.7 / 8.7 · (d) bn254
arkworks 164.2 / 6.2 · (c) handler run loop + frames 149.5 / 5.7 · (c) stack ops 132.9 / 5.1 ·
(e) post-root materialization 119.9 / 4.6 · (d) secp inline 106.2 / 4.0 · (f) keccak tx/receipt
roots + bloom 80.1 / 3.0 · (a) reveal MPT decode 71.0 / 2.7 · (b) journal 69.3 / 2.6 · (c) KECCAK256
op 59.1 / 2.2 · (b) address/slot hash memo keccak misses 38.0 / 1.4 · (b) hashbrown maps 35.1 / 1.3 ·
(b) per-tx commit 21.8 / 0.8 · (a) validate_at 19.2 / 0.7 · (c) bytecode analysis 17.8 / 0.7 ·
(b) State/CacheState 15.8 / 0.6 · (a) storage() walk 13.4 / 0.5 · (b) block finalize 13.4 / 0.5.

### Bucket membership (defining item, never generic params; see RULES for regexes)

Shared symbols `native_keccak256` / `memcpy` / `memcmp` are split per marker group (reveal · tx
· post_root · outside) by `--callers-of` return-address profiles: keccak callers measured on all
4 blocks, memcpy/memcmp on 781 and reused (each caller weighted by its own row split over the
groups of the block being attributed; reconciliation actual vs implied within 3% in the tx group).

- **(a)** reveal marker: everything except `analyze_legacy` (→c) and alloc/fmt (→f): keccak via
  `WitnessResolver::resolve_hit` + `InstrumentedTrie::new_with_codes` (code hashes),
  `zeth_mpt::*` (`decode_node_zc_into`, `Node::resolve_with`, `decode_child`), memcpy. Execution:
  keccak whose caller is `SparseState::storage` (first-touch node authentication), `jeth_core::walk::*`
  (`validate_at`, `match_path` + its memcmp), `SparseState::storage` minus the modelled fixed cost,
  `Node::get` + `decode_exact::<TrieAccount>` (account trie lookup on a `basic()` miss),
  `<Uint as Decodable>::decode` (leaf value), `jeth_core::resolver::*`.
- **(b)** `revm_context::journal::*` (`JournalInner::load_account*`, `transfer_loaded`),
  `revm_context_interface::journaled_state::*` (`JournaledAccount::sload/sstore_concrete_error`),
  `<Context as Host>::sload/sstore_skip_cold_load`, `WarmAddresses`, `revm_database::states::*`
  (`State::load_cache_account_with`, `<&mut State as Database>::basic/storage/code_by_hash`,
  `DatabaseCommit::commit`, `CacheState::apply_account_state`, `CacheAccount::change`,
  `TransitionAccount`, `bundle_state/bundle_account/reverts`), hashbrown `RawTable<(Address,Account)>`,
  `<(U256,EvmStorageSlot)>`, `<(Address,CacheAccount)>`, `<(U256,U256)>`, `<(U256,StorageSlot)>`,
  `<(Address,TransitionAccount)>`, `<(U256,RevertToSlot)>`, `<(B256,Bytecode)>`, `foldhash`,
  `MainnetHandler::pre/post_execution/first_frame_input`, `SparseState::account`, storage() fixed
  cost (360 rows × DB misses, storage-walk-analysis model), `storage_roots` IndexMap,
  `keccak_memo::*` (+ keccak via `KeccakMemo::insert_at`), `code_library::*`, `CodeMap`.
- **(c)** `revm_interpreter::*` (host/contract/stack/memory/arith/bitwise/control/system handlers,
  `shared_memory`, gas), `revm_handler::*` (`Handler::execution` = inlined run loop, `EthFrame`,
  `frame_init/return`), keccak via `instructions::system::keccak256`, `ruint::*`,
  `analyze_legacy`/`revm_bytecode`, memset in tx markers.
- **(d)** `recovery_batch::*`, `recover::*`, `crypto::*`, `jolt_inlines_secp256k1`, `ark_*`,
  `revm_precompile`, `alloy_evm::precompiles`, `alloy_eip7702`/k256, sender-derivation iterator
  (`GenericShunt<…Iter<stateless::UncompressedPublicKey>…>`) + its signing-hash keccak.
- **(e)** post_root marker (all) + `hashed_post_state`, `calculate_state_root`, `nybbles`, sorts.
- **(f)** `container::*`/JEF, receipts/bloom/tx-root/header (`receipt_root_bloom`, `HashBuilder`,
  `alloy_consensus`, `bytes::BufMut`, topics memo `RawTable<(B256,B256)>`), tx-loop glue, alloc
  (`bump_alloc`, `RawVecInner`), census println (`core::fmt`), memmove/builtins.

## 3. First touch vs repeat (native census: `jeth touches`, census lane binary, hashes match)

| block | SLOAD | SSTORE | CALL-family | BALANCE/EXTCODE* | `basic()` misses | `storage()` misses | acct tx-loads | slot tx-loads | slot ops on repeated keys |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 781 | 7,751 | 2,225 | 3,023 | 535 | 1,469 (1,464 distinct) | 2,832 (2,844 distinct) | 2,582 | 3,759 | 2,577 / 9,976 (25.8%) |
| 782 | 5,290 | 1,614 | 3,216 | 972 | 2,035 | 1,986 | 2,955 | 2,837 | 2,174 / 6,904 |
| 785 | 6,223 | 1,815 | 3,319 | 1,019 | 1,973 | 1,984 | 2,767 | 2,786 | 2,583 / 8,038 |
| 789 | 4,486 | 1,140 | 3,372 | 1,398 | 2,579 | 1,522 | 3,386 | 2,279 | 1,739 / 5,626 |

DB misses == distinct keys: revm's `State`/`CacheState` dedupes perfectly across txs — a key
touched by a second tx never reaches `SparseState` again. The remaining cost classes (781, tx
markers; `--storage-calls 2832`):

| class | 781 rows | % | 782 | 785 | 789 | 4-block % |
|---|---:|---:|---:|---:|---:|---:|
| block-once reveal (a: state trie + code hashes) | 93.6M | 15.5% | 118.5M | 114.2M | 147.7M | 18.0% |
| **first touch per distinct key/node (a+b)** | **101.8M** | **16.9%** | 81.2M | 80.3M | 63.6M | **12.4%** |
| **repeat per access / per tx (b, revm-internal)** | **39.3M** | **6.5%** | 40.8M | 39.2M | 39.4M | **6.0%** |

First-touch composition, 781: exec authentication keccak 74.7M · slot/address hash-memo misses
9.7M (keccak) · `validate_at`+`match_path` 6.3M · `storage()` walk 4.6M · account trie
`Node::get`+`TrieAccount` decode 2.2M · leaf decode 1.2M · storage() fixed 1.0M · memos 0.8M ·
`account()` fixed 0.7M · storage_roots 0.2M · code library 0.2M.
Repeat composition, 781: journal 17.7M · hashbrown maps 9.0M · per-tx commit 5.0M · State cache
4.1M · block finalize 2.6M · handler pre/post 0.9M (memcpy/memcmp shares folded in).

Unit costs (781; symbols listed in §2, rows incl. their memcpy/memcmp share):

| unit | rows | derivation |
|---|---:|---|
| first touch of a storage key (storage() miss) | **≈33.6k** | keccak 26.4k (10.2 perms ≈ 2.5 fresh 532-B branches + leaf) + validate_at 2.2k + walk 1.6k + fixed 0.36k + leaf decode 0.4k + slot-hash memo miss 2.6k (per distinct slot value) |
| first touch of an account (basic() miss) | ≈5.0k | address keccak 2.6k + Node::get/TrieAccount decode 1.5k + account() fixed 0.5k + storage_roots 0.4k |
| code_by_hash miss (468; 406 from the code library) | ≈0.9k | `LibraryView::lookup_bytecode/entry` + memcmp |
| warm SLOAD (7,751) | ≈1.0k | handler 71 + `Host::sload_skip_cold_load` 316 + `sload_concrete_error` 342 + storage-map probe share ≈300 |
| warm SSTORE (2,225) | ≈1.0k | handler 244 + `sstore_skip_cold_load` 305 + `sstore_concrete_error` 152 + map share |
| account load per CALL/BALANCE/EXTCODE*/tx-level (~4.9k) | ≈0.8k (+0.5k `load_acc_and_calc_gas` per CALL) | `JournalInner::load_account*` 3.1M + WarmAddresses + `(Address,Account)` probes |
| tx-level cache load of a block-warm key (6,341) | ≈0.64k | `State::load_cache_account_with` 2.0M + Database wrappers 1.5M + `(Address,CacheAccount)` 0.6M |
| per-tx commit (434 txs) | ≈11.6k/tx | `commit` + `apply_account_state` + `CacheAccount::change` + transitions (+memcpy 1.8M) |
| block finalize | 2.6M once | `apply_transitions_and_create_reverts`, reverts maps |

Per-tx view (781, `warm_state_buckets.py pertx --repeat-to`; tx-marker rows 304.8M = first-touch
101.0M (33%) + repeat 35.0M (11%) + EVM 130M + precompiles 34M): 433/434 txs authenticate at
least one fresh node. Top-10 by cycles: tx153 (42.4M, 72 c/g) = bn254 pairing (d); tx175 Safe
`execTransaction` (27.6M, 3.19M gas) = 50% first-touch (10.4M auth keccak); tx352/353 same
contract+selector back-to-back: 10.87M → 10.30M rows (4.0 → 3.8 c/g), first-touch 14% → 16%,
repeat 20% → 16%; tx200/367/159/218/205/162: first-touch 28–62%, repeat 6–13%.

Same-contract chains — the second tx **is** cheaper, but not free, because every transfer touches
two fresh balance slots (own leaf + unique lower branches; shared upper levels are memoized):

| chain | n | c/g order | first-touch rows | auth perms | repeat rows |
|---|---:|---|---|---|---|
| USDT `transfer` | 63 | 12.9 → 6.1 → 5.9 → 2.4 → 6.0 → 3.9 → avg 4.8 | 378k → 172k → 167k → 64k → 169k → 147k → avg 129k | 155 → 70 → 68 → 27 → 69 → 60 → avg 52 | 36k → 31k → 30k → 33k → 30k → 30k → avg 34k |
| USDC `transfer` | 44 | 5.8 → 5.2 → 3.6 → 3.5 → 3.6 → 5.5 → avg 3.8 | 123k → 110k → 116k → 62k → 119k → 131k → avg 95k | 50 → 45 → 49 → 26 → 49 → 54 → avg 39 | 37k → 52k → 36k → 32k → 34k → 39k → avg 36k |
| EntryPoint v0.6 `handleOps` | 5 | 8.0 → 6.7 → 6.9 → 3.4 → 5.4 | 979k → 296k → 299k → 564k → 354k | 405 → 116 → 121 → 230 → 141 | 220k → 116k → 159k → 169k → 111k |

Answer: **yes for repeated keys** (zero DB re-walks; the warm path is revm's own ≈1k-row journal
probes, 6% of the block), **no for new keys in a warm contract** — each still costs ≈26k rows of
authentication keccak (+≈7k of walk/validate/memo), 12.4% of the block over 4 blocks; the
trusted-digests run removes exactly that keccak (−25.8% incl. the reveal). Non-keccak first-touch
pool that a code change could compress: ≈13M on 781 (2.2%; matches storage-walk-analysis 12.6M).

## 4. Reproduce

```sh
export CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-warm-state JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-amber-nolane/release/jolt
cargo build --release -p jeth-host --features secp-inline
J=$CARGO_TARGET_DIR/release/jeth; IN=/Volumes/Dev/jeth-inputs; M=/Volumes/Dev/tmp/jeth-warm-state/measure
for b in 25905781 25905782 25905785 25905789; do
  $J run-native --input $IN/$b/input.bin; $J trace --input $IN/$b/input.bin [--skip-build]
  $J profile --input $IN/$b/input.bin --rows --split-markers --json $M/profile-split-$b.json > $M/profile-split-$b.log
  $J profile --input $IN/$b/input.bin --rows --callers-of native_keccak256 --guest-features pertx --top 80 > $M/callers-keccak-$b.log
  $J txprofile --input $IN/$b/input.bin --skip-build --top 40 > $M/txprofile-$b.log   # writes $IN/$b/txprofile.json
done
$J trace --input $IN/25905781/input.bin --trusted-digests
$J profile --input $IN/25905781/input.bin --rows --callers-of memcpy --guest-features pertx --top 80 > $M/callers-memcpy-25905781.log   # same for memcmp
uv run python scripts/warm_state_buckets.py buckets $M/profile-split-25905781.json \
  --callers native_keccak256=$M/callers-keccak-25905781.log --callers memcpy=$M/callers-memcpy-25905781.log \
  --callers memcmp=$M/callers-memcmp-25905781.log --storage-calls 2832 --trace-rows 601659728 --json-out $M/buckets-25905781.json
uv run python scripts/warm_state_buckets.py pertx $M/profile-split-25905781.json $M/txprofile-25905781.json \
  --profile-log $M/profile-split-25905781.log --callers ... --repeat-to --csv $M/pertx-25905781.csv
```
`--storage-calls` per block = `storage()` DB misses (2832 / 1986 / 1984 / 1522, RESULTS wave-3
memo-hit column == `jeth touches` db misses). Guest ELF dirs kept for the implement lane:
`/Volumes/Dev/cargo-target/jeth-amber-nolane-guest-validate_block{,-compute_advice,-pertx,-pertx-compute_advice,_trusted,_trusted-compute_advice}`.
`jeth opcodes` is the RISC-V kind histogram (781: INLINE 51.7%, C.other 12.5%, LD 7.1%, ALU-R 6.2%,
SD 5.5%, LBU 5.5%) — EVM op counts come from the census lane's `jeth touches`, not from it.

Caveats: per-tx shared-symbol splits use tx-group-wide caller shares (per-tx `validate_at` rows and
keccak perms are exact); memcpy/memcmp caller mix for 782/785/789 is 781's; the reveal/post_root
keccak reconciliation is off by design (`resolve_hit`'s own rows split 2:1 while its keccak is
99.9% reveal) but both groups map to one bucket each, so no rows move.
