# Warm state within a block — census and plan (2026-09-18, `jeth-warm-state-census`)

Question: most blocks touch the same contract state repeatedly; does jeth reach that state
faster on the second touch instead of paying the cold state-proof cost again?

Verdict (block 25905781 = 781, 603.19M rows on the no-lane tree, 434 txs):
- **Yes, already.** The state-proof work (advice walk + keccak authentication + `validate_at`)
  runs once per distinct key per block: `WitnessDatabase::storage` fired 2,832 times = the
  2,844 distinct (address, slot) loaded (12 are slots of accounts created or wiped in-block,
  served as zero without a walk); `WitnessDatabase::basic` 1,469 ≈ 1,464 distinct accounts. revm's
  `State` cache dedupes the cold path perfectly; the proven code never re-walks a key.
- **What is repeated** is bookkeeping, not proofs: per-access journal probes (7,132 warm
  SLOAD/SSTORE hits, 3.6k address ops, 3k frames), per-transaction reloads of keys already
  in `State` (1,118 accounts + 915 slots, because `finalize` empties the journal every tx), and
  the per-tx `finalize`+`State::commit` churn (4–7M, killed as unsound to restructure). Family
  total measured at 31.6M rows on 781 (wave-4 tree; 5.2% of today's block), of which ≈18–24M
  (3–4%) is repeat work (§4).
- The real cold cost — ≈40k first-touch keccak permutations ≈ 100M rows (16%) — is paid
  exactly once per distinct witness node per block. Only `--trusted-digests` or cross-block
  reuse touches it; consecutive blocks share just 2–8% of witness nodes (table §3c).
- Top lever: every `Address`, `B256` and `U256` map key is hashed byte-wise — derived `Hash`
  ends in one `Hasher::write(&[u8])` → `foldhash::hash_bytes_long`, whose `load()` is
  `read_unaligned::<u64>` = 8 `lbu` + 7 `slli` + 7 `or` ≈ 46 rows (disassembly of the current
  guest: 1,081 instructions, 288 `lbu` = 36 load sites × 8); four loads per 20-byte key, eight
  per 32-byte key. A containing-word `load()` in the already-vendored foldhash (2 `ld` + shifts
  ≈ 8 rows) saves ≈150 rows per Address hash and ≈300 per B256/U256 hash: **≈ −8…−15M on 781
  (1.3–2.5%)**, guest-only, no soundness surface, measure first. Sketch in §7.
- Levers the brief named that are void: "verified flat map after one walk" (0 — revm already
  guarantees one walk per key), bytecode analysis dedupe (0 — all 62 witness codes execute,
  R2 measured bit-identical), per-tx commit restructuring (killed, RESULTS "Killed").

## 1. Where the work happens (guest, self-verifying; rows = 781 unless noted)

| cadence | work | code | measured rows / unit |
|---|---|---|---|
| once/block | JEF zero-parse, sig verify | `container.rs`, `recover.rs` | deserialize 3.4M; sigs 78.7M (415 txs, 25698189) |
| once/block | eager state-trie build: resolve every reachable state node, keccak each | `zeth_trie.rs:178-233` `new_with_codes` → `RlpTrie::from_resolver` → `zeth-mpt mod.rs:349` `from_resolver_zc`; misses inline `resolver.rs:230` | reveal perms ≈ state nodes; `decode_node_zc_into` 14.95M, `resolve_with` 1.36M (wave N) |
| once/block | `keccak256(code)` per witness code, eager `Bytecode::new_raw` (analysis) | `zeth_trie.rs:196-206`, `validation.rs:242-258` `CodeMap::build` | 62 codes on 781 (library serves 406/468 loads pre-analyzed) |
| once/block | flat keccak memos presized `witness.state.len()/8` | `zeth_trie.rs:222-224`, `keccak_memo.rs:46-60` | fill ≈0.12M memset |
| once/block | post root: memo-built `HashedPostState`, sorted dirty paths, `insert_with`/`remove_with` stub hydration, arena encode | `zeth_trie.rs:160,350-441` | post_root keccak 30k perms; `encode_dirty` 9.8M |
| once/block | revm `State` build, `merge_transitions`, `take_bundle` | `validation.rs:111-141` | in the 4–7M churn pool |
| once/key (address) | `account()`: address words, one-entry `last_read`, flat memo (keccak on miss), `Node::get` over decoded state nodes, `decode_exact::<TrieAccount>`, `storage_roots` insert (B256 hashbrown) | `zeth_trie.rs:289-318`, `keccak_memo.rs:203-212`, `zeth-mpt node.rs:145-185` | `RlpTrie/Node::get` 1.61M ÷ 1,469 ≈ 1.1k; `storage_roots` probe 0.49M; `hash_address` 0.81M → flat memos 1.1M total (wave P) |
| once/key (slot) | `storage()`: fixed cost, `hash_slot` memo, advice walk: per level `authenticate_walk` (memo hit 50 rows / first visit keccak + `validate_entry` once per node), header decode, nibble skip loop, leaf `match_path` + `decode_exact::<U256>` | `zeth_trie.rs:320-347`, `resolver.rs:149-227`, `walk.rs:131-225,295-359` | `SparseState::storage` self 5.45M ÷ 2,832 ≈ 1.9k; `validate_at` 5.56M (555/branch, 150/leaf); first-visit keccak ≈ 40k perms ≈ 100M; branch visit 275–330, leaf 330, root re-visit 330 (`storage-walk-analysis.md` §1) |
| once/key (code hash) | `State::code_by_hash` miss → `CodeMap::get`: library binary search (12 × 32-byte compare + record decode) or `Eager` map probe, `Bytecode` clone (two `Arc` bumps) | `validation.rs:260-283`, `code_library.rs:146-190` | 468 calls × ≈1–1.5k ≈ 0.6M |
| every access | SLOAD/SSTORE: journal `state` probe (Address key) + `storage` probe (U256 key), warm/cold `transaction_id` test, `StateLoad`/`JournaledAccount` construction; SSTORE adds `touch()` + journal entry push | revm-context `journal/inner.rs:879-951` `load_account_mut_optional`, `:959-1004` `sload`/`sstore`; context-interface `journaled_state/account.rs:167-215,231-264` | hashbrown probe body ≈200–300 (waves M/P, memo symbols) + key hash in the out-of-line `foldhash::hash_bytes_long`: ≈190 rows per Address, ≈390 per B256/U256 (§7); warm hit ≈1.0–1.2k |
| every access | BALANCE/EXTCODESIZE/EXTCODEHASH/EXTCODECOPY: `load_account_info_skip_cold_load` → account probe + `warm_addresses` (coinbase compare, access-list probe, precompile set) + `load_code_preserve_error` (`State::code_by_hash` probe + clone once per (tx, account) whose cached info has no code) | `context.rs:625-650`, `inner.rs:879`, `warm_addresses.rs:118-177`, `account.rs:270-282` | ≈600–900 |
| every access | CALL family: `load_acc_and_calc_gas` → `load_account_delegated` (probe + code load), `make_call_frame` → `checkpoint`, `transfer_loaded` (two account probes, balance journal entries), frame init | revm-interpreter `call_helpers.rs:55-107`; revm-handler `frame.rs:144-250`; `inner.rs:432-480` | ≈1.5–2.5k per frame excluding interpreter setup |
| every tx | `load_accounts` (warm coinbase, access-list map), `deduct_caller` (`load_account_with_code_mut`), `reimburse_caller`, `reward_beneficiary` (coinbase reload from `State` every tx: census 434/434), `finalize` (`mem::take(state)` — journal emptied), `State::commit` → `apply_account_state` per loaded account (probe, `change()` clones info, storage filter/collect) → `TransitionState::add_transitions` | revm-handler `pre_execution.rs:19-62,165-190`, `post_execution.rs:59-107`, `api.rs:68-76`; revm-database `state.rs:368-377`, `cache.rs:182-238`; alloy-evm `eth/block.rs:203-238` | churn 4–7M (audit R1, RESULTS "Killed") |
| every tx-miss | journal miss on a key already in `State`: `State::basic` → `cache.accounts` probe + `AccountInfo` clone (+`Bytecode` clone); `State::storage` → account probe + `storage.entry` probe → journal insert | revm-database `state.rs:156-190,239-272,276-293` | ≈0.8–1.2k per reload |

## 2. Cold vs warm paths per op family (781 counts)

| op | journal hit (same tx) | `State` hit (earlier tx) | DB miss (first touch in block) |
|---|---|---|---|
| SLOAD 7,751 / SSTORE 2,225 | 2 probes incl. Address + U256 key hashes + slot bookkeeping (≈1.0–1.2k); SSTORE: original/present from `EvmStorageSlot`, journal entry if changed | + `State::storage` 2 probes + journal insert (≈1.7k more) — 915 slot reloads | + `SparseState::storage` walk: ≈1.9k non-keccak + first-visit node keccak/validate — 2,832 walks |
| BALANCE 35 / SELFBALANCE 93 / EXTCODESIZE 403 / EXTCODEHASH 3 / EXTCODECOPY 1 | account probe + warm-address checks; code load only if `info.code` is `None` | + `State::basic` clone (code included only if a previous tx committed the account with code loaded, i.e. touched by value transfer) — 1,118 account reloads | + `account()` 1.1k + memo keccak(address) + `storage_roots` insert; code: `code_by_hash` once per hash |
| CALL 1,535 / DELEGATECALL 793 / STATICCALL 695 / CALLCODE 0 | `load_account_delegated` probe + code (`Bytecode` clone), transfer probes ×2, checkpoint | same as above per target; STATICCALL targets are never touched → their code reloads through `State::code_by_hash` every tx | same |
| CREATE/CREATE2 1/3 | n/a | n/a | new account: `is_storage_known` → slots served zero, no walk |
| tx sender / coinbase / precompiles | — | reloaded from `State` every tx (`finalize` empties the journal) | first tx only |

## 3. Census (`jeth touches`, native; block hash = `run-native` on all four; 781 = `trace-summary.json` `0xf691…b529`)

### 3a. Per block

| block | txs | gas | steps | SLOAD | SSTORE | BAL/SELFBAL | EXTCODE* | CALL/DC/SC | DB basic (none) | DB storage (zero) | DB code (library) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 25905781 | 434 | 44.23M | 1,792,921 | 7,751 | 2,225 | 35/93 | 407 | 1,535/793/695 | 1,469 (67) | 2,832 (652) | 468 (406) |
| 25905782 | 342 | 47.07M | 2,427,207 | 5,290 | 1,614 | 16/100 | 856 | 2,207/476/533 | 2,035 (50) | 1,986 (608) | 358 (303) |
| 25905785 | 320 | 47.35M | 2,196,956 | 6,223 | 1,815 | 20/69 | 930 | 2,311/356/652 | 1,973 (120) | 1,984 (652) | 366 (317) |
| 25905789 | 325 | 44.61M | 2,405,640 | 4,486 | 1,140 | 17/78 | 1,303 | 2,571/276/525 | 2,579 (39) | 1,522 (456) | 322 (257) |

### 3b. Repeat structure (tx_loads = Σ over txs of keys loaded in that tx = `State::basic`/`State::storage` calls)

| block | accounts distinct / tx_loads / reloads | accounts in ≥2 txs (share of loads, of address ops) | slots distinct / tx_loads / reloads | slots in ≥2 txs (share of loads, of SLOAD+SSTORE) | SLOAD+SSTORE warm hits | slots written | code hashes executed / in ≥2 txs (share of frames) |
|---|---|---|---|---|---:|---:|---|
| 781 | 1,464 / 2,582 / 1,118 | 154 = 10.5% (49.3%, 50.9%) | 2,844 / 3,759 / 915 | 215 = 7.6% (30.1%, 25.8%) | 7,132 = 71% | 1,257 | 447 / 116 (66.3%) |
| 782 | 2,029 / 2,955 / 926 | 116 = 5.7% (35.3%, 51.3%) | 1,983 / 2,837 / 854 | 116 = 5.8% (34.2%, 31.5%) | 4,921 = 71% | 889 | 337 / 79 (65.6%) |
| 785 | 1,967 / 2,767 / 800 | 104 = 5.3% (32.7%, 60.3%) | 1,973 / 2,786 / 813 | 152 = 7.7% (34.6%, 32.1%) | 6,065 = 75% | 963 | 339 / 73 (71.3%) |
| 789 | 2,572 / 3,386 / 814 | 108 = 4.2% (27.2%, 41.5%) | 1,514 / 2,279 / 765 | 136 = 9.0% (39.5%, 30.9%) | 4,112 = 73% | 682 | 305 / 73 (77.2%) |

Hottest accounts (781): coinbase 434/434 txs (reloaded and committed every tx), USDT 89 txs
(331 slots, 1,218 slot ops), USDC 83 (250 slots, 2,068), WETH 51, ecrecover precompile 48,
Uniswap v4 PoolManager 11 (69 slots); the top-10 touch 434/434 txs (782: 342/342, 785: 320/320,
789: 325/325 — the coinbase alone does it). 5–10% of keys carry 30–50% of the loads and
26–60% of the ops; 71–75% of SLOAD/SSTORE executions hit a slot already loaded in the block.

### 3c. Cross-block reuse (`--dump-digests`, witness node sets, consecutive blocks)

| pair | 781→782 | 782→783 | 783→784 | 784→785 | 785→786 | 786→787 | 787→788 | 788→789 | 789→790 |
|---|---|---|---|---|---|---|---|---|---|
| nodes of N+1 already in N's witness | 1,567/19,647 = 8.0% | 11.3% | 9.3% | 5.0% | 9.6% | 8.0% | 12.6% | 1.8% | 5.0% |

Union of the nine earlier witnesses covers 2,557/15,570 = 16.4% of 790. Lower bound for a
multi-block guest (nodes rewritten by N's post-root and re-touched by N+1 are also known
in-guest; not counted here — needs the dirty-node set, follow-up census).

## 4. Repeated-work pools on 781 (rows; per-unit costs from §1, counts from §3)

| pool | count × rows | ≈ rows | % of 603.2M | once-per-block/key alternative? |
|---|---|---:|---:|---|
| warm SLOAD/SSTORE journal hits | 7,132 × 1.0–1.2k | 7.1–8.6M | 1.2–1.4 | cheaper hashing/probes only (§5 L1/L2) |
| cross-tx slot reloads (`State::storage` hit) | 915 × 2.8k | 2.6M | 0.4 | inherent to per-tx `finalize` |
| cross-tx account reloads (`State::basic` hit) | 1,118 × 1.5k | 1.7M | 0.3 | inherent; coinbase 434 of them |
| warm address ops + call-family loads | 3,559 × 1.0k + 2,985 × 2.5k | 3.6 + 7.5M | 1.8 | cheaper probes |
| per-tx `finalize` + `State::commit` churn | measured | 4–7M | 0.7–1.2 | killed (unsound); trims ≤1M |
| per-tx caller/coinbase/precompile loads | 434 × ~3k | 1.3M | 0.2 | inherent |
| shared-prefix re-visits inside distinct-slot walks | 2.6–5k branch visits × 300 | 0.8–1.6M | 0.2 | (root, nib0) memo, header skip (§5 L5) |
| code re-clones for untouched code accounts | ≤1.5k × 350 | ≤0.5M | 0.08 | — |
| first-touch inserts (journal + `State`) — not repeat work | (1,464+2,844) × 1.5k | 6.5M | 1.1 | presize (§5 L4) |
| **first-touch proof cost, once per node/key (reference)** | 40k perms + validate + walk | ≈115M | 19 | trusted digests / cross-block only |

Model total ≈ 25–35M of repeat work (4–6%). Measured bounds (wave-4 tree, exec phase): journal/state
bookkeeping 31.6M, plus the maps/foldhash share of the 14.8M "rest" bucket; `hash_bytes_long` is
its own symbol, so its pool was never inside the memo or journal figures.

## 5. Levers ranked (781 rows saved; soundness; effort)

| # | lever | saving | soundness | effort |
|---|---|---:|---|---|
| L1 | **word-gather `load()` in vendored foldhash** (20-byte key: 4 loads, 32-byte key: 8 loads; each `read_unaligned::<u64>` = 8 `lbu` + 14 ALU ≈ 46 rows → 2 aligned `ld` + 3 ALU ≈ 8): ≈31k Address hashes × 150 + ≈24k U256 hashes × 300 + ≈16k B256 hashes × 300 ≈ 17M model, capped by the measured buckets | −8…−15M (1.3–2.5%) | none: pure hasher; guest-only patch (native keeps upstream); determinism: same patched crate in both ELFs (L5 holds) | 1 day: `crates/vendor/foldhash/src/lib.rs:263-271` + parity test; measure `hash_bytes_long` rows before/after |
| L2 | vendored hashbrown: `Group::load` word-gather (`control/group/generic.rs:72`), aligned ctrl mirror store | −40/probe × ~60k probes ≈ −2.5M | none | 1–2 days (new vendor crate, version resolved by the guest lock) |
| L3 | flat word-keyed maps replacing `EvmState`/`EvmStorage`/`CacheState` hashbrown (revm-state aliases + revm-context + revm-database vendored) | −9…−14M after L1/L2 diminishing | none, but a large vendored surface (`Entry` API, iteration order used by `finalize`) | 1–2 weeks; do only if L1+L2 measure short |
| L4 | presize: `CacheState::accounts/contracts` via `with_cached_prestate(CacheState{..with_capacity})` (no vendoring), journal `state` map reuse across `finalize` (vendored revm-context) | −0.5…−1M | none | hours / 1 day |
| L5 | `storage()` walk: (root, nib0) memo per trie in `LastRead`, skip header re-decode on validated entries, 16-bit child mask instead of the skip loop (`storage-walk-analysis.md` #2, #5) | −1.5…−2M | derived from authenticated bytes only | 1–2 days |
| L6 | relax INV-W6 (`validate_at` once per node → kind classification only) | −5.2M (0.9%) | policy: accepts malformed-but-correctly-hashed nodes; unreachable on mainnet; native gate runs the same code | 1 day + owner sign-off (not a warm-state lever) |
| L7 | sound trims of the per-tx commit: `CacheAccount::change` without `previous_info` clone when status unchanged, `TransitionState` merge without re-hash | ≤1M | none | 1 day (vendored revm-database) |
| L8 | `State::code_by_hash` per (tx, untouched account) → keep `Bytecode` in `CacheAccount` on first load | ≤0.5M | none | vendored revm-database |
| — | verified flat map after one MPT walk; bytecode analysis dedupe; block-level `finalize` | 0 / 0 / killed | — | — |

## 6. Cross-block warm state (design note, no code)

- **Multi-block guest (blocks N..N+k in one proof):** sound. Keep the `WitnessResolver`
  memo + the materialized state trie across blocks; header(N+1).parent_hash → header(N) and
  pre_root(N+1) = computed post_root(N) give root continuity, so every node known in-guest
  (N's witness entries with `verified` set, and N's dirty nodes hashed at post-root) needs no
  keccak in N+1's reveal. Saving = overlap of N+1's node set with N's known set: lower bound
  2–13% of N+1's witness (§3c), plus the re-touched dirty paths (unmeasured). Costs: peak heap
  grows per block (bump allocator never frees: 1.5 GiB cap), per-block advice tapes must be
  concatenated in call order, and the state trie must stay mutable-in-place (Phase 2 measured
  lazy state tries +26M on write-heavy blocks — a continuing trie is eager for known nodes and
  lazy only for new ones, which is the favourable mix). Break-even only if witness overlap
  ≥ ~15% of reveal perms; today's consecutive overlap says no on this ten-block window.
- **Persisted verified state across separate proofs:** the second proof must trust a digest
  set the first proof produced. Without recursion that is exactly the `--trusted-digests`
  statement ("valid GIVEN this digest map", `zeth_trie.rs:33-48`); with recursive
  verification of proof N inside N+1 it becomes sound but the reveal saving is the same
  2–13% overlap. Not worth a statement change.
- **Cross-block code reuse** already exists: the committed code library (406/468 code loads
  on 781 pre-analyzed, zero keccak, zero analysis).

## 7. Recommended top lever: L1 — word-wise byte hashing in the vendored foldhash

Facts (code + disassembly): `Address`/`B256` are `FixedBytes<N>` with derived `Hash` →
`[u8; N]::hash` → `u8::hash_slice` → one `Hasher::write(&[u8])`; `U256` derives `Hash` on
`limbs: [u64; 4]` → `u64::hash_slice` → one `write(&[u8; 32])` (core `impl_write!`). Both reach
`foldhash::fast::FoldHasher::write` (`crates/vendor/foldhash/src/fast.rs:52-65`) → `len > 16`
→ `hash_bytes_long` (`lib.rs:279`, `#[cold] #[inline(never)]`) → four `load()` calls for
17..31 bytes, eight for 32 (`lib.rs:270`, `read_unaligned::<u64>`). In the current pertx guest
ELF the function is 1,081 instructions: 288 `lbu`, 252 `slli`, 252 `or`, 86 `ld`, 80 `sd` — every
`load()` is 8 `lbu` (4 rows each) + 7 `slli` + 7 `or` ≈ 46 rows, plus a 13-register prologue/
epilogue per call. The `write_u64` sponge path is only taken by integer keys (`u64`, `usize`). Every Address-keyed map
(journal `state`, `CacheState::accounts`, `warm_addresses.access_list`, `TransitionState`,
`BundleState`) and every B256-keyed map (`storage_roots`, `contracts`, `HashedPostState`
accounts/storages, receipt topic memo, `CodeMap::Eager`) pays it on each probe and insert.

Sketch:
1. `crates/vendor/foldhash/src/lib.rs`: replace `load(bytes, offset)` with a containing-word
   gather under `#[cfg(target_arch = "riscv64")]`: `p = ptr + offset`, `a = p & !7`, read
   `w0 = *(a as *const u64)`, `w1 = *((a + 8) as *const u64)` via `read_volatile`, shift =
   `(p & 7) * 8`, value `= (w0 >> shift) | (w1 << (64 - shift))` (shift 0 special-cased).
   Same argument as `crates/guest/src/mem.rs` (flat word-granular RAM, 8-aligned region
   starts): the over-read stays inside mapped memory. Native keeps `read_unaligned`.
2. `hash_bytes_short` (≤16 bytes) uses `from_ne_bytes` on slices — same lowering; apply the
   gather to its two 8-byte reads (`u32`/`u8` tails untouched). Rare keys here (`B64`, `u128`).
   The prologue/epilogue (26 rows per call) goes with `#[inline(never)]`; keep it unless the
   measured pool says the call overhead matters.
3. Optional in the same lane: L2 `Group::load` in a vendored hashbrown (`[patch.crates-io]`
   in `crates/guest/Cargo.toml`, version from `cargo tree -i hashbrown` there).
4. Tests: vendored foldhash `hash(&[u8;20])`/`(&[u8;32])` equal between the gather and the
   byte path at all 8 source alignments (host-side test with an aligned buffer window);
   guest `native-tests` differential like the keccak shim.

Gates: block hash `0xf691…b529` and the ten-block hashes exact (`run-native` and `trace`);
keccak census exact (`calls=44511 bytes=13335528 perms=115373` on 781 — hashing changes touch
no keccak); native/guest parity by construction (native unpatched); rows before/after on
781/782/785/789 with `jeth profile --rows` attributing `foldhash::hash_bytes_long`
(measure first: the symbol is out of line, so its pool is directly readable; model 10–17M
on 781, expected saving −8…−15M); no `unsafe` beyond the two `read_volatile` word reads with a SAFETY comment; clippy
`-D warnings`, fmt, typos. Abort if the measured `hash_bytes_long` pool is < 3M.

## 8. Reproduce

```sh
cd ~/dev/jeth.jeth-warm-state-census
CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-warm-state-plan cargo build --release -p jeth-host --features secp-inline
J=/Volumes/Dev/cargo-target/jeth-warm-state-plan/release/jeth
for b in 25905781 25905782 25905785 25905789; do
  $J touches --input /Volumes/Dev/jeth-inputs/$b/input.bin --json /tmp/touches-$b.json --dump-digests /tmp/digests-$b.txt
  $J run-native --input /Volumes/Dev/jeth-inputs/$b/input.bin
done
comm -12 /tmp/digests-25905781.txt /tmp/digests-25905782.txt | wc -l   # shared witness nodes
```

`jeth touches` (host-only, `jeth-core` feature `census`, never in the guest ELF) runs the
vendored validation loop with a counting `WitnessDatabase` wrapper, the per-tx `EvmState`
returned by `execute_transaction_without_commit`, and a `step`/`initialize_interp` inspector;
it checks receipts/bloom/gas and the post-state root like the proven path.
