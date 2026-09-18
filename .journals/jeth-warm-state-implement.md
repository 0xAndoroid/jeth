# jeth-warm-state · implement b/2 — warm-state levers landed (2026-09-18)

Tree `jeth-warm-state` = origin/main `cc29bea` + journals + `jeth touches` (`ae46f75`); Jolt pin
`jolt-amber-nolane`. Rows = plain `jeth trace` (SELF); the baseline re-run on 781 reproduced
`601,659,728` exactly. Gates on every run: `trace` block hash == `run-native` == `trace-summary.json`,
keccak census unchanged (781 `calls=44511 bytes=13335528 perms=115373`; perms 782 124,117 · 785
121,623 · 789 133,642), `cargo clippy --all --all-targets -D warnings`, `cargo nextest … --workspace`
(24 tests), the vendored crates' gather tests (foldhash, alloy-primitives `--features map`,
hashbrown). Raw logs/JSON: `/Volumes/Dev/tmp/jeth-warm-state/impl/` (`symdelta.py` = per-symbol diff
of two `profile --split-markers --json` files).

## 1. Result — three guest-side levers, −1.25% over the 4 blocks, no semantic change

| block | baseline | A' `763073a` | +B `8696d18` | +C (hashbrown) | Δ total | c/g |
|---|---:|---:|---:|---:|---:|---:|
| 25905781 | 601,659,728 | 599,666,112 (−1.99M, −0.33%) | 598,350,340 (−1.32M, −0.22%) | 594,757,274 (−3.59M, −0.60%) | −6,902,454 (−1.15%) | 13.605 → 13.448 |
| 25905782 | 720,626,001 | 717,803,769 (−2.82M, −0.39%) | 715,228,243 (−2.58M, −0.36%) | 711,709,284 (−3.52M, −0.49%) | −8,916,717 (−1.24%) | 15.311 → 15.122 |
| 25905785 | 628,266,867 | 625,725,916 (−2.54M, −0.40%) | 623,475,549 (−2.25M, −0.36%) | 619,948,197 (−3.53M, −0.57%) | −8,318,670 (−1.32%) | 13.268 → 13.092 |
| 25905789 | 675,886,779 | 673,272,096 (−2.61M, −0.39%) | 670,678,631 (−2.59M, −0.39%) | 667,152,461 (−3.53M, −0.53%) | −8,734,318 (−1.29%) | 15.152 → 14.956 |
| 4-block c/g (gas 183,253,432) | 14.332 | 14.278 (−0.38%) | 14.230 (−0.33%) | 14.153 (−0.54%) | −32,872,159 (−1.25%) | |

Block hashes on all 12 traced runs == native: 781 `0xf691…b529` · 782 `0x9331…b185` · 785
`0x2567…a155` · 789 `0xbb17…7913`. All three steps are riscv64-only codegen changes (native keeps
the upstream crates; hash values and map contents are identical by construction) — the block-hash
gate cannot see a hashing bug, which is why each gather has a host differential test at all 8
source alignments.

## 2. Step A — word-gather key hashing (`763073a`)

Where the byte-wise hashing really was: `FbHasher::write` → `write_bytes_unrolled` →
`usize::from_ne_bytes(*chunk)` (alloy-primitives 1.6.1 `map/fixed.rs`) for every `Address`/`B256`/
`U256` key — all revm and jeth maps are `Fb*Map`s — plus the generic `foldhash::hash_bytes_long`
(`load()` = `read_unaligned`, only 0.44M rows). Both now gather each 8-byte (and the Address 4-byte
tail) chunk from the containing aligned word(s) under `cfg(target_arch = "riscv64")` (`gather::
load_le`, volatile, `crates/guest/src/mem.rs` argument). Vendored copies: `crates/vendor/
alloy-primitives` (1.6.1, only `src/map/fixed.rs` changed, `[patch.crates-io]` in the guest
workspace only) and the existing `crates/vendor/foldhash`.

First attempt (gather only, upstream `#[inline]` on `write`) **lost** on 781: 601,659,728 →
603,109,567 (+1.45M). `jeth opcodes`: LBU/u −400,676 execs (−1.60M rows — the whole byte-wise pool
that existed), but LD +0.74M, SD +0.50M, SB +0.54M, ALU-I +0.60M, BRANCH +0.27M rows. The profile
showed why: a new out-of-line `<FbHasher<32> as Hasher>::write` (1.69M rows) — the bigger body
stopped inlining, every U256/B256 hash paid a call + spills, and known-aligned callers (LLVM already
emitted plain `ld`s for `[u64; 4]` keys) lost that fold. The plan's model (8 `lbu` per word
everywhere, −8…−15M) only held for alignment-unknown sites.

Fix (A'): `#[inline(always)]` on `FbHasher::write`; inlined, known-aligned callers fold the gather
back to one `ld`. Symbol deltas on 781 (pertx build, 602,851,522 → 600,857,906): every
`reserve_rehash` instance fell — `(U256,U256)` −669k, `(U256,EvmStorageSlot)` −577k, `(B256,B256)`
−324k, `(U256,StorageSlot)` −263k, `(U256,RevertToSlot)` −228k, `(Address,TransitionAccount)` −198k,
`(Address,Account)` −189k, `(Address,CacheAccount)` −176k, `(B256,Bytecode)` −167k (Σ ≈ −2.3M);
`IndexMap<B256,[u64;4]>::get` −312k, `foldhash::hash_bytes_long` −326k (443k → 118k), memcpy −826k,
`receipt_root_bloom` −566k, `PrecompilesMap::get` −293k, `apply_account_state` −205k,
`CacheAccount::change` −177k. Inlining moved rows between symbols (`Context::sload/sstore_skip_
cold_load` −3.1M → `HashMap<Address,Account>` +2.2M, `host::sload` +1.4M, `JournaledAccount` +1.0M,
`transfer_loaded` −0.8M); the journal/State bucket is roughly flat — the saving is in the
rehash/memo/topic sites where the key pointer had no provable alignment.

## 3. Step B — presize jeth-owned maps (`8696d18`, no vendoring)

| map | bound | 781 entries | `reserve_rehash` rows on 781 (A' → +B) |
|---|---|---:|---:|
| `CacheState::accounts` via `State::builder().with_cached_prestate` | `witness.state.len()` = 19,448 (≥ state-trie leaves) | 1,469 | 242,790 → 0 |
| `SparseState::storage_roots` (IndexMap) | same | 1,469 | 389,424 → 0 (`RawTable<usize>`) |
| receipts topic memo `(B256,B256)` | Σ topics over all logs | distinct topics | 244,957 → 0 |

All three ≥ 100k → kept. Not presized: `CacheState::contracts` (`(B256,Bytecode)` rehash 127k after
A'; the bound needs the code-library size), `SparseState::storages` (≤ written accounts, no
measurable `RawTable<usize>` residue), `CodeMap::Eager` (exact via `collect`). Side effects on 781:
memcpy −275k, memset +12k (ctrl bytes of the 32k-bucket tables), `receipt_root_bloom` −54k; total
−1,311,404 (pertx) / −1,315,772 (plain). The bound is 13× the final size on 781; hashbrown only
pays for it in ctrl memset (∝ buckets), the bucket array is bump-allocated and never touched.

## 4. Step C — vendored hashbrown 0.17.1, `Group::load` gather

Every probe (`find`, `find_insert_index`, `reserve_rehash`) starts with `Group::load(ctrl(pos))` =
`ptr::read_unaligned::<u64>` at an arbitrary ctrl byte → 8 `lbu` + shifts on riscv64. Vendored
`crates/vendor/hashbrown` (0.17.1 = the line alloy-primitives and indexmap resolve to; arkworks'
0.15.5 stays upstream): `control/group/generic.rs::load` → `load_gathered` (in `group/mod.rs`,
outside the `cfg_if!` impl switch so the host test compiles — aarch64 selects the NEON group and
never builds `generic.rs`). Same gather, same mem.rs argument; the ctrl array's `Group::WIDTH`
trailing mirror bytes keep the 8 loaded bytes live. Rows −3.59M/−3.52M/−3.53M/−3.53M (−0.49…−0.60%),
gate ≥ 1M/block met. Symbol deltas on 781 (+B → +C, pertx): `JournaledAccount` −562k,
`HashMap<Address,Account>` −500k, `RawTable<(U256,U256)>` −381k/−121k, `JournalInner::load_account`
−323k, `State` −226k, `receipt_root_bloom` −154k, `PrecompilesMap::get` −123k, `(U256,EvmStorageSlot)`
−105k, `BundleAccount::update_and_create_revert` −106k, `apply_transitions_and_create_reverts` −85k,
`hashed_post_state` −82k, `find_insert_index` −85k; memmove +109k.

## 5. What is left

- Warm-path bookkeeping (bucket b of the measure journal, ≈39M on 781) is now ≈32M; the rest is
  revm's journal/State logic itself (L3 flat maps, L7 commit trims — vendored revm-context/-database).
- Untouched byte-wise sites: `hash_bytes_short`'s 4-byte reads (rare keys), `memcmp`-style key
  equality (`Address`/`B256` `PartialEq` compiles to word compares already).
- `_typos.toml` excludes the two new vendored crates (upstream hex test vectors).

## 6. Reproduce

```sh
export CARGO_TARGET_DIR=/Volumes/Dev/cargo-target/jeth-warm-state JOLT_PATH=/Volumes/Dev/cargo-target/jolt-cli-amber-nolane/release/jolt
cargo build --release -p jeth-host --features secp-inline; J=$CARGO_TARGET_DIR/release/jeth; IN=/Volumes/Dev/jeth-inputs
$J trace --input $IN/25905781/input.bin                      # rebuilds the ELF pair
for b in 25905782 25905785 25905789; do $J trace --input $IN/$b/input.bin --skip-build; done
for b in 25905781 25905782 25905785 25905789; do $J run-native --input $IN/$b/input.bin; done
$J profile --rows --input $IN/25905781/input.bin --top 60
$J profile --rows --split-markers --input $IN/25905781/input.bin --json after.json
uv run python /Volumes/Dev/tmp/jeth-warm-state/impl/symdelta.py before.json after.json --top 40
$J opcodes --input $IN/25905781/input.bin --skip-build --symbols-for LBU,LD
(cd crates/vendor/foldhash && cargo nextest run --cargo-quiet)   # same in alloy-primitives (--features map) and hashbrown
```
