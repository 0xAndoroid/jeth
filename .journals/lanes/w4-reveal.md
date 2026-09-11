# Wave 4 reveal/hash reuse — 2026-09-04

**KILL all tested memos; docs-only handoff.** Node pool: **3 / 0 / 2 perms** on
25905781 / 25905786 / 25905789 (gate: 4,000 on 781). Best runtime candidate,
bloom-only, saves **3.611M rows on 781**, below its separate 5M floor.
Audit verdict: **already-optimal for unchanged-subtree digest reuse**.
Base `85ce0d0`; SELF only; Jolt pin `628713fd4` stayed frozen. No trusted runs.

## Measured decisions

| Candidate | 781 rows | Saved vs 938,512,897 | Saved perms | Verdict |
|---|---:|---:|---:|---|
| Generic EVM64 hasher + topics | 936,916,707 | 1,596,190 | 4,706 | KILL <8M |
| Fixed-byte EVM64 hasher + topics | 936,121,869 | 2,391,028 | 4,706 | KILL <8M |
| Topics only | 934,901,508 | 3,611,389 | 1,922 | KILL <5M |

Bloom-only SELF ledger; block hash/gas match native and baseline **3/3**:

| Block | Base rows | Bloom rows | Saved rows | Perms before → after | Delta = topic hits |
|---|---:|---:|---:|---:|---:|
| 781 | 938,512,897 | 934,901,508 | 3,611,389 | 121,206 → 119,284 | 1,922 |
| 786 | 461,937,742 | 461,031,064 | 906,678 | 61,356 → 60,754 | 602 |
| 789 | 1,086,513,295 | 1,084,695,846 | 1,817,449 | 140,584 → 138,611 | 1,973 |

No block regresses, but 781 misses the keep floor. EVM64's marginal cost over
bloom-only is **+2.015M rows** (generic) / **+1.220M** (fixed-byte), despite
2,784 fewer hash permutations. No memo, helper, test, host-path override, or
Cargo patch retained. Only this journal is committed; no push/merge.

## Preimage census

Full-byte `HashMap<Vec<u8>, …>` behind native `native_keccak256`, the same one-shot
hook used by the guest; every input ≥32 bytes recorded with phase/site tags.
`perms = len / 136 + 1 = ceil((len + 1) / 136)`; exact bytes determine equality.
Native/pass-1 resolver-index construction recorded separately and excluded:
54,925 / 27,449 / 59,261 perms. Address hashes (20 bytes) excluded from the
duplicate census/pool; native/SELF accounting uses all-length counters.
Vendored guest-equivalent validation used the committed-code-library input;
normal upstream native validation independently matched block hash and gas 3/3.

“Node-scale” below means **≥32-byte preimages**, not exclusively trie nodes.
Dup hits = calls minus unique byte strings within a phase. Perm columns weight
multi-permutation inputs. Gross row-equivalent is **not a measured net saving**:
duplicate perms × measured wave-2 whole-run native-keccak rows/perm
(781: 3,167.722; 786: 3,187.647; unchanged hash implementation); 789 uses the new phase profile.
Sources: `/tmp/jeth-w2/{781,786}-flat.log`, `.journals/lanes/w2-profile.md` in campaign-2x.

| Block | Phase | Hashes | Unique | Dup hits | Perms total / unique | Dup perms | Gross M rows |
|---|---|---:|---:|---:|---:|---:|---:|
| 781 | witness_reveal | 8,711 | 8,711 | 0 | 31,032 / 31,032 | 0 | 0.000 |
| 781 | execution | 19,852 | 15,820 | 4,032 | 38,885 / 34,777 | 4,108 | 13.013 |
| 781 | post_root | 11,502 | 11,502 | 0 | 32,905 / 32,905 | 0 | 0.000 |
| 781 | receipts | 3,541 | 1,619 | 1,922 | 6,034 / 4,112 | 1,922 | 6.088 |
| 781 | tx_root | 485 | 485 | 0 | 3,003 / 3,003 | 0 | 0.000 |
| 781 | poststate_keys | 1,257 | 1,111 | 146 | 1,257 / 1,111 | 146 | 0.462 |
| 786 | witness_reveal | 4,882 | 4,882 | 0 | 17,707 / 17,707 | 0 | 0.000 |
| 786 | execution | 8,592 | 6,871 | 1,721 | 17,700 / 15,954 | 1,746 | 5.566 |
| 786 | post_root | 5,465 | 5,465 | 0 | 16,126 / 16,126 | 0 | 0.000 |
| 786 | receipts | 1,315 | 713 | 602 | 2,588 / 1,986 | 602 | 1.919 |
| 786 | tx_root | 282 | 282 | 0 | 2,125 / 2,125 | 0 | 0.000 |
| 786 | poststate_keys | 487 | 415 | 72 | 487 / 415 | 72 | 0.230 |
| 789 | witness_reveal | 14,765 | 14,765 | 0 | 48,575 / 48,575 | 0 | 0.000 |
| 789 | execution | 10,843 | 8,182 | 2,661 | 21,156 / 18,345 | 2,811 | 8.794 |
| 789 | post_root | 16,825 | 16,824 | 1 | 49,385 / 49,384 | 1 | 0.003 |
| 789 | receipts | 4,817 | 2,844 | 1,973 | 7,709 / 5,736 | 1,973 | 6.173 |
| 789 | tx_root | 369 | 369 | 0 | 2,786 / 2,786 | 0 | 0.000 |
| 789 | poststate_keys | 680 | 609 | 71 | 680 / 609 | 71 | 0.222 |

### Actual trie-node pool

| Site | 781 hashes / perms | 786 hashes / perms | 789 hashes / perms |
|---|---:|---:|---:|
| Reveal resolver | 8,649 / 26,020 | 4,843 / 14,732 | 14,697 / 43,707 |
| Execution resolver | 10,769 / 28,875 | 4,615 / 12,688 | 5,657 / 15,528 |
| Post-root resolver | 28 / 28 | 28 / 28 | 25 / 25 |
| Post-root encoding/hash | 11,474 / 32,877 | 5,437 / 16,098 | 16,800 / 49,360 |
| Code misses (not nodes) | 62 / 5,012 | 39 / 2,975 | 68 / 4,868 |

All resolver rows and code-miss rows have zero intra-site duplicates. Post-root
encoding has 0 / 0 / 1 intra-phase duplicate permutations. Union of resolver and
MPT-encoder preimages gives **3 / 0 / 2 avoidable perms**, including cross-phase reuse.
The 781 gross bound is ~9,503 rows (0.0095M), before lookup/allocation/byte-compare
costs; 1,333× below the implementation gate. The ≥8M net-row gate is unreachable.

### Cross-phase reuse

Each cell: distinct shared preimages / later calls / later permutations.
Pairs overlap and must not be added together.

| Earlier → later | 781 | 786 | 789 |
|---|---:|---:|---:|
| Reveal → post-root | 0 / 0 / 0 | 0 / 0 / 0 | 0 / 0 / 0 |
| Execution resolver → post-root encoder | 3 / 3 / 3 | 0 / 0 / 0 | 1 / 2 / 2 |
| Reveal → execution (non-node callers) | 0 / 0 / 0 | 0 / 0 / 0 | 3 / 3 / 8 |
| Execution → poststate keys | 1,105 / 1,251 / 1,251 | 415 / 487 / 487 | 608 / 679 / 679 |
| Execution → receipts | 3 / 45 / 45 | 2 / 18 / 18 | 3 / 22 / 22 |
| Receipts → poststate keys | 2 / 36 / 36 | 2 / 23 / 23 | 3 / 23 / 23 |
| Signature → execution | 8 / 11 / 11 | 1 / 1 / 1 | 2 / 2 / 2 |
| Signature → final header | 1 / 1 / 5 | 1 / 1 / 5 | 1 / 1 / 5 |

**Post-root unchanged-byte re-encode/hash count: 3 / 0 / 2 calls**, all single-perm,
measured against *every original witness preimage*, including witness entries not
yet verified. These equal the verified-witness intersections too. This measures
byte identity, not identity of logical trie position; it is an upper bound on a
same-node/no-op fix. 789 has one original leaf encoding produced twice.

Execution repeats are keys/EVM inputs, not repeated witness-node hashing. Receipt
repeats are 32-byte bloom topics: e.g. Transfer topic occurs 690 / 210 / 345 times.
No receipt preimage >32 bytes repeats on this set. These are separate optimization
classes; no all-call global hash memo attempted.

## Post-root audit

```text
SparseState::calculate_state_root
  no storage writes → stored storage_root                 ← zeth_trie.rs:324
  written storage → digest-root trie, resolve dirty paths ← zeth_trie.rs:355
    resolve_stub → cache_set(from_digest(digest))          ← node.rs:299
  state_trie.insert(account)                              ← zeth_trie.rs:388
  CachedTrie::hash → memoize_arena → inner.hash            ← mpt/mod.rs:354
    cache present / Digest / Null → return                ← mpt/rlp.rs:181
    otherwise recurse, encode once, cache resulting ref   ← mpt/rlp.rs:192
```

Paths are `crates/core/src/zeth_trie.rs` and
`crates/vendor/zeth-mpt/src/mpt/{node.rs,mod.rs,rlp.rs}`.
Eager state reveal also seeds each decoded node's authenticated reference:
`rlp.rs:404–415` (`resolve_with` → `cache_set(RlpNode::from_digest)`).
Child serialization reads that cache (`rlp.rs:661–669`); unchanged children do not
get re-encoded or re-hashed. The resolver separately memoizes each witness slot
(`crates/core/src/resolver.rs:121–130`).

Same-value inserts still clear leaf and ancestor caches (`node.rs:109–113`,
`node.rs:143–147`, `node.rs:177–180`); root cache is cleared by every insert
(`mpt/mod.rs:280–282`). That is a possible redundancy, not a material measured pool.
**Verdict: already-optimal for this target; no cheap ≥4,000-perm reuse fix present.**

## Block 25905789

Base SELF profile: **1,087,254,325 rows**, 24.373 c/g; per-tx markers add
741,030 rows (0.068%) against the uninstrumented 1,086,513,295-row baseline.

| Phase | Rows | Share | c/g |
|---|---:|---:|---:|
| Reveal | 323,244,574 | 29.73% | 7.246 |
| Execution (tx spans) | 369,463,521 | 33.98% | 8.282 |
| Post-root | 255,066,303 | 23.46% | 5.718 |
| Outside phase markers | 139,479,927 | 12.83% | 3.127 |

- **Trie-heavy:** reveal + post-root = 53.19% of rows; 43,707 reveal-node perms
  versus 26,020 on 781, and 49,385 post-root perms versus 32,905, at similar gas.
- **Execution is 33.98%:** 369.464M rows; its 23,767 native execution permutations
  are lower than 781's 40,426, so execution hashing does not explain the excess.
- **Code misses are secondary:** 68 misses / 4,868 perms, ~15.2M gross hash rows
  (~1.4% of total); 77.35% library coverage looks poor but its miss pool is smaller
  than 781's 5,012 perms. No 789-specific fix attempted.

789 native-keccak attribution = 439,824,404 rows / 140,584 perms = 3,128.552
rows/perm, including shim work but excluding callees such as memcpy.

## Tested implementation and checks

- EVM64: exact aligned `[u64;8]` keys in each reusable Interpreter frame;
  KECCAK256 opcode only, other lengths direct, no globals/advice. Compared default
  hasher with `FbBuildHasher<64>`; integer-array length prefix is ignored by that
  hasher, full-key equality unchanged. Both versions passed **16/16 nextest** tests.
- Topics: block-local exact `B256Map` → `m3_2048_hashed`; receipt-root/bloom pair
  passed through the existing consensus-validation argument. Address hashing
  unchanged. Bloom-only passed **15/15 nextest** tests, including randomized
  receipt-root/bloom equality; SELF + native parity and exact perm accounting **3/3**.
- Native workspace temporarily used the guest's vendored revm-interpreter for
  opcode-memo measurement and randomized opcode equality (128 preimages, repeated
  calls, aligned/unaligned offsets, cached/uncached lengths). All probes removed
  before guest gates. Native vendor patch and prototype tests removed after kill.

| Block | EVM64 hits | Topic hits | Native perms before / after | Delta = hits |
|---|---:|---:|---:|---:|
| 781 | 2,784 | 1,922 | 119,797 / 115,091 | 4,706 |
| 786 | 1,060 | 602 | 60,611 / 58,949 | 1,662 |
| 789 | 1,888 | 1,973 | 139,646 / 135,785 | 3,861 |

Native totals exclude the pass-1 index; native signature recovery omits the guest
batch's extra hashes. Both combined SELF variants reduce 781 by exactly 4,706
perms. Per-frame cache captures 2,784 of 3,156 global EVM64 repeats on 781;
sharing cache state across frame interfaces was not attempted.

## Reproduction

Raw evidence `/tmp/jeth-w4-reveal/`: `{block}-dup.json`, `dup-summary.txt`,
`{block}-{probe,native}.log`, `789-{profile.log,markers.json}`;
`{block}-candidate-{dup.json,probe.log}`; `25905781-candidate-{a,fx}-self.log`;
`{block}-bloom-{self,native}.log`, `nextest-{candidate,fx,bloom}.log`.
Source snapshots: `candidate-{a,fx}.patch`, `bloom-candidate.patch` (development
only, not committed). Original probe: `probe.patch`, `probe.rs`, `analyze.py`;
combined probe: `candidate-probe.patch`, `candidate-probe.rs`. Apply the chosen
probe patch to base `85ce0d0`, copy its host module into `crates/host/src/probe.rs`,
build host `--release --features probe`, set `JETH_PROBE_OUT`, run `run-native`.

Cargo/jolt builds acquired `/tmp/jeth-w3-cargo.lock`; owner marker added
when adopted campaign-wide. Host target `/Volumes/Dev/cargo-target/jeth-w4-reveal`,
private guest target suffix `-guest`; later traces use `--skip-build` without the
lock. Lock contention/ownership-race and native-vendor mismatch logged with
`papercuts --source jeth-w4-reveal --tag jeth`. Input SHA-256 checks passed 3/3.
Docs-only commit skips Rust hook commands; production source is exactly the base.
