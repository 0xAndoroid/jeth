# #9 "Children slot layout" — re-derived on current code

jeth opt-amber @ 83cdf44 (+wave K), block 25905781 = 628,003,872 rows. All asm from
/Volumes/Dev/cargo-target/opt-amber-guest-validate_block/riscv64imac-unknown-none-elf/release/jeth-guest
(built 06:33), dumps in /tmp/mpt9/asm/. Row weights: 1/instr; LBU 3, LB 4, LW 4, SW 7.

## 1. Current representation

| item | fact | where |
|---|---|---|
| `Children<M>` | `[Option<Box<Node<M>>>; 16]` — 16 × 8 B = 128 B, align 8; every child (digest stub, decoded node, embedded <32 B node) is its own `Box<Node>` | children.rs:41-43, node.rs:60 |
| `Node<M>` | `Null \| Leaf(Nibbles 40 B, Bytes 32 B, M) \| Extension(Nibbles, Box, M) \| Branch(Children 128 B, M) \| Digest(Digest 32 B align 8)` | node.rs:108-115, 66-68 |
| size | `Node<Cache>` = 176 B (0xb0), align 8 — `li a1,8; li a2,0xb0` before every child alloc | asm decode_node_zc_into +0x390 |
| layout (asm) | tag u32 @0 (0 Null, 1 Leaf, 2 Ext, 3 Branch, 4 Digest); `Cache = Option<RlpNode>` = `Option<ArrayVec<u8,33>>` @4..48 (Option disc u32 @4, len u32 @8, bytes @12..45; 44 B); children @48..176; Digest words @8..40; Extension child Box @88 | resolve_with asm 0x8004ba78-0x8004bb12; arrayvec-0.7.8 lib.rs:32 (`LenUint = u32`) |
| digest child | a 176-B box holding a 33-B payload: 143 B dead per stub; 145.4k stubs on 781 = 25.6 MB of the ~58 MiB peak | §2 counts |
| zero-fill per branch decode | one `sd 3` (tag + cache None) + `memset(children,0,128)` → 48 rows in memset (aligned path: 9+3+3+1+4×7+2+1+1) + 10 rows call glue | rlp.rs:838; asm 0x8005f7c0-0x8005f7da; memset asm 0x8011b286-0x8011b380 |
| encode_dirty iteration | `memoize_arena`: `iter_mut().flatten()` + `needs_memo()` → LLVM unrolled 16 slots: `ld ptr; beqz; lw tag; addi; li; bltu [; lw cache; bnez]` = 9 rows per digest slot, 2 per empty; write pass `children.iter()` → loop stride 8 B: `add; ld; beqz; lw tag; addi; bgeu` + `write_child_ref` (aligned-source `put_prefixed` ≈ 45 rows) + 4 tail | children.rs:189-194, rlp.rs:445, 467-476, 1123-1152; asm 0x8008e3ec-0x8008e5dc, 0x8008e662-0x8008e97c |
| resolve_with iteration | `children.entries()` → `Entry::Occupied` → recursive `resolve_with` per non-empty slot: 5 rows per empty slot; per digest child (miss): 6 call glue + 9 prologue + `lw tag` 4 + dispatch 5 + 6 (call `WitnessResolver::resolve`) + 3 + 10 epilogue + 8 return glue + 5 (`OccupiedEntry` Drop re-reads the tag) = 56 rows self | rlp.rs:656-662, children.rs:79-85; asm 0x8004bb52-0x8004bb96 |
| WitnessResolver::resolve | miss = 32 rows (13-register prologue/epilogue + ADVICE_LD + beqz); hit ≈ 80 | resolver.rs:217-227; asm 0x800bfb8a-0x800bfc50 |

## 2. Row model on the current code, reconciled with the profile

Census (`/tmp/alloc-audit/py/witness_stats.py data/25905781/witness.json`):
- state trie: 7,170 branch / 1,438 leaf / 41 ext; 93,341 digest children (84,693 misses, 8,648 hits); mean k = 13.0; 4,483 branches have k = 16.
- storage entries: 8,355 branch / 2,394 leaf / 50 ext; 98,036 digest children; mean k = 11.7.
- decoded branches = memset rows / 48 = 557,376 / 48 = **11,612 exactly** → state 7,170 (eager `from_resolver_zc`, mod.rs:433-440) + storage 4,442 (lazy, hydrated by `insert_with`/`remove_with` → `resolve_stub`, zeth_trie.rs:394-412). Digest children decoded ≈ 93,341 + 4,442 × 11.7 = **145.4k**. Allocs: 2,669,856 / 17 (bump_alloc::alloc body = 17 instrs, asm 0x8011bdd4) = 157k → 145k are digest-stub boxes.
- "≈40k decodes" does not hold: 11.6k branch + ≈2.6k leaf + ≈0.1k ext ≈ **14.3k node decodes**. "≈11.5k dirty encodes" is consistent (≈7k dirty branches + ≈4.5k dirty leaves).

decode_node_zc_into self, per branch with k digest children (asm path counts):
- frame + long-form header + pass-1 setup + memset call glue + epilogue ≈ 122 (130 with a 2-byte length; k = 16 payload = 529 B)
- pass 1 `count_items` (rlp.rs:978-985; asm 0x8005f6e4-0x8005f7ae): 14 rows per digest item, 12 per empty item
- pass 2 `decode_branch_children` (rlp.rs:991-1019; asm 0x8005f838-0x8005fa16): digest child = 16 (loop + `item_len`) + 6 (alloc glue) + 5 + 3 (`lbu`) + 2 + 9 (word gather) + 15 × 7/8 (misaligned funnel; witness digest offsets are uniform mod 8) + 14 (`sw` tag 7 + 4 `sd` + 3) + 7 (`children.insert`: slli/add/ld/beqz/sd/addi/j) ≈ **75**; empty item 10 (17th value item included)
- self ≈ 122 + 14k + 12(17−k) + 75k + 10(17−k) = **496 + 67k** → k = 13: 1,368; k = 16: 1,578. Outside self per digest child: alloc body 17; per branch: memset 48.
- Σ: state 7,170 × 496 + 67 × 93,341 = 9.81M; storage 4,442 × 496 + 67 × 52.1k = 5.69M; leaves ≈ 2.6k × ≈500 (compact-path byte loop `lbu/sb` 12 rows/byte × 28-32 B, asm 0x8005fc5a) ≈ 1.3M → **16.8M vs 18.26M measured** (−8%: storage k distribution taken from the whole storage entry set).

encode_dirty self per dirty branch (k = 13): check pass 9k + 2(16−k) = 123; advice + header ≈ 20; write pass 13 × 58 + 3 × 11 + 8 ≈ 795; `RlpNode::from_rlp` glue + frame ≈ 100 → ≈ **1,040** × ≈7k = 7.3M; dirty leaves ≈ 4.5k × ≈600 (encode_path_leaf smallvec + 2 × write_str_item) = 2.7M → ≈10M vs 12.65M (dirty set on 781 is likely > 11.5k; encode_path_leaf is inlined here).

resolve_with (state trie only): 84,693 × 56 + 8,648 hits × ≈120 (`decode_stub_in_place` glue + `cache_set(RlpNode::from_digest)` = 8 `lw` + 8 `sw` + memcpy(36) ≈ 130 rows, asm 0x8004bade-0x8004bb0c) + 7,170 × 80 (frame + 16 slot iterations) = 4.74 + 1.04 + 0.57 = **6.35M vs 6.17M** ✓. WitnessResolver::resolve: 84,693 × 32 + 8,648 × 80 = 3.40M vs 3.68M ✓.

## 3. #9 re-scoped

**Layout A (recommended)** — safe Rust, kind pinned by the enum tag:
```rust
#[repr(u64)]                      // 8-B tag → `sd`, never `sb`/`sw`
pub(super) enum Slot<M> { Empty, Digest(Digest), Node(Box<Node<M>>) }   // 40 B, align 8
pub(super) struct Children<M>([Slot<M>; 16]);                          // 640 B
```
`Node<Cache>` becomes 688 B (tag 4 + Cache 44 + 640). Digest children live inline; only decoded / embedded children are boxed (allocated at resolve time instead of decode time).

Layout B (parent's sketch: `[Digest;16]` + u16 kind mask + side `[Option<Box<Node>>;16]`/Vec): same 640-650 B, but the kind ↔ array invariant is hand-enforced and the digest array is either zero-filled (64 `sd`) or `MaybeUninit` (unsafe on every read). No row advantage over A → not recommended.
`DigestOff(u32 into source)` (original #9): saves the 24-row gather + 4 `sd` at decode, but re-gathers from a misaligned source at every dirty-branch child ref (≈91k × +15 = +1.4M), at every hit (14.3k × 24), and needs a live `source` handle per branch (a `Bytes` clone ≈ 20 rows × 11.6k, or a raw pointer into the leaked witness = UB in native tests). Net ≈ +0.9M at best → drop.

Rows removed / added (781):
| loop | change | per unit | units | Δ rows |
|---|---|---|---|---|
| decode pass 2, digest child | no `Box::new_uninit` (6 glue + 17 body + beqz + mv), `sw` tag 7 → `sd` 1, insert glue 7 → 2 | −36 | 145.4k | **−5.23M** |
| decode, per branch | memset(128) + glue 58 → 16 × `sd Slot::Empty` (16) | −42 | 11,612 | **−0.49M** |
| hits (resolve_with 8,648 + resolve_stub ≈5.6k) | Box alloc moves to resolve time | +25 | 14.3k | +0.36M |
| encode check pass | 9 per digest slot (ptr deref + `lw` tag) → 3 (`ld` tag + compare) | −6 | ≈91k | −0.55M |
| encode write pass | no ptr deref, `lw` tag 4 → `ld` 1 | −4 | ≈91k | −0.36M |
| insert_with / remove_with by-value `Node` moves (node.rs:224-230, 258-264, 317-321, 353-364) | 176 → 688 B move: 44 → 172 rows | +128 | ≈2-5k restructurings | +0.3…+0.7M (avoidable: build the split branch in place, see plan) |
| resolve_with per digest child | recursion avoidable (−45 × 84.7k = −3.8M) **but equally avoidable today** with a `Node::Digest` pre-check in the Branch arm — not credited to #9 | — | — | 0 |
| **net** | | | | **≈ −6.0M (−5…−7M), ≈ 0.95% of 781** |

Why not 12–16M any more: #1 (02b2e59) removed the recursive decode call + memcpy(32) per digest child (−21.6M), #2 (197f4bb) the PayloadView Vec, #5 (4db8cf2) the per-child memoize calls — the bulk of what the original #9 would have deleted.
Memory: trie heap 14.3k × 176 + 145.4k × 176 = 28.1 MB → 14.3k × 688 = 9.8 MB (**−18 MB**; peak ≈58 → ≈40 MiB of 1.5 GiB).

Functions that must change (≈330-380 lines, all in crates/vendor/zeth-mpt/src/mpt/, no jeth-core change):
- children.rs (206 lines → ≈230, mostly rewritten): `Slot`, `Children([Slot;16])`, `Default` (16 × Empty), `PartialEq`, `Entry` (add a `Digest(&mut Slot)` arm or resolve before `entry()`), `VacantEntry::insert`, `OccupiedEntry::{get,get_mut}` + Drop (Null → `Slot::Empty`), `get`, `insert`, `len`, `take_single_child` (Digest slot → `Box::new(Node::Digest(d))`), `iter` (→ `&Slot`), `into_iter`, `entries`, `memoize_arena` (Node slots only), `From<[(u8,C);N]>`.
- node.rs: `get` 162-172 (Slot::Digest → panic "MPT: Unresolved node access", Empty → None) ≈10; `insert_with` 266-278 (Digest slot → resolve into a fresh Box, then recurse) ≈10; `remove_with` 328-370 ≈15; `size` 404-410 ≈5; fork note 100-106 rewrite.
- rlp.rs: `rlp_encoded` 351-364 ≈10; `encode_dirty` 445, 467-476 ≈10; `encoded_payload_length` 503-512 ≈8; `rlp_nodes` 528-536 ≈8; `resolve_digests` 607-613 ≈15; `resolve_with` 656-662 (Digest slot: `r.resolve` → `Box::new_uninit` + `decode_node_zc_exact_into` → `Slot::Node`, then `cache_set` + recurse; digest-for-digest → leave `Slot::Digest`) ≈25; `Decodable::decode` 741-757 ≈5; `decode_branch_children` 991-1019 + `decode_child_into` 1026-1037 + `write_digest_node` 1046-1049 (write `Slot::Digest(Digest::from_le_limbs(le_words_32(..)))` straight into `children.0[i]`; other items → `Box::new_uninit` + `decode_node_zc_into` → `Slot::Node`) ≈25; `write_child_ref` 1123-1152 + a `Slot`-level dispatch ≈10. `decode_stub_in_place` 706-727 stays (root only). `NodeRef` unchanged.
- mod.rs: `into_cached` 145-152 ≈10; tests keep `Children::from([(idx, child)…])`.

## 4. Risks and coverage

Soundness invariants:
1. Slot kind ↔ payload: pinned by the `Slot` enum tag (safe Rust); no mask/union. The only unsafe left in the decode path is the existing `Box<MaybeUninit<Node>>::assume_init` after an `Ok` (rlp.rs:859-863, 1005-1011 contract) and the root-only `&mut Node → &mut MaybeUninit<Node>` cast in `decode_stub_in_place`.
2. Digest stub vs embedded short node: `0xa0`+32 B item → `Slot::Digest`; an embedded list item (<32 B) → decoded into a Box → `Slot::Node` whose cached `RlpNode` has len < 33 → `write_child_ref` `put_raw` arm unchanged (rlp.rs:1136-1138); a 32-B string item can only be encoded with prefix 0xa0 (rlp.rs:33-36).
3. Post-root restructuring: `take_single_child` on a Digest slot must box it, then `resolve_stub` (node.rs:342-347) resolves or panics (INV-W3) as today; `insert_with`/`remove_with` reaching a Digest slot resolve first (mirror node.rs:279-282, 372-375); `OccupiedEntry` Drop sets `Slot::Empty` when the child became `Null` (children.rs:79-85 semantics).
4. In-place decode drop-safety: write the all-Empty branch first (16 `sd`), write `Slot::Digest`/`Slot::Node` only after the item is fully decoded — `out` is untouched or a valid node at every panic point (same contract as rlp.rs:806-809).
5. Codegen gate (rows, not soundness): `llvm-objdump` of `decode_node_zc_into` must show no memset/memcpy call in the branch arm, `Box::new_uninit` size 0x2b0, ≤ 60 rows on the digest-child path; `insert_with` should not grow a 688-B memcpy pair per split (build the split branch in place at node.rs:208-230 / 242-264 if it does).

Coverage: zeth-mpt 26 `#[test]` (24 run in wave I: `mpt_branch`, `insert`, `index_trie`, `keccak_trie`, `hash_sparse_mpt`, `parse_eth_get_proof_{existing,nonexisting}`, `zc_decode_matches_decodable_impl` (PartialEq over `Children`), `digest_fast_path_matches_generic_decode`, …) cover decode/insert/remove/collapse/encode parity natively; jeth nextest 19; `run-native` 10 blocks = bit-identical roots through real post-root hydration + collapses; trace 781 hash + keccak census must stay exact (calls=47504 bytes=13417708 perms=118366), only rows move.

## 5. Verdict

**BUILDABLE-IN-3H: yes** (single fable-max builder, gated), **but for ≈ −6M rows (≈1%), not 12–16M.** Cheaper items with a similar payoff should go first, each ≈10-20 lines and gated the same way:
- resolve_with Branch arm: `Node::Digest` pre-check + direct `r.resolve` (no recursive call per stub): −45 × 84.7k ≈ **−3.8M**.
- `WitnessResolver::resolve`: `#[inline(always)]` hint test + `#[cold]` verify/hit path (miss 32 → ≈6 rows): ≈ **−2.2M**.
- `cache_set(RlpNode::from_digest(..))` written in place (130 → ≈25 rows × 14.3k hits, resolve_with + resolve_stub): ≈ **−1.5M**.
Then #9 layout A if the residual ≈1% is still wanted (it also drops ≈18 MB of heap).

File-by-file plan for the #9 builder (3 h wall):
1. 0:00-0:15 — read the touch points above; write `Slot`/`Children` API in children.rs keeping method names (`get`, `entry`, `insert`, `len`, `take_single_child`, `iter`, `into_iter`, `entries`, `memoize_arena`, `From`).
2. 0:15-1:15 — children.rs + node.rs (`get`, `insert_with`, `remove_with`, `size`) + mod.rs `into_cached`; `cargo test -p zeth-mpt` green.
3. 1:15-2:00 — rlp.rs: decode (`decode_branch_children`/`decode_child_into`/`write_digest_node`), `resolve_with`/`resolve_digests`, encode (`encode_dirty`, `write_child_ref`, `encoded_payload_length`, `rlp_encoded`, `rlp_nodes`), `Decodable::decode`; tests green.
4. 2:00-2:30 — guest build (15 s), objdump codegen gate (§4.5), trace 781 (hash + census exact, expect −5…−7M), `run-native` 10 blocks, jeth nextest.
5. 2:30-3:00 — sweep 782-790 hashes, RESULTS.md wave entry, update node.rs:100-106 fork note, commit (do not push).
Abort: rows not ≤ −4M, any hash/census change, or a memset/memcpy in the branch arm not fixable in 20 min → revert the commit.
