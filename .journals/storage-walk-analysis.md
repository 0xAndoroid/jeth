# storage() → walk_storage row model, block 25905781 (628.0M rows)

Sources: crates/core/src/zeth_trie.rs (storage 305-331), walk.rs, resolver.rs; current ELF
disassembly in /tmp/storage-walk/{storage,match_path,validate_at,classify,memcmp}.asm;
data/25905781/profile-waveI-rows.log (same self-row figures as the brief).

## 0. Pool (non-keccak, 781)

| symbol | self rows | per call (2,832) |
|---|---:|---:|
| SparseState::storage (walk_storage/authenticate_walk/verify_slot/walk_entry inlined) | 5,452,362 | 1,925 |
| walk::validate_at (INV-W6, once per distinct entry) | 5,563,861 | 1,964 |
| match_path (self) 127,239 + its memcmp ≈ 277k (lane1b caller profile: 98 rows/call) | ~0.40M | ~143 |
| memcmp from storage() (address 20 B + EMPTY_ROOT 32 B) | ~0.43M | ~150 |
| Uint<256> Decodable::decode, storage share (~30% of 989,549) | ~0.30M | ~130 (per leaf) |
| hash_address + IndexMap probe + 4×memcpy on last_read miss | ~0.5M | ~700 per miss |
| **total** | **≈12.6M** | **≈4.4k** |

Excluded (keccak, other lane): slot hash 2,832 perms; first-verify keccak of every distinct
walked node ≈ 9.4k branches×4 perms + 2.3k leaves×1 perm ≈ 40k perms ≈ 100M rows (16% of the
block) in self-verifying mode — 8× the whole non-keccak pool. `--trusted-digests` removes it.

## 1. Per-visit costs (from storage.asm)

Addresses are in /tmp/storage-walk/storage.asm.

| step | where | rows | notes |
|---|---|---:|---|
| authenticate_walk, memo hit | 0x800cefb6–0x800cf0e8 | ~50 | ADVICE_LD 1 + `hint!=0` + verified_set bounds+load+mask (9) + verified[i] bounds + 4 ld (7) + 4× VirtualAssertEQ (4) + kinds bounds/load/shift (13) + witness[i] ptr/len bounds (13) + loop reloads from stack (4) |
| first visit extras | 0x800cf04c–0x800cf0c0, 0x800cf104–0x800cf144 | ~35 + validate_at | keccak (excluded) → le_words_32 shift-combine (15) + memo store (8) + set_kind (6) + call setup |
| entry header `decode_header` | 0x800cf16a–0x800cf214 | ~50 branch (0xf9: 2-byte len loop), ~25 leaf | per visit, re-derived every time although validate_entry already proved exact consumption |
| branch: key_nibble + depth check | 0x800cf246–0x800cf276 | ~14 | |
| branch: `for _ in 0..nib skip_item` | 0x800cf27a–0x800cf372 | 16–17 × nib ≈ 125 avg | digest item: lbu(3)+14 ALU/branch = 17; empty item 15 |
| branch: item_header + le_words_32 (unaligned) | 0x800cf382–0x800cf6b2 | ~35 | 5 ld + 12 shift/or (witness bytes rarely 8-aligned) |
| **branch visit total** | | **≈ 275–330** | |
| leaf: path header + match_path call + value header + range | 0x800cf6dc–0x800cf8ba | ~60 self + match_path (20 frame + 25 body + memcmp 98) | memcmp 29 B misaligned generic path |
| leaf: decode_exact::<U256> | 0x800cf8c4 | ~130 | ruint byte loop (`try_from_be_slice`) |
| **leaf visit total** | | **≈ 330** | |
| per call fixed | 0x800ced06–0x800cefac, epilogue | ~360 | prologue/epilogue 30, RefCell checks 10, `last.address==address` → memcmp(20) ≈ 85, `B256::from(slot)` byteswap 0x800cee28–0x800cef62 ≈ 125 (no Zbb rev8), `root == EMPTY_ROOT_WORDS` → memcmp(32) ≈ 70, walk setup 35 |
| per call, last_read miss | 0x800ced74–0x800cee18 | ~700 | hash_address (~285) + IndexMap get (~200) + **4 memcpy** (32 B, 20 B, 88 B, 88 B ≈ 200): `Some(LastRead{..})` built in a temp and copied twice |

validate_at (validate_at.asm): 17-item scan loop 0x8009fd46–0x8009fe70 ≈ 26 rows/item
(lbu 3 + ~23 ALU/branch; items 0/1 +6 for the `first` store) → full branch ≈ 50 header + 17×26
+ 40 frame + 20 tail ≈ **555 rows/branch**; leaf/extension ≈ **150**. Runs once per entry
(kinds memo checked at 0x800cf0fc before the call) — confirmed once-per-node, not per visit.
classify (inline children) absent from the profile (<0.02%) → inline children are negligible.

## 2. Solving for visits (781)

validate_at 5.56M = L×150 + B×555 with L ≈ 2.3k distinct leaves (≈80% of reads hit a leaf)
→ **B ≈ 9.4k distinct branch nodes** (±15%).
storage self 5.45M = 2,832×230 (fixed self) + 2.3k×180 (leaf self) + 11.7k×35 (first-visit)
+ V_b×(275–330) → **V_b ≈ 12–15k branch visits**; ≈ 4.2–5.2 branch levels + terminal per walk.
Revisits = V_b − B ≈ **2.6k–5k (22–35% of branch visits)**. Structural cross-check: root revisits
= Σ(r_t−1) ≈ 1.8k over ~1k tries + level-1 collisions Σ max(0, r_t − 16(1−(15/16)^r_t)) ≈
0.6–1.5k (heavy tries) → ≈ 2.5–3.3k, matching the low end. Below-root levels are almost never
shared: reads of one trie diverge at nibble 0/1.

What is repeated per storage() call: the fixed ~360 rows (address memcmp, slot byteswap,
EMPTY_ROOT memcmp), the root-node visit (~330, including its 50-row re-authentication) for every
read after the first of a trie, and ~50 rows of authentication + ~50 rows of header re-decode
at every level although both facts are memoized/provable from the first visit.

## 3. Ranked fixes (rows on 781, non-keccak)

| # | fix | expected | effort | risk / soundness |
|---|---|---:|---|---|
| 1 | **Relax INV-W6**: drop full-node `validate_at` for walked entries; classify kind on first visit by "payload exhausted after items 0,1 → 2-item else branch" (+35 rows once per node, memoized in `kinds`), keep per-item `decode_header` canonicality checks in the walk (already executed). | **−5.2M** (5.56M − 0.4M) | 1 day + parity tests | Policy, not soundness: every walked entry is keccak-authenticated against a digest chained to the pre-state root, so it IS the genuine consensus node (collision resistance); genuine nodes are canonical RLP. Validation can only fail on a corrupt witness (honest-prover bug) — never adversarially. Divergence set vs eager decode grows (accepts malformed-but-correctly-hashed nodes), unreachable on mainnet. Native gate runs the same code → guest/native agree. Needs owner sign-off on the L6 design law. |
| 2 | **Validated-entry fast walk**: (a) skip re-decoding the entry header — `hlen = 1 + (b≥0xf8 ? b−0xf7 : 0)`, payload = `entry[hlen..]` (validate_entry proved exact consumption, walk.rs:221) → −45×14.8k ≈ 0.55M; (b) per-entry 16-bit non-empty-child mask recorded during the validate scan (3 rows/item = 51/node = +0.48M) → child offset = nib + 32×popcount(mask & ((1<<nib)−1)) (~20 rows, no Zbb) replacing the 125-row skip loop → −105×12k = 1.26M; nodes with an inline child (mask sentinel) fall back to the loop; (c) one 8-aligned per-entry record {digest[4], kind/mask/hlen word, ptr, len} instead of 4 Vecs → 1 bounds check, no stack reloads → −15×14.8k ≈ 0.2M | **−1.5M net** (2.0M − 0.48M) | 1–2 days | Derived only from validated bytes; parity test skip-loop vs mask offsets. If #1 is taken, the mask must be built by the first-visit classifier (+51/node) — same net. |
| 3 | **Fixed-cost trims in storage()**: EMPTY_ROOT compare as `root[0]!=E0 \|\| …` inline (−65×2,832 = 0.18M); address compare as 2 aligned-gather words + u32 (−50×2,832 = 0.14M); build `LastRead` in place on miss (no 4 memcpy: −200 × ~1.5k misses ≈ 0.3M) | **−0.6M** | hours | none |
| 4 | **Leaf path**: inline match_path + word-wise body compare (5-load shift-combine + tail mask, ~35 rows vs memcmp 98 + 20 frame) → −0.23M; word-wise U256 leaf decode (le_words_32 gather + mask + swap, ~40 vs ~130) → −0.2M | **−0.4M** | hours–1 day | alloy_rlp canonicality of the value (leading zeros, single-byte) must be re-implemented: 3 checks |
| 5 | (b) **root-slot / (root,nib0) memo per trie** in `LastRead` (16 × ([u64;4] child digest, slot)): skips root authentication for every repeat read (−50×1.8k = 0.09M) and the whole root visit when nib0 repeats (−330 × 0.6–1.5k = 0.2–0.5M) | **−0.3–0.5M** | 1 day | Memo content = child digests read from the authenticated root entry + the slot whose `verified[i]` already equals that digest; pre-state tries immutable during execution; memo lives in `last_read`, reset by `calculate_state_root` (never reads it). |
| 6 | (a) **full per-node decoded-children memo** (16 digests/offsets per branch) | **≈ 0 net** | — | build cost (≥50–160 rows/node × 9.4k) ≈ savings (200 × 2.6k revisits); only the 16-bit mask variant (#2b) pays. Reject. |
| 7 | (d) **lazy decode into RlpTrie + Node::get** | **+9M (worse)** | — | measured decode_node_zc_into = 18.26M / ≈9.7k decoded nodes ≈ 1.9k rows/node (+ alloc + memcpy share) vs validate 555 + 1.3 visits × 300 ≈ 950/node; even at the brief's 450 rows/node it needs ≥1.5 visits/node — storage tries have ≈1.25. Reject. |
| 8 | (c) slot-hash memo (other lane) | excluded | — | hint: key by U256 limbs, not `B256::from(slot)` — the byteswap is 125 rows/call = 0.35M on 781 and stays in a B256-keyed memo. |

Totals: #2–#5 ≈ 2.8–3.0M (≈25% of the 11.0M pool, 0.45% of the block); with #1 ≈ 8M (1.3% of the block).
Floor after everything: ≈ 2,832 × (200 fixed + 4.5 × ~130 per
level + 150 leaf) ≈ 2.6M non-keccak.

## 4. Verdict

The non-keccak storage walk is within ~2× of its floor; validate_at (INV-W6) is 51% of the pool
and is the only lever ≥ 5M, and it is a parity policy, not a soundness check. Everything else
sums to ~3M. The real storage-read cost is authentication keccak (~100M, 16% of the block) —
addressed only by trusted digests / fewer distinct nodes, not by walk code.
