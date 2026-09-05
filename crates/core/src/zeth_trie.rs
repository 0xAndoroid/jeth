//! Vendored from paradigmxyz/stateless `crates/tries/src/zeth.rs` @ 6e55612
//! (zeth-backed sparse MPT; Copyright 2025 RISC Zero, Inc., Apache-2.0).
//!
//! jeth modification: `SparseState::new` can consume PRE-COMPUTED node digests
//! and code hashes (delivered as Jolt TRUSTED ADVICE) instead of keccak-hashing
//! every witness node in-guest — the reveal phase's hashing measured 274M trace
//! rows (19%) on a real block. See `set_trusted_digests` for the soundness
//! contract: the digest map becomes verifier-trusted input, so this variant
//! proves "the block is valid GIVEN this digest map" — appropriate when the
//! verifier (or proving customer) independently possesses the witness.
#![allow(warnings)]
// Copyright 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use alloc::vec::Vec;
use core::{cell::RefCell, marker::PhantomData, ptr::read_volatile};

use tries::{StatelessTrie, StatelessTrieError, WitnessDbError};

/// Pre-computed digests: (state trie node keccaks, bytecode keccaks), in
/// witness order. Set by the guest from trusted advice before validation.
static mut TRUSTED_DIGESTS: Option<(&'static [[u8; 32]], &'static [[u8; 32]])> = None;

/// Install trusted digests for the next `SparseState::new` (single-hart guest).
///
/// # Soundness
/// The supplied digests are NOT verified in-guest. A wrong digest either makes
/// the corresponding node unreachable (reveal/read failure ⇒ panic) or, if
/// adversarially crafted, substitutes node content — which is exactly the trust
/// granted to Jolt trusted advice (verifier-attested input). The pre-state root
/// linkage still anchors the trie shape: only nodes whose (claimed) digest is
/// referenced from the root are reachable.
pub fn set_trusted_digests(state: &'static [[u8; 32]], codes: &'static [[u8; 32]]) {
    unsafe { TRUSTED_DIGESTS = Some((state, codes)) }
}

fn take_trusted_digests() -> Option<(&'static [[u8; 32]], &'static [[u8; 32]])> {
    unsafe { TRUSTED_DIGESTS.take() }
}
use crate::resolver::{b256_from_le_words, WitnessResolver};
use alloy_primitives::{
    keccak256,
    map::{indexmap::map::Entry, B256IndexMap},
    Address, B256, KECCAK256_EMPTY, U256,
};
use alloy_rpc_types_debug::ExecutionWitness;
use alloy_trie::{TrieAccount, EMPTY_ROOT_HASH};
use reth_evm::revm::database::BundleAccount;
use reth_trie_common::{HashedPostState, HashedStorage};
use revm_bytecode::Bytecode;
use zeth_mpt::CachedTrie;

/// Zero-overhead helper for tries that only contain RLP encoded data.
#[derive(Debug, Clone, Default)]
#[repr(transparent)]
struct RlpTrie<T> {
    inner: CachedTrie,
    phantom: PhantomData<T>,
}

impl<T: alloy_rlp::Decodable + alloy_rlp::Encodable> RlpTrie<T> {
    fn new(inner: CachedTrie) -> Self {
        Self {
            inner,
            phantom: PhantomData,
        }
    }

    pub fn from_resolver(root: B256, resolver: &mut WitnessResolver) -> alloy_rlp::Result<Self> {
        // jeth: zero-copy decode — leaf values reference the witness bytes;
        // digests resolve through the advice-indexed resolver (no map).
        Ok(Self::new(CachedTrie::from_resolver_zc(root, resolver)?))
    }

    /// Lazy trie anchored at `root` — nothing resolved up front; mutations
    /// resolve on demand. `EMPTY_ROOT_HASH` short-circuits to the empty trie.
    pub fn from_digest_root(root: B256) -> Self {
        Self::new(CachedTrie::from_digest(root))
    }

    pub fn insert_with(&mut self, key: impl AsRef<[u8]>, value: T, r: &mut WitnessResolver) {
        self.inner.insert_with(key, alloy_rlp::encode(value), r);
    }

    pub fn remove_with(&mut self, key: impl AsRef<[u8]>, r: &mut WitnessResolver) -> bool {
        self.inner.remove_with(key, r)
    }

    pub fn get(&self, key: impl AsRef<[u8]>) -> alloy_rlp::Result<Option<T>> {
        self.inner.get(key).map(alloy_rlp::decode_exact).transpose()
    }

    pub fn insert(&mut self, key: impl AsRef<[u8]>, value: T) {
        self.inner.insert(key, alloy_rlp::encode(value));
    }

    pub fn remove(&mut self, key: impl AsRef<[u8]>) -> bool {
        self.inner.remove(key)
    }

    pub fn hash(&mut self) -> B256 {
        self.inner.hash()
    }
}

/// Represents a sparse version of the Ethereum world state.
/// This is significantly more performant than the Reth default.
///
/// Phase 1b (advice-trie): storage tries are never materialized for reads —
/// `storage()` byte-walks raw witness RLP anchored at the account's
/// `storage_root` (recorded by `account()`); tries exist only for WRITTEN
/// accounts, created at post-root and hydrated on demand along dirty paths.
#[derive(Debug, Clone)]
pub struct SparseState {
    /// state MPT containing all used accounts (still eagerly revealed)
    state: RlpTrie<TrieAccount>,
    /// storage tries of written accounts — created at post-root only (§4.3)
    storages: B256IndexMap<RlpTrie<U256>>,
    /// hashed_address → storage_root (as words), recorded on every successful
    /// `account()` (pre-state leaves are immutable during execution, so
    /// re-records agree)
    storage_roots: RefCell<B256IndexMap<[u64; 4]>>,
    /// advice-indexed digest→witness-slot resolver (replaces `rlp_by_digest`).
    resolver: RefCell<WitnessResolver>,
    address_hashes: RefCell<AddressMemo>,
    /// slot → keccak(slot): address-independent, so one entry serves every
    /// contract that touches the same slot number. Keyed by the limbs; the
    /// big-endian form is only built for the keccak.
    slot_hashes: RefCell<SlotMemo>,
    /// last address resolved by `account()` / `storage()`: consecutive reads
    /// of one contract skip the address-hash and storage-root map probes
    last_read: RefCell<Option<LastRead>>,
}

type AddressMemo = KeccakMemo<3>;
type SlotMemo = KeccakMemo<4>;

/// Flat open-addressing keccak memo: `K` key words → digest words. A
/// hashbrown probe costs ≈300 rows on Jolt (byte-wise control-group scan,
/// sub-word stores, a four-word hash fold, a second probe on insert); a linear
/// probe over whole-word entries costs ≈25. `live` marks occupancy, so a zero
/// key is an ordinary key.
#[derive(Debug, Clone)]
struct KeccakMemo<const K: usize> {
    entries: Vec<MemoEntry<K>>,
    len: usize,
    /// `64 - log2(entries.len())`: the slot is the top bits of the hash.
    shift: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct MemoEntry<const K: usize> {
    live: u64,
    key: [u64; K],
    digest: [u64; 4],
}

impl<const K: usize> MemoEntry<K> {
    const EMPTY: Self = Self {
        live: 0,
        key: [0; K],
        digest: [0; 4],
    };
}

impl<const K: usize> KeccakMemo<K> {
    /// Sized for about `expected` keys; the table doubles past a 0.7 load.
    fn with_capacity(expected: usize) -> Self {
        Self::with_slots(expected.next_power_of_two().max(64))
    }

    fn with_slots(slots: usize) -> Self {
        Self {
            entries: alloc::vec![MemoEntry::EMPTY; slots],
            len: 0,
            shift: 64 - slots.trailing_zeros(),
        }
    }

    fn len(&self) -> usize {
        self.len
    }

    /// Fibonacci hash of the XOR-folded key words.
    #[inline(always)]
    fn slot(&self, key: &[u64; K]) -> usize {
        let folded = key.iter().fold(0u64, |acc, word| acc ^ word);
        (folded.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> self.shift) as usize
    }

    /// The digest memoized for `key`, or `digest()` recorded for it.
    #[inline(always)]
    fn get_or_insert_with(&mut self, key: [u64; K], digest: impl FnOnce() -> [u64; 4]) -> [u64; 4] {
        let mask = self.entries.len() - 1;
        let mut i = self.slot(&key);
        loop {
            let entry = &self.entries[i];
            if entry.live == 0 {
                return self.insert_at(i, key, digest);
            }
            let mut diff = 0;
            for j in 0..K {
                diff |= entry.key[j] ^ key[j];
            }
            if diff == 0 {
                return entry.digest;
            }
            i = (i + 1) & mask;
        }
    }

    /// Miss path, kept out of line so the hit path above stays a few
    /// instructions with no frame of its own.
    #[cold]
    #[inline(never)]
    fn insert_at(
        &mut self,
        i: usize,
        key: [u64; K],
        digest: impl FnOnce() -> [u64; 4],
    ) -> [u64; 4] {
        let digest = digest();
        self.entries[i] = MemoEntry {
            live: 1,
            key,
            digest,
        };
        self.len += 1;
        if 10 * self.len > 7 * self.entries.len() {
            self.grow();
        }
        digest
    }

    fn grow(&mut self) {
        let mut grown = Self::with_slots(2 * self.entries.len());
        let mask = grown.entries.len() - 1;
        for entry in self.entries.iter().filter(|entry| entry.live != 0) {
            let mut i = grown.slot(&entry.key);
            while grown.entries[i].live != 0 {
                i = (i + 1) & mask;
            }
            grown.entries[i] = *entry;
        }
        grown.len = self.len;
        *self = grown;
    }
}

/// The 20 address bytes as three little-endian words (word 2 holds bytes
/// 16..20), gathered from the 8-aligned words containing them: `Address` is
/// align 1, and a byte-wise assembly costs 3 rows per byte on Jolt.
///
/// # Safety of the containing-word reads
/// As for [`zeth_mpt::le_words_32`]: every word read holds a live byte of the
/// address — word 0 holds byte 0, word 2 holds byte 16 at every offset, and
/// word 3 is read only when the offset puts byte 19 in it — and Jolt guest RAM
/// is flat and word-granular (natively the containing word lies in the same
/// allocation granule). Every load address is a multiple of 8.
/// A `B256` at an 8-byte boundary. A bare `B256` is align 1, so materializing
/// one from words stores its 32 bytes one at a time (≈220 rows); into an
/// aligned slot it is four whole-word stores.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
struct AlignedB256(B256);

impl AlignedB256 {
    #[inline(always)]
    fn from_le_words(words: [u64; 4]) -> Self {
        Self(b256_from_le_words(words))
    }
}

#[inline(always)]
fn address_words(address: &Address) -> [u64; 3] {
    let src = address.as_ptr() as usize;
    let so = src & 7;
    let base = (src & !7) as *const u64;
    unsafe {
        let w0 = u64::from_le(read_volatile(base));
        let w1 = u64::from_le(read_volatile(base.add(1)));
        let w2 = u64::from_le(read_volatile(base.add(2)));
        if so == 0 {
            return [w0, w1, w2 & 0xffff_ffff];
        }
        let w3 = if so > 4 {
            u64::from_le(read_volatile(base.add(3)))
        } else {
            0
        };
        let sr = (8 * so) as u32;
        let sl = 64 - sr;
        [
            (w0 >> sr) | (w1 << sl),
            (w1 >> sr) | (w2 << sl),
            ((w2 >> sr) | (w3 << sl)) & 0xffff_ffff,
        ]
    }
}

/// One-entry memo of the address → (hashed address, storage root) chain.
/// Pre-state storage roots are immutable during execution, so an entry never
/// goes stale. Invariant: `last_read ≡ storage_roots[hashed(address)]` — the
/// pre-state trie mutates only in `calculate_state_root`, which never reads
/// the memo. `repr(C)` keeps `hashed` at an 8-aligned offset (whole-word
/// copies).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct LastRead {
    root: [u64; 4],
    hashed: B256,
    address: Address,
}

impl SparseState {
    /// Removes an account from the state.
    fn remove_account(&mut self, hashed_address: &B256) {
        self.state.remove(hashed_address);
        self.storages.remove(hashed_address);
    }

    /// `HashedPostState::from_bundle_state::<KeccakKeyHasher>` with the address
    /// and slot digests taken from the execution-time memos: every changed
    /// account went through `account()` and every SSTORE'd slot was first
    /// SLOADed through `storage()`. Memo misses (slots of created accounts,
    /// never read) fall back to keccak.
    pub fn hashed_post_state<'a>(
        &self,
        state: impl IntoIterator<Item = (&'a Address, &'a BundleAccount)>,
    ) -> HashedPostState {
        hashed_post_state(state, &self.address_hashes, &self.slot_hashes)
    }

    /// `keccak256(address)` through the `account()` memo (log emitters were
    /// all loaded during execution).
    pub fn hashed_address(&self, address: Address) -> B256 {
        hash_address(address, &self.address_hashes).0
    }
}

impl SparseState {
    /// Like [`StatelessTrie::new`] but returns a [`crate::validation::CodeMap`]
    /// (raw bytes when `lazy-analysis` is enabled) instead of eagerly analyzed
    /// [`Bytecode`] — used by the vendored per-tx validation path.
    pub fn new_with_codes(
        witness: &ExecutionWitness,
        pre_state_root: B256,
    ) -> Result<(Self, crate::validation::CodeMap), StatelessTrieError> {
        let trusted = take_trusted_digests().filter(|(state_digests, code_hashes)| {
            state_digests.len() == witness.state.len() && code_hashes.len() == witness.codes.len()
        });

        let mut resolver = WitnessResolver::new(&witness.state, trusted.map(|(s, _)| s));

        let state = RlpTrie::from_resolver(pre_state_root, &mut resolver)
            .map_err(|_| StatelessTrieError::WitnessRevealFailed { pre_state_root })?;
        #[cfg(feature = "premeasure")]
        crate::premeasure::STATE_BUILD.record();

        // hash all the supplied bytecode (or adopt trusted hashes); analysis is
        // deferred per the CodeMap policy.
        let codes = crate::validation::CodeMap::build(match trusted {
            Some((_, code_hashes)) => itertools_either::Either::Left(
                code_hashes
                    .iter()
                    .zip(witness.codes.iter())
                    .map(|(hash, code)| (B256::from(*hash), code)),
            ),
            None => itertools_either::Either::Right(
                witness.codes.iter().map(|code| (keccak256(code), code)),
            ),
        });

        Ok((
            Self {
                state,
                storages: B256IndexMap::default(),
                storage_roots: RefCell::new(B256IndexMap::default()),
                resolver: RefCell::new(resolver),
                address_hashes: RefCell::new(AddressMemo::with_capacity(witness.state.len() / 8)),
                slot_hashes: RefCell::new(SlotMemo::with_capacity(witness.state.len() / 8)),
                last_read: RefCell::new(None),
            },
            codes,
        ))
    }
}

/// Minimal local `Either` iterator (avoids an itertools dependency).
mod itertools_either {
    pub enum Either<L, R> {
        Left(L),
        Right(R),
    }
    impl<T, L: Iterator<Item = T>, R: Iterator<Item = T>> Iterator for Either<L, R> {
        type Item = T;
        fn next(&mut self) -> Option<T> {
            match self {
                Either::Left(l) => l.next(),
                Either::Right(r) => r.next(),
            }
        }
    }
}

impl StatelessTrie for SparseState {
    /// Initialize the stateless trie using the `ExecutionWitness`.
    fn new(
        witness: &ExecutionWitness,
        pre_state_root: B256,
    ) -> Result<(Self, B256IndexMap<Bytecode>), StatelessTrieError> {
        let trusted = take_trusted_digests().filter(|(state_digests, code_hashes)| {
            state_digests.len() == witness.state.len() && code_hashes.len() == witness.codes.len()
        });

        // digest resolution goes through the advice-indexed resolver: no map
        // build — self-verifying mode keccaks each witness entry at first
        // resolve (memoized), trusted mode seeds the memo from the blob.
        let mut resolver = WitnessResolver::new(&witness.state, trusted.map(|(s, _)| s));

        // construct the state trie from the witness data and the given state root
        let state = RlpTrie::from_resolver(pre_state_root, &mut resolver)
            .map_err(|_| StatelessTrieError::WitnessRevealFailed { pre_state_root })?;
        #[cfg(feature = "premeasure")]
        crate::premeasure::STATE_BUILD.record();

        // hash all the supplied bytecode (or adopt trusted hashes)
        let bytecode = match trusted {
            Some((_, code_hashes)) => code_hashes
                .iter()
                .zip(witness.codes.iter())
                .map(|(hash, code)| (B256::from(*hash), Bytecode::new_raw(code.clone())))
                .collect(),
            None => witness
                .codes
                .iter()
                .map(|code| (keccak256(code), Bytecode::new_raw(code.clone())))
                .collect(),
        };

        Ok((
            Self {
                state,
                storages: B256IndexMap::default(),
                storage_roots: RefCell::new(B256IndexMap::default()),
                resolver: RefCell::new(resolver),
                address_hashes: RefCell::new(AddressMemo::with_capacity(witness.state.len() / 8)),
                slot_hashes: RefCell::new(SlotMemo::with_capacity(witness.state.len() / 8)),
                last_read: RefCell::new(None),
            },
            bytecode,
        ))
    }

    /// Returns the `TrieAccount` that corresponds to the `Address`.
    fn account(&self, address: Address) -> Result<Option<TrieAccount>, WitnessDbError> {
        let hashed_address = match &*self.last_read.borrow() {
            Some(last) if last.address == address => AlignedB256(last.hashed),
            _ => hash_address(address, &self.address_hashes),
        };
        match self.state.get(&hashed_address.0)? {
            None => Ok(None),
            Some(account) => {
                // record the storage anchor for byte-walk reads; no
                // materialization (the account leaf is authenticated chain to
                // pre_state_root, so the root is authenticated too)
                let root = zeth_mpt::le_words_32(account.storage_root.as_slice());
                self.storage_roots
                    .borrow_mut()
                    .insert(hashed_address.0, root);
                *self.last_read.borrow_mut() = Some(LastRead {
                    root,
                    hashed: hashed_address.0,
                    address,
                });
                Ok(Some(account))
            }
        }
    }

    /// Returns the storage slot value that corresponds to the given (address, slot) tuple.
    fn storage(&self, address: Address, slot: U256) -> Result<U256, WitnessDbError> {
        // storage() is always called after account(), so the anchor must exist
        // (same revm-enforced invariant as the old trie-must-exist unwrap)
        let memo = match &*self.last_read.borrow() {
            Some(last) if last.address == address => Some(last.root),
            _ => None,
        };
        let root = match memo {
            Some(root) => root,
            None => {
                let hashed = hash_address(address, &self.address_hashes);
                let root = *self.storage_roots.borrow().get(&hashed.0).unwrap();
                *self.last_read.borrow_mut() = Some(LastRead {
                    root,
                    hashed: hashed.0,
                    address,
                });
                root
            }
        };
        let key = hash_slot(slot, &self.slot_hashes);
        Ok(self
            .resolver
            .borrow_mut()
            .walk_storage(root, &key.0)?
            .unwrap_or(U256::ZERO))
    }

    /// Computes the new state root from the HashedPostState.
    fn calculate_state_root(&mut self, state: HashedPostState) -> Result<B256, StatelessTrieError> {
        #[cfg(feature = "premeasure")]
        crate::premeasure::EXEC_END.record();
        let Self {
            state: state_trie,
            storages,
            storage_roots,
            resolver,
            ..
        } = self;
        let storage_roots = storage_roots.get_mut();
        let resolver = resolver.get_mut();

        let mut removed_accounts = Vec::new();
        // DET-1 (L5): `state.accounts` is a foldhash HashMap — advice calls
        // (on-demand dirty-path resolution) must never be sequenced under
        // unsorted map iteration. Sorting also pins the perm order.
        let mut accounts: Vec<_> = state.accounts.into_iter().collect();
        accounts.sort_unstable_by_key(|(hashed_address, _)| *hashed_address);
        for (hashed_address, account) in accounts {
            // nonexisting accounts must be removed from the state
            let Some(account) = account else {
                removed_accounts.push(hashed_address);
                continue;
            };

            // §4.3 storage-arena creation rules
            let storage_root = match state.storages.get(&hashed_address) {
                // no storage changes → cached root passthrough, zero work
                None => match storage_roots.get(&hashed_address) {
                    Some(root) => b256_from_le_words(*root),
                    // never read during execution: fall back to the (pre-state)
                    // account leaf, exactly like the old storage_trie_mut
                    None => state_trie
                        .get(hashed_address)
                        .unwrap()
                        .map_or(EMPTY_ROOT_HASH, |a| a.storage_root),
                },
                Some(storage) => {
                    let storage_trie = if storage.wiped {
                        // fresh empty trie, discard the pre-root: merging
                        // against the pre-trie would demand witness paths that
                        // legitimately don't exist (selfdestruct/recreate)
                        storages.insert(hashed_address, RlpTrie::default());
                        storages.get_mut(&hashed_address).unwrap()
                    } else {
                        match storages.entry(hashed_address) {
                            Entry::Occupied(entry) => entry.into_mut(),
                            Entry::Vacant(entry) => {
                                // anchor at the recorded root (or the pre-state
                                // leaf); EMPTY_ROOT_HASH → empty trie, no
                                // resolver call; everything else stays a stub
                                // hydrated on demand by the mutations below
                                let anchor = match storage_roots.get(&hashed_address) {
                                    Some(root) => b256_from_le_words(*root),
                                    None => state_trie
                                        .get(hashed_address)
                                        .unwrap()
                                        .map_or(EMPTY_ROOT_HASH, |a| a.storage_root),
                                };
                                entry.insert(RlpTrie::from_digest_root(anchor))
                            }
                        }
                    };

                    // DET-2 (L5): sort storage updates by hashed slot.
                    let mut slots: Vec<_> = storage.storage.iter().collect();
                    slots.sort_unstable_by_key(|(hashed_key, _)| *hashed_key);
                    // apply all state modifications
                    for &(hashed_key, value) in &slots {
                        if !value.is_zero() {
                            storage_trie.insert_with(hashed_key, *value, resolver);
                        }
                    }
                    // removals must happen last, otherwise unresolved orphans might still exist
                    // (DET-3: insert-before-remove preserved)
                    for &(hashed_key, value) in &slots {
                        if value.is_zero() {
                            storage_trie.remove_with(hashed_key, resolver);
                        }
                    }

                    storage_trie.hash()
                }
            };

            // update/insert the account after all changes have been processed
            let account = TrieAccount {
                nonce: account.nonce,
                balance: account.balance,
                storage_root,
                code_hash: account.bytecode_hash.unwrap_or(KECCAK256_EMPTY),
            };
            state_trie.insert(hashed_address, account);
        }
        removed_accounts
            .iter()
            .for_each(|hashed_address| self.remove_account(hashed_address));

        #[cfg(feature = "premeasure")]
        crate::premeasure::PRE_STATE_HASH.record();
        let root = self.state.hash();
        #[cfg(feature = "premeasure")]
        crate::premeasure::POST_ROOT.record();
        Ok(root)
    }
}

fn hash_address(address: Address, memo: &RefCell<AddressMemo>) -> AlignedB256 {
    let digest = memo
        .borrow_mut()
        .get_or_insert_with(address_words(&address), || {
            zeth_mpt::le_words_32(keccak256(address).as_slice())
        });
    let digest = AlignedB256::from_le_words(digest);
    #[cfg(test)]
    debug_assert_eq!(digest.0, keccak256(address));
    digest
}

fn hashed_post_state<'a>(
    state: impl IntoIterator<Item = (&'a Address, &'a BundleAccount)>,
    address_hashes: &RefCell<AddressMemo>,
    slot_hashes: &RefCell<SlotMemo>,
) -> HashedPostState {
    state
        .into_iter()
        .map(|(address, account)| {
            let hashed_address = hash_address(*address, address_hashes).0;
            let hashed_account = account.info.as_ref().map(Into::into);
            let hashed_storage = HashedStorage::from_iter(
                account.status.was_destroyed(),
                account
                    .storage
                    .iter()
                    .map(|(slot, value)| (hash_slot(*slot, slot_hashes).0, value.present_value)),
            );
            (
                hashed_address,
                hashed_account,
                (!hashed_storage.is_empty()).then_some(hashed_storage),
            )
        })
        .collect()
}

fn hash_slot(slot: U256, memo: &RefCell<SlotMemo>) -> AlignedB256 {
    let digest = memo.borrow_mut().get_or_insert_with(*slot.as_limbs(), || {
        zeth_mpt::le_words_32(keccak256(B256::from(slot)).as_slice())
    });
    let digest = AlignedB256::from_le_words(digest);
    #[cfg(test)]
    debug_assert_eq!(digest.0, keccak256(B256::from(slot)));
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_memo_matches_direct_hashes() {
        let memo = RefCell::new(AddressMemo::with_capacity(0));
        let mut rng = 0x9432_1735_abc0_ef89u64;
        let addresses: Vec<_> = (0..1024)
            .map(|_| {
                let mut bytes = [0u8; 20];
                for byte in &mut bytes {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    *byte = rng as u8;
                }
                Address::from(bytes)
            })
            .collect();
        for _ in 0..2 {
            for &address in &addresses {
                let expected = keccak256(address);
                assert_eq!(hash_address(address, &memo).0, expected);
            }
        }
        assert_eq!(memo.borrow().len(), addresses.len());
    }

    /// Ten thousand random keys through both memos, from the minimum table
    /// size (several doublings): every digest is the keccak, repeats hit.
    #[test]
    fn memos_match_keccak_across_growth() {
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut addresses = Vec::new();
        let mut slots = Vec::new();
        for i in 0..10_000u64 {
            let mut bytes = [0u8; 20];
            bytes[..8].copy_from_slice(&next().to_le_bytes());
            bytes[8..16].copy_from_slice(&next().to_le_bytes());
            bytes[16..].copy_from_slice(&(next() as u32).to_le_bytes());
            addresses.push(Address::from(bytes));
            // half small slot numbers, half hash-like
            slots.push(if i % 2 == 0 {
                U256::from(i)
            } else {
                U256::from_limbs([next(), next(), next(), next()])
            });
        }
        let address_memo = RefCell::new(AddressMemo::with_capacity(0));
        let slot_memo = RefCell::new(SlotMemo::with_capacity(0));
        for _ in 0..2 {
            for (address, slot) in addresses.iter().zip(&slots) {
                assert_eq!(hash_address(*address, &address_memo).0, keccak256(address));
                assert_eq!(hash_slot(*slot, &slot_memo).0, keccak256(B256::from(*slot)));
            }
            assert_eq!(address_memo.borrow().len(), addresses.len());
            assert_eq!(slot_memo.borrow().len(), slots.len());
        }
        assert!(address_memo.borrow().entries.len() >= 16_384);
        assert_eq!(core::mem::align_of::<AlignedB256>(), 8);
        // every source alignment of the address bytes gathers the same words
        let mut buffer = [0u8; 28];
        for offset in 0..8 {
            buffer[offset..offset + 20].copy_from_slice(addresses[0].as_slice());
            let address = Address::from_slice(&buffer[offset..offset + 20]);
            assert_eq!(
                address_words(&address),
                address_words(&addresses[0]),
                "offset={offset}"
            );
            let mut expected = [0u8; 24];
            expected[..20].copy_from_slice(addresses[0].as_slice());
            let words = address_words(&address);
            assert_eq!(words[0].to_le_bytes(), expected[..8]);
            assert_eq!(words[1].to_le_bytes(), expected[8..16]);
            assert_eq!(words[2].to_le_bytes(), expected[16..]);
        }
    }

    #[test]
    fn slot_memo_matches_direct_hashes() {
        let memo = RefCell::new(SlotMemo::with_capacity(0));
        let slots: Vec<_> = (0u64..64)
            .flat_map(|i| {
                [
                    U256::from(i),
                    U256::from_be_bytes(keccak256(i.to_be_bytes()).0),
                ]
            })
            .collect();
        for _ in 0..2 {
            for &slot in &slots {
                assert_eq!(hash_slot(slot, &memo).0, keccak256(B256::from(slot)));
            }
        }
        assert_eq!(memo.borrow().len(), slots.len());
    }

    #[test]
    fn memo_post_state_matches_from_bundle_state() {
        use reth_evm::revm::database::{states::StorageSlot, AccountStatus};
        use reth_trie_common::KeccakKeyHasher;
        use revm_state::AccountInfo;

        let address = |i: u8| Address::repeat_byte(i);
        let info = |nonce: u64| AccountInfo {
            nonce,
            balance: U256::from(nonce) * U256::from(1_000_000_007u64),
            code_hash: if nonce % 2 == 0 {
                KECCAK256_EMPTY
            } else {
                keccak256([nonce as u8])
            },
            ..Default::default()
        };
        let mapping_slot = U256::from_be_bytes(keccak256(b"mapping").0);
        let storage = |slots: &[(U256, u64, u64)]| {
            slots
                .iter()
                .map(|&(slot, old, new)| {
                    (
                        slot,
                        StorageSlot::new_changed(U256::from(old), U256::from(new)),
                    )
                })
                .collect()
        };
        let accounts = [
            // changed account: read slots 0/7, plus slot 9 written without a read
            (
                address(1),
                BundleAccount::new(
                    Some(info(1)),
                    Some(info(2)),
                    storage(&[
                        (U256::ZERO, 1, 2),
                        (U256::from(7), 3, 0),
                        (U256::from(9), 0, 4),
                    ]),
                    AccountStatus::Changed,
                ),
            ),
            // created (never in the pre-state): slots never read; shares slot 0
            (
                address(2),
                BundleAccount::new(
                    None,
                    Some(info(3)),
                    storage(&[(U256::ZERO, 0, 5), (mapping_slot, 0, 6)]),
                    AccountStatus::InMemoryChange,
                ),
            ),
            // destroyed: wiped storage, no slots
            (
                address(3),
                BundleAccount::new(
                    Some(info(4)),
                    None,
                    Default::default(),
                    AccountStatus::Destroyed,
                ),
            ),
            // destroyed and recreated in the same block
            (
                address(4),
                BundleAccount::new(
                    Some(info(5)),
                    Some(info(6)),
                    storage(&[(mapping_slot, 0, 8)]),
                    AccountStatus::DestroyedChanged,
                ),
            ),
            // balance-only change
            (
                address(5),
                BundleAccount::new(
                    Some(info(7)),
                    Some(info(8)),
                    Default::default(),
                    AccountStatus::Changed,
                ),
            ),
            // touched but non-existent
            (
                address(6),
                BundleAccount::new(
                    None,
                    None,
                    Default::default(),
                    AccountStatus::LoadedNotExisting,
                ),
            ),
        ];

        // execution-time reads: every account but the created one was loaded,
        // slots 0/7 of address(1) and the mapping slot of address(4) were read
        let address_hashes = RefCell::new(AddressMemo::with_capacity(0));
        let slot_hashes = RefCell::new(SlotMemo::with_capacity(0));
        for i in [1, 3, 4, 5, 6] {
            hash_address(address(i), &address_hashes);
        }
        for slot in [U256::ZERO, U256::from(7), mapping_slot] {
            hash_slot(slot, &slot_hashes);
        }
        assert_eq!(
            (address_hashes.borrow().len(), slot_hashes.borrow().len()),
            (5, 3)
        );

        let expected = HashedPostState::from_bundle_state::<KeccakKeyHasher>(
            accounts.iter().map(|(address, account)| (address, account)),
        );
        let got = hashed_post_state(
            accounts.iter().map(|(address, account)| (address, account)),
            &address_hashes,
            &slot_hashes,
        );
        assert_eq!(got, expected);
        assert_eq!(got.accounts.len(), 6);
        assert_eq!(got.storages.len(), 4);
        assert!(got.storages[&keccak256(address(3))].wiped);
        assert!(got.storages[&keccak256(address(4))].wiped);
        // misses were filled in: address(2) and slot 9; repeats (slot 0, the
        // mapping slot) hit the existing entries
        assert_eq!(
            (address_hashes.borrow().len(), slot_hashes.borrow().len()),
            (6, 4)
        );
    }
}
