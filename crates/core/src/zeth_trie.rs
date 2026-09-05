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
use core::{cell::RefCell, marker::PhantomData};

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
    map::{indexmap::map::Entry, AddressMap, B256IndexMap},
    Address, B256, KECCAK256_EMPTY, U256,
};
use alloy_rpc_types_debug::ExecutionWitness;
use alloy_trie::{TrieAccount, EMPTY_ROOT_HASH};
use reth_trie_common::HashedPostState;
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
    address_hashes: RefCell<AddressMap<B256>>,
}

impl SparseState {
    /// Removes an account from the state.
    fn remove_account(&mut self, hashed_address: &B256) {
        self.state.remove(hashed_address);
        self.storages.remove(hashed_address);
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
                address_hashes: RefCell::new(AddressMap::with_capacity_and_hasher(
                    witness.state.len() / 8,
                    Default::default(),
                )),
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
                address_hashes: RefCell::new(AddressMap::with_capacity_and_hasher(
                    witness.state.len() / 8,
                    Default::default(),
                )),
            },
            bytecode,
        ))
    }

    /// Returns the `TrieAccount` that corresponds to the `Address`.
    fn account(&self, address: Address) -> Result<Option<TrieAccount>, WitnessDbError> {
        let hashed_address = hash_address(address, &self.address_hashes);
        match self.state.get(hashed_address)? {
            None => Ok(None),
            Some(account) => {
                // record the storage anchor for byte-walk reads; no
                // materialization (the account leaf is authenticated chain to
                // pre_state_root, so the root is authenticated too)
                self.storage_roots.borrow_mut().insert(
                    hashed_address,
                    zeth_mpt::le_words_32(account.storage_root.as_slice()),
                );
                Ok(Some(account))
            }
        }
    }

    /// Returns the storage slot value that corresponds to the given (address, slot) tuple.
    fn storage(&self, address: Address, slot: U256) -> Result<U256, WitnessDbError> {
        // storage() is always called after account(), so the anchor must exist
        // (same revm-enforced invariant as the old trie-must-exist unwrap)
        let root = *self
            .storage_roots
            .borrow()
            .get(&hash_address(address, &self.address_hashes))
            .unwrap();
        let key = keccak256(B256::from(slot));
        Ok(self
            .resolver
            .borrow_mut()
            .walk_storage(root, &key)?
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

fn hash_address(address: Address, memo: &RefCell<AddressMap<B256>>) -> B256 {
    let mut memo = memo.borrow_mut();
    let digest = *memo.entry(address).or_insert_with(|| keccak256(address));
    #[cfg(test)]
    debug_assert_eq!(digest, keccak256(address));
    digest
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_memo_matches_direct_hashes() {
        let memo = RefCell::new(AddressMap::default());
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
                assert_eq!(hash_address(address, &memo), expected);
            }
        }
        assert_eq!(memo.borrow().len(), addresses.len());
    }
}
