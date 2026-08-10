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
use crate::resolver::WitnessResolver;
use alloy_primitives::{
    keccak256,
    map::{indexmap::map::Entry, B256IndexMap},
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
#[derive(Debug, Clone)]
pub struct SparseState {
    /// state MPT containing all used accounts
    state: RlpTrie<TrieAccount>,
    /// storage MPTs sorted by the hashed address of their account
    storages: RefCell<B256IndexMap<RlpTrie<U256>>>,

    /// advice-indexed digest→witness-slot resolver (replaces `rlp_by_digest`).
    /// RefCell: `account()` is `&self` on the trait but resolves lazily-built
    /// storage tries — same interior-mutability pattern as `storages`.
    resolver: RefCell<WitnessResolver>,
}

impl SparseState {
    /// Removes an account from the state.
    fn remove_account(&mut self, hashed_address: &B256) {
        self.state.remove(hashed_address);
        self.storages.get_mut().remove(hashed_address);
    }

    /// Clears the storage of an account.
    fn clear_storage(&mut self, hashed_address: B256) -> &mut RlpTrie<U256> {
        match self.storages.get_mut().entry(hashed_address) {
            Entry::Occupied(mut entry) => {
                entry.insert(RlpTrie::default());
                entry
            }
            Entry::Vacant(entry) => entry.insert_entry(RlpTrie::default()),
        }
        .into_mut()
    }

    /// Returns a mutable version of the storage trie of the given account.
    fn storage_trie_mut(&mut self, hashed_address: B256) -> alloy_rlp::Result<&mut RlpTrie<U256>> {
        let trie = match self.storages.get_mut().entry(hashed_address) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                // build the storage trie matching the storage root of the account
                let storage_root = self
                    .state
                    .get(hashed_address)?
                    .map_or(EMPTY_ROOT_HASH, |a| a.storage_root);
                entry.insert(RlpTrie::from_resolver(
                    storage_root,
                    self.resolver.get_mut(),
                )?)
            }
        };

        Ok(trie)
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
                storages: RefCell::new(B256IndexMap::default()),
                resolver: RefCell::new(resolver),
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
                storages: RefCell::new(B256IndexMap::default()),
                resolver: RefCell::new(resolver),
            },
            bytecode,
        ))
    }

    /// Returns the `TrieAccount` that corresponds to the `Address`.
    fn account(&self, address: Address) -> Result<Option<TrieAccount>, WitnessDbError> {
        let hashed_address = keccak256(address);
        match self.state.get(hashed_address)? {
            None => Ok(None),
            Some(account) => {
                // each time an account is accessed, check whether its storage trie already exists
                // otherwise construct it from the witness data and the account's storage root
                match self.storages.borrow_mut().entry(hashed_address) {
                    Entry::Vacant(entry) => {
                        entry.insert(RlpTrie::from_resolver(
                            account.storage_root,
                            &mut self.resolver.borrow_mut(),
                        )?);
                    }
                    Entry::Occupied(_) => {}
                }

                Ok(Some(account))
            }
        }
    }

    /// Returns the storage slot value that corresponds to the given (address, slot) tuple.
    fn storage(&self, address: Address, slot: U256) -> Result<U256, WitnessDbError> {
        let storages = self.storages.borrow();
        // storage() is always be called after account(), so the storage trie must already exist
        let storage_trie = storages.get(&keccak256(address)).unwrap();
        Ok(storage_trie
            .get(keccak256(B256::from(slot)))?
            .unwrap_or(U256::ZERO))
    }

    /// Computes the new state root from the HashedPostState.
    fn calculate_state_root(&mut self, state: HashedPostState) -> Result<B256, StatelessTrieError> {
        #[cfg(feature = "premeasure")]
        crate::premeasure::EXEC_END.record();
        let mut removed_accounts = Vec::new();
        // DET-1 (L5): `state.accounts` is a foldhash HashMap — advice calls
        // (on-demand storage-trie builds) must never be sequenced under
        // unsorted map iteration. Sorting also pins the perm order.
        let mut accounts: Vec<_> = state.accounts.into_iter().collect();
        accounts.sort_unstable_by_key(|(hashed_address, _)| *hashed_address);
        for (hashed_address, account) in accounts {
            // nonexisting accounts must be removed from the state
            let Some(account) = account else {
                removed_accounts.push(hashed_address);
                continue;
            };

            // apply storage changes before computing the storage root
            let storage_root = match state.storages.get(&hashed_address) {
                None => self.storage_trie_mut(hashed_address).unwrap().hash(),
                Some(storage) => {
                    let storage_trie = if storage.wiped {
                        self.clear_storage(hashed_address)
                    } else {
                        self.storage_trie_mut(hashed_address).unwrap()
                    };

                    // DET-2 (L5): sort storage updates by hashed slot.
                    let mut slots: Vec<_> = storage.storage.iter().collect();
                    slots.sort_unstable_by_key(|(hashed_key, _)| *hashed_key);
                    // apply all state modifications
                    for &(hashed_key, value) in &slots {
                        if !value.is_zero() {
                            storage_trie.insert(hashed_key, *value);
                        }
                    }
                    // removals must happen last, otherwise unresolved orphans might still exist
                    // (DET-3: insert-before-remove preserved)
                    for &(hashed_key, value) in &slots {
                        if value.is_zero() {
                            storage_trie.remove(hashed_key);
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
            self.state.insert(hashed_address, account);
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
