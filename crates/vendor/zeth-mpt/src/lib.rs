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

//! Sparse Merkle Patricia Trie implementation used by the zeth state trie.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod mpt;

#[cfg(feature = "orphan")]
pub use mpt::orphan;
#[cfg(feature = "premeasure")]
pub use mpt::premeasure;
pub use mpt::{decode_header, le_words_32, CachedTrie, DigestResolver, Trie, EMPTY_ROOT_HASH};

/// Keccak of an RLP node whose hash is computed in the proven execution.
/// With the optional guest cache, the guest checks reused prefix bytes and
/// continues from a state it computed earlier. Native hashing is unchanged.
#[inline]
pub fn hash_node_rlp(rlp: &[u8]) -> alloy_primitives::B256 {
    #[cfg(all(
        target_arch = "riscv64",
        target_os = "none",
        feature = "keccak-prefix-cache"
    ))]
    {
        extern "C" {
            fn jeth_mpt_keccak256(bytes: *const u8, len: usize, output: *mut u8);
        }
        let mut digest = alloy_primitives::B256::ZERO;
        // SAFETY: the guest shim reads the live input slice and writes exactly
        // the 32 bytes of this separate digest buffer.
        unsafe {
            jeth_mpt_keccak256(rlp.as_ptr(), rlp.len(), digest.as_mut_ptr());
        }
        digest
    }
    #[cfg(not(all(
        target_arch = "riscv64",
        target_os = "none",
        feature = "keccak-prefix-cache"
    )))]
    {
        #[cfg(all(
            not(target_arch = "riscv64"),
            feature = "keccak-prefix-cache",
            not(test)
        ))]
        unsafe {
            extern "C" {
                fn jeth_record_mpt_prefix(bytes: *const u8, len: usize);
            }
            jeth_record_mpt_prefix(rlp.as_ptr(), rlp.len());
        }
        alloy_primitives::keccak256(rlp)
    }
}
