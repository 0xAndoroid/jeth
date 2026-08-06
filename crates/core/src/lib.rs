//! jeth-core: shared host/guest logic — guest input type + stateless block validation.
//!
//! The heavy lifting is `stateless::stateless_validation` (paradigmxyz/stateless):
//! ancestor-header chain checks, pre-state witness reveal against the parent state
//! root, full tx execution (revm), post-execution consensus checks, and post-state
//! root comparison against the block header.

#![no_std]

extern crate alloc;

mod chainspec;
#[cfg(feature = "secp-inline")]
mod crypto;
mod recover;

#[cfg(feature = "secp-inline")]
pub use crypto::install_jolt_crypto;

use alloc::{sync::Arc, vec::Vec};
use reth_ethereum_primitives::Block;
use reth_evm::EthEvmFactory;
use serde::{Deserialize, Serialize};

pub use chainspec::{mainnet_spec, ChainSpec};
pub use stateless::{
    validation::StatelessValidationError, ExecutionWitness, UncompressedPublicKey,
};

/// Trie implementation used for witness reveal + state-root computation.
///
/// `tries::zeth::SparseState` (zeth-mpt backed) — NOT the default reth
/// `StatelessSparseTrie`: geth/zeth-proxy witnesses don't carry the storage
/// exclusion proofs the reth sparse trie demands for absent-slot reads, while
/// the zeth MPT resolves absence from the revealed partial trie directly
/// (this is the trie zeth 0.3 runs in production on risc0).
pub type Trie = tries::zeth::SparseState;

/// EVM config type used for both native and guest validation.
pub type EthEvmConfig = reth_evm_ethereum::EthEvmConfig<ChainSpec, EthEvmFactory>;

/// Everything the guest needs to statelessly validate one block.
///
/// Serialized with postcard. The block is RLP bytes under binary serializers
/// (`Block`'s derived serde is binary-codec-hostile — zeth learned this on risc0).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockInput {
    /// The block to validate (RLP-encoded in binary formats).
    #[serde(with = "rlp_block")]
    pub block: Block,
    /// Host-recovered uncompressed secp256k1 public key per transaction (tx order).
    /// The guest *verifies* each tx signature against these instead of running
    /// in-guest ecrecover — same soundness, cheaper.
    pub signers: Vec<UncompressedPublicKey>,
    /// Execution witness: trie nodes, contract codes, (unused) keys, ancestor headers.
    pub witness: ExecutionWitness,
}

/// Compact result returned from the guest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Hash of the validated block.
    pub block_hash: [u8; 32],
    /// Cumulative gas used by the block (from execution, cross-checked against the
    /// header by `validate_block_post_execution`).
    pub gas_used: u64,
}

/// Statelessly validate `input.block` against mainnet rules.
///
/// Errors (rather than returning) on ANY consensus failure: bad ancestor chain,
/// witness/pre-state mismatch, execution failure, receipts/bloom/gas mismatch,
/// or post-state root mismatch. The guest wrapper panics on error, which the
/// tracer surfaces as a failed run.
pub fn validate_mainnet(input: BlockInput) -> Result<ValidationResult, StatelessValidationError> {
    let chain_spec = Arc::new(mainnet_spec());
    let evm_config = EthEvmConfig::new(chain_spec.clone());

    let output = stateless::stateless_validation_with_trie::<Trie, _, _>(
        input.block,
        input.signers,
        input.witness,
        chain_spec,
        evm_config,
    )?;

    Ok(ValidationResult {
        block_hash: output.block_hash.0,
        gas_used: output.execution_output.result.gas_used,
    })
}

/// Verify tx signatures against host-supplied pubkeys and derive senders
/// (separable phase for cycle accounting). Uses the Jolt secp256k1 inline when
/// the `secp-inline` feature is on (guest builds), alloy/k256 otherwise.
pub use recover::recover_block;

/// Validate an already-recovered block (the non-signature phases).
pub fn validate_recovered(
    recovered: reth_primitives_traits::RecoveredBlock<Block>,
    witness: ExecutionWitness,
) -> Result<ValidationResult, StatelessValidationError> {
    let chain_spec = Arc::new(mainnet_spec());
    let evm_config = EthEvmConfig::new(chain_spec.clone());

    let output = stateless::stateless_validation_recovered_with_trie::<Trie, _, _>(
        recovered, witness, chain_spec, evm_config,
    )?;

    Ok(ValidationResult {
        block_hash: output.block_hash.0,
        gas_used: output.execution_output.result.gas_used,
    })
}

/// Serde adapter: RLP bytes for binary serializers, derived serde for JSON.
mod rlp_block {
    use alloc::vec::Vec;
    use reth_ethereum_primitives::Block;
    use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(block: &Block, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            block.serialize(s)
        } else {
            s.serialize_bytes(&alloy_rlp::encode(block))
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Block, D::Error> {
        if d.is_human_readable() {
            Block::deserialize(d)
        } else {
            d.deserialize_byte_buf(RlpBytesVisitor)
        }
    }

    struct RlpBytesVisitor;

    impl<'de> de::Visitor<'de> for RlpBytesVisitor {
        type Value = Block;

        fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("RLP-encoded block bytes")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Block, E> {
            alloy_rlp::decode_exact(v).map_err(E::custom)
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Block, E> {
            self.visit_bytes(&v)
        }
    }

    /// Encode a block as RLP (host-side helper, e.g. for size stats).
    pub fn encode(block: &Block) -> Vec<u8> {
        alloy_rlp::encode(block)
    }
}

pub use rlp_block::encode as encode_block_rlp;
