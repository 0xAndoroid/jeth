//! jeth-core: shared host/guest logic — guest input type + stateless block validation.
//!
//! The heavy lifting is `stateless::stateless_validation` (paradigmxyz/stateless):
//! ancestor-header chain checks, pre-state witness reveal against the parent state
//! root, full tx execution (revm), post-execution consensus checks, and post-state
//! root comparison against the block header.

#![no_std]

extern crate alloc;

pub mod advice;
#[cfg(feature = "secp-inline")]
mod bn254;
mod chainspec;
pub mod code_library;
pub mod container;
#[cfg(feature = "secp-inline")]
mod crypto;
#[cfg(feature = "guest-instrument")]
mod instrument;
#[cfg(feature = "premeasure")]
pub mod premeasure;
mod recover;
#[cfg(feature = "secp-inline")]
pub mod recovery_batch;
mod resolver;
pub mod validation;
mod walk;
mod zeth_trie;

pub use zeth_trie::set_trusted_digests;

#[cfg(feature = "secp-inline")]
pub use crypto::{inline_ecrecover, install_jolt_crypto};

use alloc::{sync::Arc, vec::Vec};
use alloy_primitives::Bytes;
use reth_ethereum_primitives::Block;
use reth_evm::EthEvmFactory;
use serde::{Deserialize, Serialize};

pub use chainspec::{mainnet_spec, ChainSpec};
pub use stateless::{
    validation::StatelessValidationError, ExecutionWitness, UncompressedPublicKey,
};

/// Turn a validated JEF view into the existing stateless-validation inputs.
///
/// The view must point into memory that remains live for the validation run.
pub fn from_container(
    view: container::ContainerView<'static>,
) -> Result<(Block, Vec<UncompressedPublicKey>, ExecutionWitness), container::ContainerError> {
    let block = alloy_rlp::decode_exact(view.block_rlp)
        .map_err(|_| container::ContainerError::InvalidBlockRlp)?;
    let signers = view
        .signers
        .iter()
        .map(|record| {
            let mut key = [0; 65];
            key.copy_from_slice(&record[..65]);
            UncompressedPublicKey(key)
        })
        .collect();
    let witness = ExecutionWitness {
        state: view.state.into_iter().map(Bytes::from_static).collect(),
        codes: view.codes.into_iter().map(Bytes::from_static).collect(),
        keys: Vec::new(),
        headers: view.headers.into_iter().map(Bytes::from_static).collect(),
    };
    Ok((block, signers, witness))
}

/// Decode JEF bytes whose backing allocation outlives validation.
pub fn decode_container(bytes: &'static [u8]) -> Result<BlockInput, container::ContainerError> {
    let view = container::ContainerReader::read(bytes)?;
    if view.library_id_lo != code_library::LIBRARY_ID_LO {
        return Err(container::ContainerError::InvalidLibrary);
    }
    let (block, signers, witness) = from_container(view)?;
    Ok(BlockInput {
        block,
        signers,
        witness,
    })
}

/// Trie implementation used for witness reveal + state-root computation.
///
/// `tries::zeth::SparseState` (zeth-mpt backed) — NOT the default reth
/// `StatelessSparseTrie`: geth/zeth-proxy witnesses don't carry the storage
/// exclusion proofs the reth sparse trie demands for absent-slot reads, while
/// the zeth MPT resolves absence from the revealed partial trie directly
/// (this is the trie zeth 0.3 runs in production on risc0).
/// (Vendored from `tries::zeth` with the trusted-digest extension — see
/// `zeth_trie.rs`; behavior without trusted digests is identical.)
#[cfg(not(feature = "guest-instrument"))]
pub type Trie = zeth_trie::SparseState;
/// Instrumented variant (markers + keccak checkpoints around reveal/root).
#[cfg(feature = "guest-instrument")]
pub type Trie = instrument::InstrumentedTrie;

/// EVM config type used for both native and guest validation.
pub type EthEvmConfig = reth_evm_ethereum::EthEvmConfig<ChainSpec, EthEvmFactory>;

/// Host-side form of everything needed to statelessly validate one block.
///
/// JEF encodes the block as canonical RLP and the witness as borrowed byte records.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockInput {
    /// The block to validate.
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
    let mut input = input;
    code_library::append_raw_codes(&mut input.witness.codes);
    let chain_spec = Arc::new(mainnet_spec());
    let evm_config = EthEvmConfig::new(chain_spec.clone());

    let output = stateless::stateless_validation_with_trie::<Trie, _, _>(
        input.block,
        input.signers,
        input.witness,
        chain_spec,
        evm_config,
    )?;

    #[cfg(feature = "secp-inline")]
    recovery_batch::verify();

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
///
/// Runs jeth's vendored validation loop ([`validation::validate_recovered_pertx`])
/// — behaviorally identical to upstream `stateless` 6e55612 (the native gate
/// cross-checks it on every bench), with optional per-tx cycle markers and lazy
/// bytecode analysis.
pub fn validate_recovered(
    recovered: reth_primitives_traits::RecoveredBlock<Block>,
    witness: ExecutionWitness,
) -> Result<ValidationResult, StatelessValidationError> {
    let chain_spec = Arc::new(mainnet_spec());
    let evm_config = EthEvmConfig::new(chain_spec.clone());

    let output = validation::validate_recovered_pertx(recovered, witness, chain_spec, evm_config)?;

    #[cfg(feature = "secp-inline")]
    recovery_batch::verify();

    Ok(ValidationResult {
        block_hash: output.block_hash.0,
        gas_used: output.gas_used,
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
