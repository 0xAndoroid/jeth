//! Block sender recovery: verify each tx signature against a host-supplied
//! uncompressed pubkey and derive the sender address.
//!
//! Local reimplementation of `stateless::recover_block_with_public_keys` so the
//! signature check itself is pluggable:
//! - default: alloy/k256 `verify_and_compute_signer_unchecked` (native + fallback)
//! - `secp-inline` feature: Jolt's secp256k1 inline `ecdsa_verify` (guest builds) —
//!   same acceptance set (validated pubkey on curve, r/s canonical nonzero, ECDSA
//!   check) plus the identical EIP-2 low-s gate applied here for both paths.

use crate::UncompressedPublicKey;
use alloc::vec::Vec;
use alloy_primitives::Address;
use reth_chainspec::EthereumHardforks;
use reth_ethereum_primitives::{Block, TransactionSigned};
use reth_primitives_traits::{Block as _, RecoveredBlock};
use stateless::validation::StatelessValidationError;

/// Verifies all transactions against the supplied public keys; returns a
/// [`RecoveredBlock`] with the derived senders.
pub fn recover_block(
    block: Block,
    public_keys: Vec<UncompressedPublicKey>,
) -> Result<RecoveredBlock<Block>, StatelessValidationError> {
    if block.body().transactions.len() != public_keys.len() {
        return Err(StatelessValidationError::Custom(
            "Number of public keys must match number of transactions",
        ));
    }

    let chain_spec = crate::mainnet_spec();
    let is_homestead = chain_spec.is_homestead_active_at_block(block.header.number);

    let senders = public_keys
        .iter()
        .zip(block.body().transactions())
        .map(|(vk, tx)| verify_and_compute_sender(vk, tx, is_homestead))
        .collect::<Result<Vec<_>, _>>()?;

    let block_hash = block.hash_slow();
    Ok(RecoveredBlock::new(block, senders, block_hash))
}

fn verify_and_compute_sender(
    vk: &UncompressedPublicKey,
    tx: &TransactionSigned,
    is_homestead: bool,
) -> Result<Address, StatelessValidationError> {
    let sig = tx.signature();

    // EIP-2: non-normalized (high-s) signatures are only valid pre-homestead.
    let sig_is_normalized = sig.normalize_s().is_none();
    if is_homestead && !sig_is_normalized {
        return Err(StatelessValidationError::HomesteadSignatureNotNormalized);
    }
    let sig_hash = tx.signature_hash();

    #[cfg(feature = "secp-inline")]
    {
        inline_verify(&vk.0, sig, sig_hash)
    }
    #[cfg(not(feature = "secp-inline"))]
    {
        alloy_consensus::crypto::secp256k1::verify_and_compute_signer_unchecked(
            &vk.0, sig, sig_hash,
        )
        .map_err(|_| StatelessValidationError::SignerRecovery)
    }
}

/// ECDSA verification via the Jolt secp256k1 inline.
///
/// `ecdsa_verify` validates everything internally: r/s/z canonical and nonzero,
/// pubkey coordinates canonical, point on curve and not at infinity, then checks
/// `r == x(u1·G + u2·Q) mod n`. Any failure → `SignerRecovery` (guest panics).
#[cfg(feature = "secp-inline")]
fn inline_verify(
    vk: &[u8; 65],
    sig: &alloy_primitives::Signature,
    sig_hash: alloy_primitives::B256,
) -> Result<Address, StatelessValidationError> {
    use alloy_primitives::{keccak256, U256};
    use jolt_inlines_secp256k1::{Secp256k1Fr, Secp256k1Point};

    const SECP256K1_ORDER: U256 = U256::from_be_bytes([
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ]);

    if vk[0] != 0x04 {
        return Err(StatelessValidationError::SignerRecovery);
    }

    // Point limbs: [x0..x3, y0..y3], little-endian u64 limbs.
    let x = U256::from_be_slice(&vk[1..33]);
    let y = U256::from_be_slice(&vk[33..65]);
    let mut q_limbs = [0u64; 8];
    q_limbs[..4].copy_from_slice(x.as_limbs());
    q_limbs[4..].copy_from_slice(y.as_limbs());
    let q = Secp256k1Point::from_u64_arr(&q_limbs)
        .map_err(|_| StatelessValidationError::SignerRecovery)?;

    // z = sighash as integer, reduced mod n (n < 2^256 < 2n → one subtraction).
    let mut z = U256::from_be_bytes(sig_hash.0);
    if z >= SECP256K1_ORDER {
        z -= SECP256K1_ORDER;
    }
    let z = Secp256k1Fr::from_u64_arr(z.as_limbs())
        .map_err(|_| StatelessValidationError::SignerRecovery)?;
    let r = Secp256k1Fr::from_u64_arr(sig.r().as_limbs())
        .map_err(|_| StatelessValidationError::SignerRecovery)?;
    let s = Secp256k1Fr::from_u64_arr(sig.s().as_limbs())
        .map_err(|_| StatelessValidationError::SignerRecovery)?;

    jolt_inlines_secp256k1::ecdsa_verify(z, r, s, q)
        .map_err(|_| StatelessValidationError::SignerRecovery)?;

    // Sender = keccak256(uncompressed point without the 0x04 tag)[12..].
    let digest = keccak256(&vk[1..]);
    Ok(Address::from_slice(&digest[12..]))
}
