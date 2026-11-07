//! KZG verification with scalar multiplication in G1 rather than G2.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{BigInteger, One, PrimeField};
use ark_serialize::CanonicalDeserialize;
use reth_evm::revm::precompile::{
    bls12_381_const::TRUSTED_SETUP_TAU_G2_BYTES, primitives::OnceLock,
};

fn scalar(bytes: &[u8; 32]) -> Option<Fr> {
    let value = Fr::from_be_bytes_mod_order(bytes);
    (value.into_bigint().to_bytes_be().as_slice() == bytes).then_some(value)
}

pub(crate) fn verify(commitment: &[u8; 48], z: &[u8; 32], y: &[u8; 32], proof: &[u8; 48]) -> bool {
    // Keep revm's canonical encodings and subgroup checks for both input points.
    let Ok(commitment) = G1Affine::deserialize_compressed(&commitment[..]) else {
        return false;
    };
    let Ok(proof) = G1Affine::deserialize_compressed(&proof[..]) else {
        return false;
    };
    let Some(z) = scalar(z) else { return false };
    let Some(y) = scalar(y) else { return false };

    static TAU_G2: OnceLock<G2Affine> = OnceLock::new();
    let tau = TAU_G2.get_or_init(|| {
        // This is the same fixed Ethereum ceremony point used by revm.
        #[expect(clippy::expect_used, reason = "fixed valid Ethereum ceremony point")]
        G2Affine::deserialize_compressed_unchecked(&TRUSTED_SETUP_TAU_G2_BYTES[..])
            .expect("valid Ethereum KZG setup point")
    });

    // e(C - yG1, -G2) e(proof, tauG2 - zG2) = 1 iff
    // e(C - yG1 + z*proof, -G2) e(proof, tauG2) = 1.
    // Both pairings now have fixed G2 inputs; no G2 scalar multiplication.
    let left = (commitment.into_group() - G1Affine::generator().mul_bigint(y.into_bigint())
        + proof.mul_bigint(z.into_bigint()))
    .into_affine();
    Bls12_381::multi_pairing([left, proof], [-G2Affine::generator(), *tau])
        .0
        .is_one()
}

#[cfg(test)]
#[path = "kzg/tests.rs"]
mod tests;
