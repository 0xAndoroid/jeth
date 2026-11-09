//! Regenerate fixed KZG pairing coefficients from Ethereum's existing setup.
//!
//! Run from the workspace root:
//! `cargo run -p jeth-core --example kzg-prepare -- crates/core/src/kzg/g2-prepared.bin`

use ark_bls12_381::{Bls12_381, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::CanonicalDeserialize;
use reth_evm::revm::precompile::bls12_381_const::TRUSTED_SETUP_TAU_G2_BYTES;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .ok_or("expected output filename")?;
    let tau = G2Affine::deserialize_compressed(&TRUSTED_SETUP_TAU_G2_BYTES[..])?;
    let mut bytes = Vec::new();
    for point in [-G2Affine::generator(), tau] {
        let prepared = <Bls12_381 as Pairing>::G2Prepared::from(point);
        assert!(!prepared.infinity);
        assert_eq!(prepared.ell_coeffs.len(), 68);
        for (a, b, c) in prepared.ell_coeffs {
            for fq2 in [a, b, c] {
                for fq in [fq2.c0, fq2.c1] {
                    // Raw Montgomery limbs, in little-endian order, matching the loader.
                    for limb in fq.0 .0 {
                        bytes.extend(limb.to_le_bytes());
                    }
                }
            }
        }
    }
    assert_eq!(bytes.len(), 39_168);
    std::fs::write(output, bytes)?;
    Ok(())
}
