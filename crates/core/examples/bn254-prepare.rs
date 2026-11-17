//! Recompute the standard BN254 G2 encoding and Miller-loop coefficients.
//!
//! From the workspace root:
//! `cargo run -p jeth-core --example bn254-prepare -- crates/core/src/bn254_pairing/generator.bin`

use ark_bn254::{Bn254, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{BigInteger, PrimeField};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = std::env::args_os()
        .nth(1)
        .ok_or("expected output filename")?;
    let point = G2Affine::generator();
    let mut bytes = Vec::new();
    for value in [point.x.c1, point.x.c0, point.y.c1, point.y.c0] {
        bytes.extend(value.into_bigint().to_bytes_be());
    }
    assert_eq!(bytes.len(), 128);
    let prepared = <Bn254 as Pairing>::G2Prepared::from(point);
    assert!(!prepared.infinity);
    assert_eq!(prepared.ell_coeffs.len(), 87);
    for (a, b, c) in prepared.ell_coeffs {
        for value in [a.c0, a.c1, b.c0, b.c1, c.c0, c.c1] {
            for limb in value.0 .0 {
                bytes.extend(limb.to_le_bytes());
            }
        }
    }
    std::fs::write(output, &bytes)?;
    assert_eq!(bytes.len(), 16_832);
    Ok(())
}
