//! bn254 G1 scalar multiplication for the ecmul precompile (0x07).
//!
//! revm's arkworks backend multiplies through `Affine::mul_bigint`: plain
//! double-and-add over the full 254-bit scalar (~254 doublings + ~127 mixed
//! additions). ark-bn254 ships GLV parameters for G1, so k = k1 + λ·k2 with
//! |k1|, |k2| < 2^128 halves the doublings (128 doublings + ~96 additions from
//! the {P, φ(P), P+φ(P)} table). Same group element, same canonical affine
//! output. Parsing and encoding mirror revm-precompile's `bn254::arkworks`
//! byte for byte, including the two rejection variants.

use ark_bn254::{g1::Config, Fq, Fr, G1Affine};
use ark_ec::{scalar_mul::glv::GLVConfig, AffineRepr};
use ark_ff::{BigInt, PrimeField, Zero};
use reth_evm::revm::precompile::PrecompileHalt;

/// Canonical (< p) big-endian field element; revm's `read_fq` rejection.
fn read_fq(bytes: &[u8]) -> Result<Fq, PrecompileHalt> {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = u64::from_be_bytes(bytes[24 - 8 * i..32 - 8 * i].try_into().unwrap());
    }
    Fq::from_bigint(BigInt::new(limbs)).ok_or(PrecompileHalt::Bn254FieldPointNotAMember)
}

fn write_fq(out: &mut [u8], value: Fq) {
    for (i, limb) in value.into_bigint().0.iter().enumerate() {
        out[24 - 8 * i..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
    }
}

/// `k·P` for the 64-byte affine `point` (x ‖ y big-endian, (0, 0) = infinity)
/// and the raw 32-byte big-endian `scalar`, reduced mod r as revm does.
pub(crate) fn g1_mul(point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
    let x = read_fq(&point[..32])?;
    let y = read_fq(&point[32..64])?;
    let p = if x.is_zero() && y.is_zero() {
        G1Affine::identity()
    } else {
        let p = G1Affine::new_unchecked(x, y);
        if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
            return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
        }
        p
    };
    let k = Fr::from_be_bytes_mod_order(scalar);
    let product = Config::glv_mul_affine(p, k);
    let mut out = [0u8; 64];
    if let Some((x, y)) = product.xy() {
        write_fq(&mut out[..32], x);
        write_fq(&mut out[32..], y);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ark_ec::CurveGroup;
    use reth_evm::revm::precompile::{Crypto, DefaultCrypto};

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    fn random_bytes(state: &mut u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_exact_mut(8) {
            chunk.copy_from_slice(&xorshift(state).to_be_bytes());
        }
        out
    }

    fn encode(point: G1Affine) -> [u8; 64] {
        let mut out = [0u8; 64];
        if let Some((x, y)) = point.xy() {
            write_fq(&mut out[..32], x);
            write_fq(&mut out[32..], y);
        }
        out
    }

    fn check(point: &[u8; 64], scalar: &[u8; 32]) {
        assert_eq!(
            g1_mul(point, scalar),
            DefaultCrypto.bn254_g1_mul(point, scalar),
            "point={point:02x?} scalar={scalar:02x?}"
        );
    }

    #[test]
    fn glv_mul_matches_revm_double_and_add() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let generator = G1Affine::generator();
        let mut points = vec![encode(G1Affine::identity()), encode(generator)];
        for _ in 0..64 {
            let k = random_bytes(&mut state);
            let limbs: [u64; 4] = core::array::from_fn(|i| {
                u64::from_be_bytes(k[24 - 8 * i..32 - 8 * i].try_into().unwrap())
            });
            points.push(encode(generator.mul_bigint(limbs).into_affine()));
        }
        // r and 2^128 straddle the GLV decomposition's coefficient magnitudes.
        let r: [u8; 32] = {
            let mut out = [0u8; 32];
            for (i, limb) in Fr::MODULUS.0.iter().enumerate() {
                out[24 - 8 * i..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
            }
            out
        };
        let mut r_minus_1 = r;
        r_minus_1[31] -= 1;
        let mut r_plus_1 = r;
        r_plus_1[31] += 1;
        let mut two_pow_128 = [0u8; 32];
        two_pow_128[15] = 1;
        let mut two_pow_128_minus_1 = [0u8; 32];
        two_pow_128_minus_1[16..].fill(0xff);
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut two = [0u8; 32];
        two[31] = 2;
        let edge_scalars = [
            [0u8; 32],
            one,
            two,
            r_minus_1,
            r,
            r_plus_1,
            two_pow_128,
            two_pow_128_minus_1,
            [0xff; 32],
        ];
        for point in &points {
            for scalar in &edge_scalars {
                check(point, scalar);
            }
        }
        for _ in 0..10_000 {
            let point = &points[xorshift(&mut state) as usize % points.len()];
            check(point, &random_bytes(&mut state));
        }

        // Rejections: off-curve point, non-canonical coordinate (x = p).
        let mut off_curve = [0u8; 64];
        off_curve[31] = 1;
        off_curve[63] = 1;
        check(&off_curve, &one);
        let mut non_canonical = [0u8; 64];
        for (i, limb) in Fq::MODULUS.0.iter().enumerate() {
            non_canonical[24 - 8 * i..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
        }
        non_canonical[63] = 2;
        check(&non_canonical, &one);
        assert_eq!(
            g1_mul(&off_curve, &one),
            Err(PrecompileHalt::Bn254AffineGFailedToCreate)
        );
        assert_eq!(
            g1_mul(&non_canonical, &one),
            Err(PrecompileHalt::Bn254FieldPointNotAMember)
        );
    }
}
