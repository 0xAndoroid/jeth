//! BN254 G1 scalar multiplication with a signed-window GLV loop.

use ark_bn254::{g1::Config, Fq, Fr, G1Affine, G1Projective};
use ark_ec::{scalar_mul::glv::GLVConfig, AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, BigInt, BigInteger, PrimeField, Zero};
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
    let product = windowed_glv(p, k);
    let mut out = [0u8; 64];
    if let Some((x, y)) = product.xy() {
        write_fq(&mut out[..32], x);
        write_fq(&mut out[32..], y);
    }
    Ok(out)
}

#[expect(
    clippy::expect_used,
    reason = "literal width four is accepted by find_wnaf"
)]
fn windowed_glv(point: G1Affine, scalar: Fr) -> G1Affine {
    if point.is_zero() || scalar.is_zero() {
        return G1Affine::identity();
    }
    let ((positive_1, k1), (positive_2, k2)) = Config::scalar_decomposition(scalar);
    let digits_1 = k1.into_bigint().find_wnaf(4).expect("valid window width");
    let digits_2 = k2.into_bigint().find_wnaf(4).expect("valid window width");
    // Width four uses at most P, 3P, 5P, 7P. Small scalars need only a
    // prefix; normalize it together for mixed additions in the loop.
    let table_len = digits_1
        .iter()
        .chain(&digits_2)
        .map(|digit| digit.unsigned_abs() as usize / 2 + 1)
        .max()
        .unwrap_or(1);
    let mut odd = [point.into_group(); 4];
    let twice = odd[0].double();
    for i in 1..table_len {
        odd[i] = odd[i - 1] + twice;
    }
    let first = G1Projective::normalize_batch(&odd[..table_len]);
    let second = first
        .iter()
        .map(Config::endomorphism_affine)
        .collect::<alloc::vec::Vec<_>>();
    let mut result = G1Projective::zero();
    for bit in (0..digits_1.len().max(digits_2.len())).rev() {
        result.double_in_place();
        for (digits, table, positive) in [
            (&digits_1, &first, positive_1),
            (&digits_2, &second, positive_2),
        ] {
            let digit = digits.get(bit).copied().unwrap_or(0);
            if digit != 0 {
                let addend = table[(digit.unsigned_abs() / 2) as usize];
                result += if (digit > 0) == positive {
                    addend
                } else {
                    -addend
                };
            }
        }
    }
    result.into_affine()
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
