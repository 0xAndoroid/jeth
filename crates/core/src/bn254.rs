//! BN254 G1 scalar multiplication with a signed-window GLV loop.

use ark_bn254::{g1::Config, Fq, Fr, G1Affine};
use ark_ec::{scalar_mul::glv::GLVConfig, AffineRepr};
use ark_ff::{AdditiveGroup, BigInt, BigInteger, Field, PrimeField, Zero};
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
    // prefix. Affine additions check an advised slope locally.
    let table_len = digits_1
        .iter()
        .chain(&digits_2)
        .map(|digit| digit.unsigned_abs() as usize / 2 + 1)
        .max()
        .unwrap_or(1);
    let mut first = [point; 4];
    let twice = affine_add(point, point);
    for i in 1..table_len {
        first[i] = affine_add(first[i - 1], twice);
    }
    let second = first.map(|point| Config::endomorphism_affine(&point));
    let mut result = G1Affine::identity();
    for bit in (0..digits_1.len().max(digits_2.len())).rev() {
        result = affine_add(result, result);
        for (digits, table, positive) in [
            (&digits_1, &first, positive_1),
            (&digits_2, &second, positive_2),
        ] {
            let digit = digits.get(bit).copied().unwrap_or(0);
            if digit != 0 {
                let addend = table[(digit.unsigned_abs() / 2) as usize];
                result = affine_add(
                    result,
                    if (digit > 0) == positive {
                        addend
                    } else {
                        -addend
                    },
                );
            }
        }
    }
    result
}

/// Both inputs are valid curve points. Handle infinity, inverse pairs, and
/// doubling before consuming advice, so every advised denominator is nonzero.
fn affine_add(p: G1Affine, q: G1Affine) -> G1Affine {
    if p.is_zero() {
        return q;
    }
    if q.is_zero() {
        return p;
    }
    let (numerator, denominator) = if p.x == q.x {
        if p.y != q.y || p.y.is_zero() {
            return G1Affine::identity();
        }
        let xx = p.x.square();
        (xx.double() + xx, p.y.double())
    } else {
        (q.y - p.y, q.x - p.x)
    };
    let slope = advised_slope(numerator, denominator);
    let x = slope.square() - p.x - q.x;
    let y = slope * (p.x - x) - p.y;
    G1Affine::new_unchecked(x, y)
}

#[cfg_attr(
    any(feature = "compute_advice", not(target_arch = "riscv64")),
    expect(clippy::expect_used, reason = "affine_add excludes zero denominators")
)]
fn advised_slope(numerator: Fq, denominator: Fq) -> Fq {
    use crate::advice::advice_u64;
    #[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
    let slope = (numerator * denominator.inverse().expect("nonzero slope denominator"))
        .0
         .0;
    let raw = BigInt(core::array::from_fn(|i| {
        let _ = i;
        advice_u64!(slope[i])
    }));
    checked_slope(numerator, denominator, raw)
}

/// The caller establishes denominator != 0. This equation then uniquely
/// determines the slope; no batch challenge or deferred check is involved.
fn checked_slope(numerator: Fq, denominator: Fq, raw: BigInt<4>) -> Fq {
    // The tape carries the Montgomery residue, not the canonical integer value.
    assert!(raw < Fq::MODULUS, "noncanonical slope advice");
    let slope = Fq::new_unchecked(raw);
    assert!(slope * denominator == numerator, "invalid slope advice");
    slope
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use ark_ec::CurveGroup;
    use reth_evm::revm::precompile::{Crypto, DefaultCrypto};

    #[test]
    fn affine_add_handles_group_edge_cases() {
        let g = G1Affine::generator();
        let zero = G1Affine::identity();
        assert_eq!(affine_add(zero, zero), zero);
        assert_eq!(affine_add(zero, g), g);
        assert_eq!(affine_add(g, zero), g);
        assert_eq!(affine_add(g, -g), zero);
        assert_eq!(affine_add(g, g), g.into_group().double().into_affine());
        assert_eq!(affine_add(-g, -g), (-g).into_group().double().into_affine());
    }

    #[test]
    fn zero_slope_is_valid_when_numerator_is_zero() {
        assert_eq!(
            checked_slope(Fq::zero(), Fq::from(7u64), BigInt::new([0; 4])),
            Fq::zero()
        );
    }

    #[test]
    #[should_panic(expected = "invalid slope advice")]
    fn wrong_canonical_slope_is_rejected() {
        checked_slope(Fq::from(1u64), Fq::from(2u64), BigInt::new([0; 4]));
    }

    #[test]
    #[should_panic(expected = "noncanonical slope advice")]
    fn noncanonical_slope_is_rejected() {
        checked_slope(Fq::zero(), Fq::from(2u64), Fq::MODULUS);
    }

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
