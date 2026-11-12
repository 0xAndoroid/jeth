//! bn254 G1 scalar multiplication for the ecmul precompile (0x07).
//!
//! The existing bn254 GLV parameters split the scalar into two short signed
//! components. A shared signed-window loop uses affine odd-multiple tables;
//! the endomorphism derives the second table from the first after one batch
//! normalization. Parsing, scalar reduction and encoding retain revm's
//! canonical-input checks and failure variants.

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
    let product = window_glv_mul(p, k);
    let mut out = [0u8; 64];
    if let Some((x, y)) = product.xy() {
        write_fq(&mut out[..32], x);
        write_fq(&mut out[32..], y);
    }
    Ok(out)
}

/// Shared signed-window loop for the two existing bn254 GLV components.
fn window_glv_mul(p: G1Affine, k: Fr) -> G1Affine {
    use alloc::vec::Vec;
    use ark_bn254::G1Projective;
    use ark_ec::CurveGroup;
    use ark_ff::AdditiveGroup;

    const WIDTH: usize = 4;
    if p.is_zero() || k.is_zero() {
        return G1Affine::identity();
    }
    if k == Fr::from(1u64) {
        return p;
    }
    let ((positive_1, k1), (positive_2, k2)) = Config::scalar_decomposition(k);
    let digits_1 = sparse_window_digits::<WIDTH>(k1.into_bigint());
    let digits_2 = sparse_window_digits::<WIDTH>(k2.into_bigint());

    // Normalize only the odd multiples of P. The endomorphism then gives the
    // second affine table without another inversion.
    let mut odd = Vec::with_capacity(1 << (WIDTH - 2));
    odd.push(p.into_group());
    let twice = odd[0].double();
    for i in 1..(1 << (WIDTH - 2)) {
        odd.push(odd[i - 1] + twice);
    }
    let first = G1Projective::normalize_batch(&odd);
    let second: Vec<_> = first.iter().map(Config::endomorphism_affine).collect();
    let mut result = G1Projective::zero();
    for i in (0..digits_1.len().max(digits_2.len())).rev() {
        result.double_in_place();
        for (digits, table, positive) in [
            (&digits_1, &first, positive_1),
            (&digits_2, &second, positive_2),
        ] {
            let digit = digits.get(i).copied().unwrap_or(0);
            if digit != 0 {
                let point = table[(digit.unsigned_abs() as usize - 1) / 2];
                result += if (digit < 0) != !positive {
                    -point
                } else {
                    point
                };
            }
        }
    }
    result.into_affine()
}

/// Skip the window-sized zero run guaranteed after each nonzero wNAF digit.
fn sparse_window_digits<const WIDTH: usize>(mut value: ark_ff::BigInt<4>) -> alloc::vec::Vec<i64> {
    use ark_ff::BigInteger;
    let mut digits = alloc::vec::Vec::new();
    let mut position = 0usize;
    while !value.is_zero() {
        if value.is_even() {
            value.div2();
            position += 1;
            continue;
        }
        let low = (value.0[0] & ((1u64 << WIDTH) - 1)) as i64;
        let digit = if low >= 1 << (WIDTH - 1) {
            low - (1 << WIDTH)
        } else {
            low
        };
        digits.resize(position, 0);
        digits.push(digit);
        if digit > 0 {
            value.sub_with_borrow(&ark_ff::BigInt::from(digit as u64));
        } else {
            value.add_with_carry(&ark_ff::BigInt::from((-digit) as u64));
        }
        value.divn(WIDTH as u32);
        position += WIDTH;
    }
    digits
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

    #[test]
    fn field_square_matches_original_montgomery() {
        use ark_bn254::FqConfig;
        use ark_ff::{AdditiveGroup, Field, MontConfig};
        let mut state = 0x54_32_BA_25_4A_11_2026u64;
        for a in [Fq::ZERO, Fq::ONE, -Fq::ONE]
            .into_iter()
            .chain((0..10_000).map(|_| Fq::from_be_bytes_mod_order(&random_bytes(&mut state))))
        {
            let mut original = a;
            <FqConfig as MontConfig<4>>::square_in_place(&mut original);
            assert_eq!(a.square(), original);
        }
    }

    fn encode_g2(point: ark_bn254::G2Affine) -> [u8; 128] {
        let mut out = [0u8; 128];
        if let Some((x, y)) = point.xy() {
            for (chunk, value) in out.chunks_exact_mut(32).zip([x.c1, x.c0, y.c1, y.c0]) {
                write_fq(chunk, value);
            }
        }
        out
    }

    #[test]
    fn bn254_precompile_edges_and_gas() {
        use ark_bn254::{Fq2, G2Affine};
        use ark_ff::Field;
        use reth_evm::revm::precompile::bn254::{run_add, run_mul, run_pair};
        let p = G1Affine::generator();
        let zero = encode(G1Affine::identity());
        let encoded = encode(p);
        let negative = encode(-p);
        assert_eq!(
            DefaultCrypto.bn254_g1_add(&encoded, &zero).unwrap(),
            encoded
        );
        assert_eq!(
            DefaultCrypto.bn254_g1_add(&encoded, &negative).unwrap(),
            zero
        );
        assert_eq!(
            DefaultCrypto.bn254_g1_add(&encoded, &encoded).unwrap(),
            encode((p + p).into_affine())
        );
        for (left, right) in [
            (zero, zero),
            (encoded, zero),
            (encoded, encoded),
            (encoded, negative),
        ] {
            let input = [left.as_slice(), right.as_slice()].concat();
            let result = run_add(&input, 150, 150).unwrap();
            assert_eq!(result.gas_used, 150);
            assert_eq!(
                result.bytes.as_ref(),
                DefaultCrypto.bn254_g1_add(&left, &right).unwrap()
            );
            assert_eq!(run_add(&input, 150, 149), Err(PrecompileHalt::OutOfGas));
        }
        for scalar in [[0u8; 32], [0xff; 32]] {
            let input = [encoded.as_slice(), scalar.as_slice()].concat();
            let result = run_mul(&input, 6000, 6000).unwrap();
            assert_eq!(result.gas_used, 6000);
            assert_eq!(result.bytes.as_ref(), g1_mul(&encoded, &scalar).unwrap());
            assert_eq!(run_mul(&input, 6000, 5999), Err(PrecompileHalt::OutOfGas));
        }
        let q = encode_g2(G2Affine::generator());
        let single = [encoded.as_slice(), q.as_slice()].concat();
        let cancelled = [single.as_slice(), negative.as_slice(), q.as_slice()].concat();
        let infinity = [zero.as_slice(), q.as_slice()].concat();
        for (input, expected) in [
            (vec![], true),
            (single, false),
            (cancelled, true),
            (infinity, true),
        ] {
            let gas = 45000 + 34000 * (input.len() / 192) as u64;
            let result = run_pair(&input, 34000, 45000, gas).unwrap();
            assert_eq!(result.gas_used, gas);
            let mut output = [0u8; 32];
            output[31] = u8::from(expected);
            assert_eq!(result.bytes.as_ref(), output);
            assert_eq!(
                run_pair(&input, 34000, 45000, gas - 1),
                Err(PrecompileHalt::OutOfGas)
            );
        }
        assert_eq!(
            run_pair(&[0u8; 191], 34000, 45000, u64::MAX),
            Err(PrecompileHalt::Bn254PairLength)
        );
        let non_subgroup = (0..1000u64)
            .filter_map(|i| {
                G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(i), Fq::ONE), false)
            })
            .find(|q| !q.is_in_correct_subgroup_assuming_on_curve())
            .expect("deterministically find an on-curve point outside G2");
        assert!(non_subgroup.is_on_curve());
        let bad_q = encode_g2(non_subgroup);
        for g1 in [zero, encoded] {
            assert_eq!(
                DefaultCrypto.bn254_pairing_check(&[(&g1, &bad_q)]),
                Err(PrecompileHalt::Bn254AffineGFailedToCreate)
            );
        }
        let mut invalid = [0u8; 64];
        for (i, limb) in Fq::MODULUS.0.iter().enumerate() {
            invalid[24 - 8 * i..32 - 8 * i].copy_from_slice(&limb.to_be_bytes());
        }
        assert_eq!(
            DefaultCrypto.bn254_g1_add(&invalid, &zero),
            Err(PrecompileHalt::Bn254FieldPointNotAMember)
        );
        assert_eq!(
            DefaultCrypto.bn254_pairing_check(&[(&invalid, &q)]),
            Err(PrecompileHalt::Bn254FieldPointNotAMember)
        );
    }

    #[test]
    fn sparse_digits_match_arkworks_wnaf() {
        use ark_ff::{AdditiveGroup, BigInteger, Field};
        let mut state = 0x8877_6655_4433_2211u64;
        for scalar in [Fr::ZERO, Fr::ONE, -Fr::ONE]
            .into_iter()
            .chain((0..10_000).map(|_| Fr::from_be_bytes_mod_order(&random_bytes(&mut state))))
        {
            let n = scalar.into_bigint();
            assert_eq!(sparse_window_digits::<4>(n), n.find_wnaf(4).unwrap());
        }
        for bit in 0..254 {
            let mut n = BigInt::<4>::from(0u64);
            n.0[bit / 64] = 1u64 << (bit % 64);
            for value in [
                n,
                {
                    let mut x = n;
                    x.sub_with_borrow(&BigInt::from(1u64));
                    x
                },
                {
                    let mut x = n;
                    x.add_with_carry(&BigInt::from(1u64));
                    x
                },
            ] {
                assert_eq!(
                    sparse_window_digits::<4>(value),
                    value.find_wnaf(4).unwrap()
                );
            }
        }
    }
}
