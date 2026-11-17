#![expect(clippy::many_single_char_names, reason = "pairing exponent notation")]
use super::*;
use alloc::vec::Vec;
use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::BigInteger;
use ark_serialize::CanonicalDeserialize;
use num_bigint::BigUint;

#[test]
fn exponent_and_kernel_identities() {
    let p = BigUint::from_bytes_le(&Fq::MODULUS.to_bytes_le());
    let r = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
    let abs_x = BigUint::from(ABS_X);
    let one = BigUint::from(1u8);
    let m = p.pow(4) - p.pow(2) + &one;
    let k = &m / &r;
    assert_eq!(&k * &r, m);
    let lambda = &p + &abs_x;
    let mut a = lambda.clone();
    let mut b = m;
    while b != BigUint::default() {
        (a, b) = (b.clone(), a % b);
    }
    assert_eq!(a, r);
    let root = BigUint::from_bytes_le(
        &ROOT_EXP
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>(),
    );
    assert_eq!((&lambda * root) % &k, one);
    // Arkworks' hard exponent is 3k. Cubing in the order-r target group
    // preserves the identity predicate because r is not divisible by 3.
    let hard = BigUint::from(3u8)
        + (&abs_x + 1u8).pow(2) * (&p - &abs_x) * (abs_x.pow(2) + p.pow(2) - 1u8);
    assert_eq!(hard, &k * 3u8);
    assert_ne!(r % 3u8, BigUint::default());
}

#[test]
fn witnesses_match_final_exponentiation_and_reject_mutations() {
    assert!(!check_witness(&Fq12::zero(), &Fq12::one()));
    assert!(!check_witness(&Fq12::one(), &Fq12::zero()));
    assert!(check_witness(&Fq12::one(), &Fq12::one()));
    assert!(!check(&Fq12::zero()));
    for seed in 1..=4u64 {
        let mut state = seed;
        let raw = Fq12::from_base_prime_field_elems((0..12).map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            Fq::from(state)
        }))
        .unwrap();
        let valid = raw.pow(Fr::MODULUS);
        for f in [raw, valid] {
            let expected = Bls12_381::final_exponentiation(MillerLoopOutput(f))
                .unwrap()
                .0
                .is_one();
            assert_eq!(check(&f), expected);
            assert_eq!(witness(&f).is_some(), expected);
            assert!(!check_witness(&f, &Fq12::zero()));
            assert!(!check_witness(&f, &raw));
        }
        let w = witness(&valid).unwrap();
        assert!(check_witness(&valid, &w));
        assert!(!check_witness(&valid, &(w + Fq12::one())));
    }
}

// The Miller-loop output `verify` computes for c-kzg's correct-proof opening, and the limbs of
// the witness a native build supplies for it.
fn opening() -> (Fq12, [[u64; 6]; 12]) {
    let (c, z, y, p) = crate::kzg::tests::correct_proof();
    let c = G1Affine::deserialize_compressed(&c[..]).unwrap();
    let p = G1Affine::deserialize_compressed(&p[..]).unwrap();
    let left = c.into_group() - G1Affine::generator() * Fr::from_be_bytes_mod_order(&y)
        + p * Fr::from_be_bytes_mod_order(&z);
    let f = Bls12_381::multi_miller_loop(
        [left.into_affine(), p],
        crate::kzg::prepared::fixed_points(),
    )
    .0;
    (f, limbs(&witness(&f).unwrap()))
}

#[test]
fn native_witness_of_a_kzg_opening_is_accepted() {
    let (f, limbs) = opening();
    assert!(check_supplied(&f, 1, || limbs));
}

#[test]
#[should_panic(expected = "invalid pairing residue witness")]
fn altered_witness_limb_aborts() {
    let (f, mut limbs) = opening();
    limbs[0][0] ^= 1;
    check_supplied(&f, 1, || limbs);
}

#[test]
#[should_panic(expected = "canonical pairing witness coefficient")]
fn non_canonical_witness_coefficient_aborts() {
    let (f, mut limbs) = opening();
    let mut coefficient = BigInt(limbs[0]);
    coefficient.add_with_carry(&Fq::MODULUS);
    limbs[0] = coefficient.0;
    check_supplied(&f, 1, || limbs);
}

#[test]
#[should_panic(expected = "pairing witness flag")]
fn witness_flag_above_one_aborts() {
    let (f, limbs) = opening();
    check_supplied(&f, 2, || limbs);
}

#[cfg(feature = "native-advice")]
#[test]
fn recorded_native_advice_is_accepted_and_an_altered_word_aborts() {
    extern crate std;
    let f = opening().0;
    let (_, tape) = crate::advice::native::record(|| check(&f)).unwrap();
    let mut words: Vec<u64> = tape
        .as_chunks()
        .0
        .iter()
        .map(|word| u64::from_le_bytes(*word))
        .collect();
    assert_eq!(words[0], 1);
    assert_eq!(tape.len(), 8 * (1 + 12 * 6));
    let replay = |words: &[u64]| {
        let mut limbs = words[1..].iter();
        check_supplied(&f, words[0], || {
            core::array::from_fn(|_| core::array::from_fn(|_| *limbs.next().unwrap()))
        })
    };
    assert!(replay(&words));
    words[1] ^= 1;
    assert!(std::panic::catch_unwind(|| replay(&words)).is_err());
}
