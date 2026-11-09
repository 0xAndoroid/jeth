#![expect(clippy::unwrap_used, reason = "test fixtures and assertions")]
#![expect(clippy::many_single_char_names, reason = "pairing exponent notation")]
use super::*;
use alloc::vec::Vec;
use ark_bn254::Fr;
use ark_ff::BigInteger;
use num_bigint::BigUint;

#[test]
fn exponent_and_kernel_identities() {
    let p = BigUint::from_bytes_le(&Fq::MODULUS.to_bytes_le());
    let r = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le());
    let x = BigUint::from(X);
    let one = BigUint::from(1u8);
    let m = p.pow(4) - p.pow(2) + &one;
    let k = &m / &r;
    assert_eq!(&k * &r, m);
    assert_eq!(&p - 6u8 * x.pow(2), r);
    let mut a = r.clone();
    let mut b = m;
    while b != BigUint::default() {
        (a, b) = (b.clone(), a % b);
    }
    assert_eq!(a, r);
    let root = BigUint::from_bytes_le(
        &ROOT_EXP
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect::<Vec<_>>(),
    );
    assert_eq!((&r * root) % &k, one);
    // Arkworks uses this multiple of k for its hard exponent. Its multiplier
    // is coprime to r, so it tests the same target-group identity.
    let c = 2u8 * &x * (6u8 * x.pow(2) + 3u8 * &x + 1u8);
    let hard = p.pow(3) * (12u8 * x.pow(3) + 6u8 * x.pow(2) + 4u8 * &x - 1u8)
        + p.pow(2) * (12u8 * x.pow(3) + 6u8 * x.pow(2) + 6u8 * &x)
        + &p * (12u8 * x.pow(3) + 6u8 * x.pow(2) + 4u8 * &x)
        + (12u8 * x.pow(3) + 12u8 * x.pow(2) + 6u8 * &x + 1u8);
    assert_eq!(hard, &c * &k);
    let mut a = c;
    let mut b = r;
    while b != BigUint::default() {
        (a, b) = (b.clone(), a % b);
    }
    assert_eq!(a, one);
}

#[test]
fn witnesses_match_final_exponentiation_and_reject_mutations() {
    assert!(!check_witness(&Fq12::zero(), &Fq12::one()));
    assert!(!check_witness(&Fq12::one(), &Fq12::zero()));
    assert!(check_witness(&Fq12::one(), &Fq12::one()));
    assert!(!check(&Fq12::zero()));
    for seed in 1..=128u64 {
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
            let expected = Bn254::final_exponentiation(MillerLoopOutput(f))
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
