//! Preparation of the standard BN254 G2 generator.
//!
//! The binary contains its 128-byte EIP-197 encoding, then the Miller-loop
//! coefficients as little-endian Montgomery limbs. Tests recompute both.
//! Regenerate with the `bn254-prepare` example.

use super::Prepared;
use ark_bn254::{Fq, Fq2};
use ark_ff::BigInt;

const COEFFICIENTS: usize = 87;
const WORDS: usize = COEFFICIENTS * 3 * 2 * 4;
const BYTES: &[u8; 128 + WORDS * 8] = include_bytes!("generator.bin");

pub(super) static ENCODING: [u8; 128] = {
    let mut encoding = [0; 128];
    let mut i = 0;
    while i < encoding.len() {
        encoding[i] = BYTES[i];
        i += 1;
    }
    encoding
};

// Align coefficient loads as words before guest execution; decoding bytes
// at runtime would add expensive byte accesses to the RISC-V trace.
static DATA: [u64; WORDS] = {
    let mut words = [0; WORDS];
    let mut i = 0;
    while i < words.len() {
        let j = 128 + 8 * i;
        words[i] = u64::from_le_bytes([
            BYTES[j],
            BYTES[j + 1],
            BYTES[j + 2],
            BYTES[j + 3],
            BYTES[j + 4],
            BYTES[j + 5],
            BYTES[j + 6],
            BYTES[j + 7],
        ]);
        i += 1;
    }
    words
};

pub(super) fn prepared() -> Prepared {
    let mut offset = 0;
    let mut field = || {
        let limbs = core::array::from_fn(|_| {
            let limb = DATA[offset];
            offset += 1;
            limb
        });
        Fq::new_unchecked(BigInt(limbs))
    };
    let ell_coeffs = (0..COEFFICIENTS)
        .map(|_| {
            let a = Fq2::new(field(), field());
            let b = Fq2::new(field(), field());
            let c = Fq2::new(field(), field());
            (a, b, c)
        })
        .collect();
    Prepared {
        ell_coeffs,
        infinity: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G2Affine;
    use ark_ec::AffineRepr;
    use ark_ff::{BigInteger, PrimeField};

    #[test]
    fn table_and_encoding_match_standard_generator() {
        let point = G2Affine::generator();
        let encoding: alloc::vec::Vec<u8> = [point.x.c1, point.x.c0, point.y.c1, point.y.c0]
            .into_iter()
            .flat_map(|value| value.into_bigint().to_bytes_be())
            .collect();
        assert_eq!(&ENCODING[..], encoding);
        assert!(point.is_on_curve());
        assert!(point.is_in_correct_subgroup_assuming_on_curve());
        assert_eq!(prepared(), Prepared::from(point));
    }
}
