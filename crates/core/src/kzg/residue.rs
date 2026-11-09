//! Check the final-exponentiation identity with a locally verified root witness.
//!
//! Write M = p^4 - p^2 + 1 and k = M/r. For nonzero Miller output f, its easy
//! exponentiation g = f^((p^6 - 1)(p^2 + 1)) belongs to the order-M subgroup H.
//! The pairing is one iff g^k = 1. For BLS12-381, lambda = p - x satisfies
//! gcd(lambda, M) = r, so the image of w -> w^lambda on H is exactly the
//! order-k subgroup. Thus g^k = 1 iff some w in H satisfies w^lambda = g.
//!
//! Check membership before using cyclotomic formulas. With h = f^(p^2 + 1),
//! check w^lambda * h = h^(p^6), avoiding an inverse in the guest. The native
//! advice pass finds w with an exponent inverse modulo k. The interpreted
//! compute-advice pass omits this costly generation and selects the original
//! final exponentiation instead. If no witness is supplied, advice cannot
//! assert a negative result. Point and scalar validation remain in `verify`.
use crate::advice::advice_u64;
use ark_bls12_381::{Bls12_381, Fq, Fq12};
use ark_ec::pairing::{MillerLoopOutput, Pairing};
use ark_ff::{BigInt, CyclotomicMultSubgroup, Field, One, PrimeField, Zero};

const ABS_X: u64 = 0xd201_0000_0001_0000;

// (p - x)^(-1) mod ((p^4 - p^2 + 1)/r), in little-endian u64 limbs.
#[cfg(not(target_arch = "riscv64"))]
const ROOT_EXP: [u64; 20] = [
    0x4e66_2c16_110d_608f,
    0x8eab_f4a0_ee70_4cf4,
    0xd202_a25a_d907_82e2,
    0x1b66_a57f_35d9_f0ec,
    0x66bd_bb50_b060_7859,
    0x4bb7_cd94_0d0c_c31f,
    0x7946_d556_9dae_71bf,
    0x97e7_f89f_e8df_5a3b,
    0xc974_6bae_7613_02cd,
    0xfece_ee86_62eb_4f03,
    0xc9cb_0b92_4938_8683,
    0x2a41_3c3b_ea14_db86,
    0xbd48_8612_3d0c_55ee,
    0x2efb_4449_ca27_6299,
    0x4365_5ffc_898e_b627,
    0xfd80_c269_2316_f41c,
    0x5bef_97df_d768_416f,
    0xfe04_2a65_9057_bbfa,
    0x551a_96cd_4a6f_0f8e,
    0x000c_b0ed_eef3_2edd,
];

fn check_witness(f: &Fq12, w: &Fq12) -> bool {
    // For nonzero w, this equation is exactly w^(p^4-p^2+1) = 1.
    if w.is_zero() || w.frobenius_map(4) * w != w.frobenius_map(2) || f.is_zero() {
        return false;
    }
    let h = f.frobenius_map(2) * f;
    w.frobenius_map(1) * w.cyclotomic_exp([ABS_X]) * h == h.frobenius_map(6)
}

#[cfg(not(target_arch = "riscv64"))]
fn witness(f: &Fq12) -> Option<Fq12> {
    let a = f.frobenius_map(6) * f.inverse()?;
    let g = a.frobenius_map(2) * a;
    // The easy exponentiation places g in the cyclotomic subgroup.
    let w = g.cyclotomic_exp(ROOT_EXP);
    check_witness(f, &w).then_some(w)
}

#[expect(
    clippy::expect_used,
    reason = "invalid untrusted advice must abort the guest"
)]
pub(super) fn check(f: &Fq12) -> bool {
    #[cfg(not(target_arch = "riscv64"))]
    let supplied = witness(f);
    #[cfg(all(target_arch = "riscv64", feature = "compute_advice"))]
    let supplied: Option<Fq12> = None;
    let available = advice_u64!(u64::from(supplied.is_some()));
    assert!(available <= 1, "pairing witness flag");
    if available == 0 {
        return Bls12_381::final_exponentiation(MillerLoopOutput(*f))
            .is_some_and(|value| value.0.is_one());
    }
    #[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
    let limbs: [[u64; 6]; 12] = {
        let mut limbs = [[0; 6]; 12];
        for (dst, coefficient) in limbs.iter_mut().zip(
            supplied
                .expect("generated witness")
                .to_base_prime_field_elements(),
        ) {
            *dst = coefficient.into_bigint().0;
        }
        limbs
    };
    let coefficients: [Fq; 12] = core::array::from_fn(|_i| {
        let words = core::array::from_fn(|_j| advice_u64!(limbs[_i][_j]));
        Fq::from_bigint(BigInt(words)).expect("canonical pairing witness coefficient")
    });
    let w = Fq12::from_base_prime_field_elems(coefficients).expect("twelve Fp12 coefficients");
    assert!(check_witness(f, &w), "invalid pairing residue witness");
    true
}

#[cfg(test)]
#[path = "residue_tests.rs"]
mod tests;
