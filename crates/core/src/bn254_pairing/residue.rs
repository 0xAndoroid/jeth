//! BN254 final-exponentiation identity via a checked root witness.
//! For M=p^4-p^2+1 and k=M/r, gcd(r,M)=r and gcd(r,k)=1.
//! The easy exponent g is in H of order M; g^k=1 iff w^r=g for some w in H.
//! Since r=p-6*x^2, check the equation using two exponentiations by x.
//!
//! For nonzero Miller output f, let h=f^(p^2+1). Checking
//! w^p*h = w^(6*x^2)*h^(p^6) avoids the inverse in g=h^(p^6)/h.
//! Check w in H before using cyclotomic formulas. Native advice finds a root
//! with r^(-1) modulo k; the interpreted advice pass skips root generation
//! and selects the original final exponentiation. Advice cannot assert a
//! negative result: if no root is supplied, the guest runs the original check.
use crate::advice::advice_u64;
use ark_bn254::{Bn254, Fq, Fq12};
use ark_ec::pairing::{MillerLoopOutput, Pairing};
use ark_ff::{BigInt, CyclotomicMultSubgroup, Field, One, PrimeField, Zero};
const X: u64 = 4_965_661_367_192_848_881;
#[cfg(not(target_arch = "riscv64"))]
// r^(-1) mod ((p^4-p^2+1)/r), little-endian u64 limbs.
const ROOT_EXP: [u64; 12] = [
    0x7bdd_d0a7_2d12_b933,
    0x5c8c_4118_79a5_3e66,
    0x19ac_0d18_1823_4996,
    0x7b10_3a3c_e1c1_ef40,
    0xa44c_d5b0_7a5d_3c0a,
    0x4032_11b7_6ed6_ab71,
    0x9fc0_7aa1_8f23_0223,
    0xd23b_7e14_f272_f01b,
    0x7dbe_665b_8da5_5d0a,
    0x1a32_79ae_1307_a485,
    0xbc6f_9666_bf95_d24c,
    0x00bb_481c_2234_572b,
];

fn check_witness(f: &Fq12, w: &Fq12) -> bool {
    if w.is_zero() || f.is_zero() || w.frobenius_map(4) * w != w.frobenius_map(2) {
        return false;
    }
    let xx = w.cyclotomic_exp([X]).cyclotomic_exp([X]);
    let twice = xx.cyclotomic_square();
    let six = twice.cyclotomic_square() * twice;
    let h = f.frobenius_map(2) * f;
    w.frobenius_map(1) * h == six * h.frobenius_map(6)
}

#[cfg(not(target_arch = "riscv64"))]
fn witness(f: &Fq12) -> Option<Fq12> {
    let a = f.frobenius_map(6) * f.inverse()?;
    let g = a.frobenius_map(2) * a;
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
    assert!(available <= 1, "BN pairing witness flag");
    if available == 0 {
        return Bn254::final_exponentiation(MillerLoopOutput(*f)).is_some_and(|v| v.0.is_one());
    }
    #[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
    let limbs: [[u64; 4]; 12] = {
        let mut limbs = [[0; 4]; 12];
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
        Fq::from_bigint(BigInt(words)).expect("canonical BN pairing witness coefficient")
    });
    let w = Fq12::from_base_prime_field_elems(coefficients).expect("twelve Fp12 coefficients");
    assert!(check_witness(f, &w), "invalid BN pairing residue witness");
    true
}

#[cfg(test)]
#[path = "residue_tests.rs"]
mod tests;
