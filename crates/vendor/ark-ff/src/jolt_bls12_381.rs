//! Guest-side dispatch of BLS12-381 Fq multiplication to the Jolt inlines (`jolt-bls12-381-inline`,
//! riscv64 only). Every inline returns the canonical (< p) Montgomery product.
#![allow(unsafe_code)]

use crate::fields::models::fp::{Fp, FpConfig};
use crate::fields::models::quadratic_extension::{QuadExtConfig, QuadExtField};
use crate::Field;
use core::mem::{offset_of, size_of, MaybeUninit};
use jeth_inlines_bls12_381::{LIMBS, MODULUS};

/// `limbs == p`; false for every other modulus and every other limb count.
pub(crate) const fn is_modulus(limbs: &[u64]) -> bool {
    if limbs.len() != LIMBS {
        return false;
    }
    let mut i = 0;
    while i < LIMBS {
        if limbs[i] != MODULUS[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// a ← a·b·R⁻¹ mod p for canonical six-limb Montgomery elements. Callers gate on
/// `MontBackend::JOLT_BLS12_381_FQ`, which checks the modulus and that the element is exactly its
/// six limbs at offset 0.
#[inline(always)]
pub(crate) fn mul_assign<P: FpConfig<N>, const N: usize>(a: &mut Fp<P, N>, b: &Fp<P, N>) {
    let out = a as *mut Fp<P, N> as *mut u64;
    // SAFETY: the element is six u64 limbs (see `JOLT_BLS12_381_FQ`); the inline reads both operands
    // before writing `out`.
    unsafe { jeth_inlines_bls12_381::mulp(out, out, b as *const Fp<P, N> as *const u64) }
}

/// (a₀·b₀ + a₁·b₁)·R⁻¹ mod p for canonical six-limb Montgomery elements; callers gate on
/// `MontBackend::JOLT_BLS12_381_FQ` and `M == 2`.
#[inline(always)]
pub(crate) fn sum_of_products_2<P: FpConfig<N>, const N: usize, const M: usize>(
    a: &[Fp<P, N>; M],
    b: &[Fp<P, N>; M],
) -> Fp<P, N> {
    let mut out = MaybeUninit::<Fp<P, N>>::uninit();
    // SAFETY: `[Fp; 2]` is twelve contiguous limbs (see `JOLT_BLS12_381_FQ`); the inline writes all
    // six limbs of `out`.
    unsafe {
        jeth_inlines_bls12_381::sopp2(
            out.as_mut_ptr() as *mut u64,
            a.as_ptr() as *const u64,
            b.as_ptr() as *const u64,
        );
        out.assume_init()
    }
}

/// The quadratic extension of BLS12-381 Fq by the nonresidue −1, with `c0` at offset 0 and `c1` at
/// offset 48 (the layout the fused inline reads and writes). A 48-byte prime field of characteristic
/// p is `Fp<MontBackend<_, 6>, 6>`: `MontBackend` is the only `FpConfig` in the crate graph, so the
/// base field is the Montgomery form the inline expects.
#[inline(always)]
pub(crate) fn is_fq2<P: QuadExtConfig>() -> bool {
    size_of::<P::BaseField>() == 8 * LIMBS
        && size_of::<QuadExtField<P>>() == 16 * LIMBS
        && offset_of!(QuadExtField<P>, c0) == 0
        && offset_of!(QuadExtField<P>, c1) == 8 * LIMBS
        && P::BaseField::extension_degree() == 1
        && P::BaseField::characteristic() == &MODULUS[..]
        && P::NONRESIDUE == -P::BaseField::ONE
}

/// a ← a·b in Fq[u]/(u² + 1).
#[inline(always)]
pub(crate) fn fp2_mul_assign<P: QuadExtConfig>(a: &mut QuadExtField<P>, b: &QuadExtField<P>) {
    let out = a as *mut QuadExtField<P> as *mut u64;
    // SAFETY: layout checked by `is_fq2`; the inline reads both operands before writing `out`.
    unsafe { jeth_inlines_bls12_381::fp2mul(out, out, b as *const QuadExtField<P> as *const u64) }
}
