//! Guest-side dispatch of bn254 Fq multiplication to the Jolt inlines (`jolt-bn254-inline`,
//! riscv64 only). Every inline returns the Montgomery reduction in [0, 2q); the conditional
//! subtraction that canonicalizes it stays compiled code (a top-limb compare in the common case).
#![allow(unsafe_code)]

use crate::fields::models::quadratic_extension::{QuadExtConfig, QuadExtField};
use crate::{BigInt, BigInteger, Field, PrimeField};
use core::mem::{align_of, offset_of, size_of, MaybeUninit};
use jeth_inlines_bn254::{BN254_MINUS_ONE, BN254_MODULUS};

const Q: BigInt<4> = BigInt(BN254_MODULUS);

/// `limbs == q`; false for every other modulus and every other limb count.
pub(crate) const fn is_modulus(limbs: &[u64]) -> bool {
    if limbs.len() != BN254_MODULUS.len() {
        return false;
    }
    let mut i = 0;
    while i < BN254_MODULUS.len() {
        if limbs[i] != BN254_MODULUS[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `limbs` must point to a four-limb element in [0, 2q).
#[inline(always)]
unsafe fn subtract_modulus(limbs: *mut u64) {
    let x = &mut *(limbs as *mut BigInt<4>);
    if *x >= Q {
        x.sub_with_borrow(&Q);
    }
}

/// a ← a·b·R⁻¹ mod q for canonical four-limb Montgomery elements.
#[inline(always)]
pub(crate) fn mul_assign<F>(a: &mut F, b: &F) {
    assert!(size_of::<F>() == 32);
    let out = a as *mut F as *mut u64;
    // SAFETY: `F` is four u64 limbs; the inline reads both operands before writing `out`.
    unsafe {
        jeth_inlines_bn254::mulq(out, out, b as *const F as *const u64);
        subtract_modulus(out);
    }
}

/// (a₀·b₀ + a₁·b₁)·R⁻¹ mod q for canonical four-limb Montgomery elements.
#[inline(always)]
pub(crate) fn sum_of_products_2<F: Copy, const M: usize>(a: &[F; M], b: &[F; M]) -> F {
    assert!(M == 2 && size_of::<F>() == 32);
    let mut out = MaybeUninit::<F>::uninit();
    // SAFETY: `[F; 2]` is eight contiguous limbs; the inline writes all four limbs of `out`.
    unsafe {
        jeth_inlines_bn254::sopq2(
            out.as_mut_ptr() as *mut u64,
            a.as_ptr() as *const u64,
            b.as_ptr() as *const u64,
        );
        subtract_modulus(out.as_mut_ptr() as *mut u64);
        out.assume_init()
    }
}

/// Four limbs read from a 32-byte constant (a `BigInt<4>` or an `Fp<MontBackend<_, 4>, 4>`).
///
/// # Safety
/// `T` must be exactly four initialized `u64` words.
const unsafe fn limbs<T>(value: &T) -> [u64; 4] {
    *(value as *const T as *const [u64; 4])
}

const fn same(a: &[u64; 4], b: &[u64; 4]) -> bool {
    let mut i = 0;
    while i < 4 {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The quadratic extension of bn254 Fq by the nonresidue −1, with `c0` at offset 0 and `c1` at
/// offset 32 (the layout the fused inline reads and writes). Evaluated at compile time: a 32-byte,
/// 8-aligned base field whose prime field has the 32-byte modulus q is `Fp<MontBackend<_, 4>, 4>`
/// (`MontBackend` is the only `FpConfig` in the crate graph), and its nonresidue is compared limb
/// by limb against −1 in Montgomery form.
pub(crate) const fn is_fq2<P: QuadExtConfig>() -> bool {
    if size_of::<P::BaseField>() != 32
        || align_of::<P::BaseField>() != 8
        || size_of::<QuadExtField<P>>() != 64
        || offset_of!(QuadExtField<P>, c0) != 0
        || offset_of!(QuadExtField<P>, c1) != 32
        || size_of::<<<P::BaseField as Field>::BasePrimeField as PrimeField>::BigInt>() != 32
    {
        return false;
    }
    // SAFETY: both constants are 32 initialized bytes (sizes checked above).
    let (modulus, nonresidue) = unsafe {
        (
            limbs(&<<P::BaseField as Field>::BasePrimeField as PrimeField>::MODULUS),
            limbs(&P::NONRESIDUE),
        )
    };
    is_modulus(&modulus) && same(&nonresidue, &BN254_MINUS_ONE)
}

impl<P: QuadExtConfig> QuadExtField<P> {
    pub(crate) const JOLT_BN254_FQ2: bool = is_fq2::<P>();
}

/// a ← a·b in Fq2 for canonical coefficients.
#[inline(always)]
pub(crate) fn fp2_mul_assign<P: QuadExtConfig>(a: &mut QuadExtField<P>, b: &QuadExtField<P>) {
    let out = a as *mut QuadExtField<P> as *mut u64;
    // SAFETY: `is_fq2` checked the layout; the inline reads both operands before writing `out`.
    unsafe {
        jeth_inlines_bn254::fp2mulq(out, out, b as *const QuadExtField<P> as *const u64);
        subtract_modulus(out);
        subtract_modulus(out.add(4));
    }
}
