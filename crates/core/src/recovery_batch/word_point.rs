//! Word equality for the field coordinates used by the recovery MSM.
//! Canonical limb addition uses the base-field modulus; point formulas and
//! multiplication, squaring and division remain in the shared SDK.

use jolt_inlines_sdk::ec::{AffinePoint, CurveParams, ECField};
use jolt_inlines_secp256k1::{Secp256k1Curve, Secp256k1Error, Secp256k1Fq};

#[derive(Clone, Debug)]
pub(super) struct WordField(pub(super) Secp256k1Fq);

impl PartialEq for WordField {
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        let a = self.0.e();
        let b = other.0.e();
        a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
    }
}

impl ECField for WordField {
    type Error = Secp256k1Error;

    #[inline(always)]
    fn zero() -> Self {
        Self(Secp256k1Fq::zero())
    }

    #[inline(always)]
    fn is_zero(&self) -> bool {
        let a = self.0.e();
        (a[0] | a[1] | a[2] | a[3]) == 0
    }

    #[inline(always)]
    fn neg(&self) -> Self {
        Self::zero().sub(self)
    }

    #[inline(always)]
    fn dbl(&self) -> Self {
        self.add(self)
    }

    #[inline(always)]
    fn tpl(&self) -> Self {
        self.dbl().add(self)
    }

    #[inline(always)]
    fn square(&self) -> Self {
        Self(self.0.square())
    }

    #[inline(always)]
    fn add(&self, other: &Self) -> Self {
        let a = self.0.e();
        let b = other.0.e();
        let mut words = [0; 4];
        let mut carry = false;
        for i in 0..4 {
            let (sum, first) = a[i].overflowing_add(b[i]);
            let (sum, second) = sum.overflowing_add(u64::from(carry));
            words[i] = sum;
            carry = first || second;
        }
        // p = 2^256 - C. The input sum is below 2p, so one correction
        // suffices, whether the original sum carried or lies in [p, 2^256).
        const C: u64 = (1 << 32) + 977;
        if carry || (words[1] & words[2] & words[3] == u64::MAX && words[0] >= 0u64.wrapping_sub(C))
        {
            let (low, mut carry) = words[0].overflowing_add(C);
            words[0] = low;
            for word in &mut words[1..] {
                (*word, carry) = word.overflowing_add(u64::from(carry));
            }
        }
        Self::from_u64_arr_unchecked(&words)
    }

    #[inline(always)]
    fn sub(&self, other: &Self) -> Self {
        let a = self.0.e();
        let b = other.0.e();
        let mut words = [0; 4];
        let mut borrow = false;
        for i in 0..4 {
            let (difference, first) = a[i].overflowing_sub(b[i]);
            let (difference, second) = difference.overflowing_sub(u64::from(borrow));
            words[i] = difference;
            borrow = first || second;
        }
        if borrow {
            // The wrapped difference exceeds C, so subtracting C cannot
            // underflow the full word array and gives the canonical a-b+p.
            let (low, mut borrow) = words[0].overflowing_sub((1 << 32) + 977);
            words[0] = low;
            for word in &mut words[1..] {
                (*word, borrow) = word.overflowing_sub(u64::from(borrow));
            }
        }
        Self::from_u64_arr_unchecked(&words)
    }

    #[inline(always)]
    fn mul(&self, other: &Self) -> Self {
        Self(self.0.mul(&other.0))
    }

    #[inline(always)]
    fn div(&self, other: &Self) -> Self {
        Self(self.0.div(&other.0))
    }

    #[inline(always)]
    fn div_assume_nonzero(&self, other: &Self) -> Self {
        Self(self.0.div_assume_nonzero(&other.0))
    }

    #[inline(always)]
    fn to_u64_arr(&self) -> [u64; 4] {
        self.0.e()
    }

    #[inline(always)]
    fn from_u64_arr(arr: &[u64; 4]) -> Result<Self, Self::Error> {
        Secp256k1Fq::from_u64_arr(arr).map(Self)
    }

    #[inline(always)]
    fn from_u64_arr_unchecked(arr: &[u64; 4]) -> Self {
        Self(Secp256k1Fq::from_u64_arr_unchecked(arr))
    }
}

#[derive(Clone)]
pub(super) struct Curve;

impl CurveParams<WordField> for Curve {
    type Error = Secp256k1Error;

    fn curve_b() -> WordField {
        WordField(<Secp256k1Curve as CurveParams<Secp256k1Fq>>::curve_b())
    }

    fn not_on_curve_error() -> Self::Error {
        <Secp256k1Curve as CurveParams<Secp256k1Fq>>::not_on_curve_error()
    }
}

pub(super) type Point = AffinePoint<WordField, Curve>;

/// Add a point whose non-infinity invariant was checked when constructing
/// the GLV term. Bucket values can still be infinity, equal or opposite.
#[inline(always)]
pub(super) fn add_finite(left: &Point, right: &Point) -> Point {
    debug_assert!(!right.is_infinity());
    if left.is_infinity() {
        return right.clone();
    }
    let x = left.x();
    let y = left.y();
    let other_x = right.x();
    let other_y = right.y();
    if x == other_x {
        return if y == other_y {
            left.double()
        } else {
            Point::infinity()
        };
    }
    let slope = y.sub(&other_y).div_assume_nonzero(&x.sub(&other_x));
    let result_x = slope.square().sub(&x).sub(&other_x);
    let result_y = slope.mul(&x.sub(&result_x)).sub(&y);
    Point::new_unchecked(result_x, result_y)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jolt_inlines_secp256k1::{Secp256k1Point, Secp256k1PointExt};

    fn word(point: &Secp256k1Point) -> Point {
        Point::new_unchecked(WordField(point.x()), WordField(point.y()))
    }

    #[test]
    fn finite_addition_matches_complete_addition() {
        let mut a = Secp256k1Point::generator();
        let mut b = a.double();
        for _ in 0..64 {
            for left in [&a, &a.neg(), &b, &Secp256k1Point::infinity()] {
                for right in [&a, &b] {
                    assert_eq!(
                        add_finite(&word(left), &word(right)).to_u64_arr(),
                        left.add(right).to_u64_arr()
                    );
                }
            }
            a = a.double().add(&b);
            b = b.double().add(&Secp256k1Point::generator());
        }
    }

    #[test]
    fn canonical_word_arithmetic_matches_shared_field() {
        use alloy_primitives::U256;
        let modulus = U256::from_limbs([0xffff_fffe_ffff_fc2f, u64::MAX, u64::MAX, u64::MAX]);
        let mut values = alloc::vec![
            U256::ZERO,
            U256::from(1),
            modulus - U256::from(1),
            modulus - U256::from(2)
        ];
        for bit in [32, 64, 128, 192, 255] {
            let value = U256::from(1) << bit;
            values.extend([value - U256::from(1), value, value + U256::from(1)]);
        }
        let mut rng = 0x84ec_33b1_b5d0_729fu64;
        for _ in 0..64 {
            let mut limbs = [0; 4];
            for limb in &mut limbs {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                *limb = rng;
            }
            values.push(U256::from_limbs(limbs) % modulus);
        }
        for a in &values {
            let a = WordField::from_u64_arr(a.as_limbs()).unwrap();
            assert_eq!(a.neg().0.e(), a.0.neg().e());
            assert_eq!(a.dbl().0.e(), a.0.dbl().e());
            assert_eq!(a.tpl().0.e(), a.0.tpl().e());
            for b in &values {
                let b = WordField::from_u64_arr(b.as_limbs()).unwrap();
                let sum = a.add(&b).0.e();
                let difference = a.sub(&b).0.e();
                assert_eq!(sum, a.0.add(&b.0).e());
                assert_eq!(difference, a.0.sub(&b.0).e());
                assert!(U256::from_limbs(sum) < modulus);
                assert!(U256::from_limbs(difference) < modulus);
            }
        }
    }

    #[test]
    fn point_operations_match_shared_curve() {
        let mut a = Secp256k1Point::generator();
        let mut b = a.double();
        let mut rng = 0x931e_23a7_4dd1_8f09u64;
        for _ in 0..128 {
            for rhs in [&a, &a.neg(), &b, &Secp256k1Point::infinity()] {
                assert_eq!(
                    word(&a).add(&word(rhs)).to_u64_arr(),
                    a.add(rhs).to_u64_arr()
                );
                assert_eq!(
                    word(rhs).add(&word(&a)).to_u64_arr(),
                    rhs.add(&a).to_u64_arr()
                );
            }
            assert_eq!(word(&a).double().to_u64_arr(), a.double().to_u64_arr());
            assert_eq!(word(&a).neg().to_u64_arr(), a.neg().to_u64_arr());
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            a = a.double();
            if rng & 1 != 0 {
                a = a.add(&b);
            }
            b = b.double().add(&Secp256k1Point::generator());
        }
    }

    #[test]
    fn limb_equality_matches_byte_reference() {
        let mut rng = 0x79a3_c41e_638f_d927u64;
        for _ in 0..256 {
            let mut a = [0u64; 4];
            for limb in &mut a {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                *limb = rng;
            }
            a[3] >>= 1;
            for index in 0..=32 {
                let mut b = a;
                if index < 32 {
                    b[index / 8] ^= 1 << ((index % 8) * 8);
                }
                let left = WordField::from_u64_arr(&a).unwrap();
                let right = WordField::from_u64_arr(&b).unwrap();
                let equal = a
                    .iter()
                    .flat_map(|x| x.to_le_bytes())
                    .eq(b.iter().flat_map(|x| x.to_le_bytes()));
                assert_eq!(left == right, equal);
            }
        }
        assert!(WordField::zero().is_zero());
    }
}
