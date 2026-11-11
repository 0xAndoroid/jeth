//! Word equality for the field coordinates used by the recovery MSM.
//! Arithmetic and exceptional-point handling remain in the shared SDK.

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
        Self(self.0.neg())
    }

    #[inline(always)]
    fn dbl(&self) -> Self {
        Self(self.0.dbl())
    }

    #[inline(always)]
    fn tpl(&self) -> Self {
        Self(self.0.tpl())
    }

    #[inline(always)]
    fn square(&self) -> Self {
        Self(self.0.square())
    }

    #[inline(always)]
    fn add(&self, other: &Self) -> Self {
        Self(self.0.add(&other.0))
    }

    #[inline(always)]
    fn sub(&self, other: &Self) -> Self {
        Self(self.0.sub(&other.0))
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

#[cfg(test)]
mod tests {
    use super::*;
    use jolt_inlines_secp256k1::{Secp256k1Point, Secp256k1PointExt};

    fn word(point: &Secp256k1Point) -> Point {
        Point::new_unchecked(WordField(point.x()), WordField(point.y()))
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
