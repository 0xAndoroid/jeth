//! Software model of the inline semantics: word-by-word Montgomery reduction (HAC 14.32) of the
//! exact 512-bit sum of products. Used by the host fallbacks and as the test reference.

use crate::{BN254_INV, BN254_MODULUS};

pub type Limbs = [u64; 4];

/// (a·b + m·q) / 2^256, truncated to 256 bits.
pub fn mulq(a: &Limbs, b: &Limbs) -> Limbs {
    redc(&[(*a, *b)])
}

/// (a₀·b₀ + a₁·b₁ + m·q) / 2^256, truncated to 256 bits.
pub fn sopq2(a: &[u64; 8], b: &[u64; 8]) -> Limbs {
    redc(&[(lo(a), lo(b)), (hi(a), hi(b))])
}

/// c₀ = REDC(a₀·b₀ + a₁·(q − b₁)), c₁ = REDC(a₀·b₁ + a₁·b₀); returned as `c₀ ‖ c₁`.
pub fn fp2mulq(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
    let (a0, a1, b0, b1) = (lo(a), hi(a), lo(b), hi(b));
    let c1 = redc(&[(a0, b1), (a1, b0)]);
    let c0 = redc(&[(a0, b0), (a1, negate(&b1))]);
    let mut out = [0u64; 8];
    out[..4].copy_from_slice(&c0);
    out[4..].copy_from_slice(&c1);
    out
}

/// q − b as a 256-bit integer (wrapping for b > q).
pub fn negate(b: &Limbs) -> Limbs {
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, b1) = BN254_MODULUS[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        out[i] = d;
        borrow = u64::from(b1 | b2);
    }
    out
}

/// (Σ aᵢ·bᵢ + m·q) / 2^256 with m ≡ −(Σ aᵢ·bᵢ)·q⁻¹ (mod 2^256), truncated to 256 bits.
pub fn redc(pairs: &[(Limbs, Limbs)]) -> Limbs {
    let mut s = [0u64; 9];
    for (a, b) in pairs {
        for (i, &limb) in a.iter().enumerate() {
            mac_row(&mut s, i, limb, b);
        }
    }
    for i in 0..4 {
        let m = s[i].wrapping_mul(BN254_INV);
        mac_row(&mut s, i, m, &BN254_MODULUS);
    }
    [s[4], s[5], s[6], s[7]]
}

/// s += x·y·2^(64·i), propagating the carry through the 9-limb accumulator.
fn mac_row(s: &mut [u64; 9], i: usize, x: u64, y: &Limbs) {
    let mut carry = 0u128;
    for j in 0..4 {
        let t = s[i + j] as u128 + x as u128 * y[j] as u128 + carry;
        s[i + j] = t as u64;
        carry = t >> 64;
    }
    let mut k = i + 4;
    while carry != 0 && k < 9 {
        let t = s[k] as u128 + carry;
        s[k] = t as u64;
        carry = t >> 64;
        k += 1;
    }
}

fn lo(x: &[u64; 8]) -> Limbs {
    x[..4].try_into().unwrap()
}

fn hi(x: &[u64; 8]) -> Limbs {
    x[4..].try_into().unwrap()
}
