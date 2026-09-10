//! U256 arithmetic on the Jolt BIGINT256_MUL inline (256×256→512-bit product,
//! 141 rows; `jolt-inlines/bigint`).

use alloy_primitives::{ruint::algorithms, U256};

/// `(a * b) % modulus`, written over `modulus`; zero when the modulus is zero
/// (EVM MULMOD semantics, identical to ruint's `mul_mod`). The 512-bit product
/// comes from the inline, the 512/256 reduction stays ruint's Knuth division.
#[inline(always)]
pub fn mul_mod(a: &U256, b: &U256, modulus: &mut U256) {
    if modulus.is_zero() {
        return;
    }
    let mut product = [0u64; 8];
    // SAFETY: `Uint` is `repr(transparent)` over `[u64; 4]` (8-byte aligned);
    // the inline reads 32 bytes from each operand and writes 64 bytes to
    // `product`. U256 has no padding bits, so raw limb writes keep it canonical.
    unsafe {
        jolt_inlines_bigint::bigint256_mul_inline(
            a.as_limbs().as_ptr(),
            b.as_limbs().as_ptr(),
            product.as_mut_ptr(),
        );
        algorithms::div(&mut product, modulus.as_limbs_mut());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(a: U256, b: U256, m: U256) {
        let mut got = m;
        mul_mod(&a, &b, &mut got);
        assert_eq!(got, a.mul_mod(b, m), "a={a:#x} b={b:#x} m={m:#x}");
    }

    fn edge_values() -> [U256; 16] {
        let one = U256::from(1);
        let max = U256::MAX;
        let half = one << 255;
        [
            U256::ZERO,
            one,
            U256::from(2),
            U256::from(3),
            U256::from(u64::MAX),
            one << 64,
            (one << 64) + one,
            (one << 128) - one,
            one << 128,
            (one << 192) - one,
            half - one,
            half,
            half + one,
            U256::from_limbs([0x1234567 | u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1]),
            max - one,
            max,
        ]
    }

    #[test]
    fn edge_operands_match_ruint() {
        let vals = edge_values();
        for &a in &vals {
            for &b in &vals {
                for &m in &vals {
                    check(a, b, m);
                }
            }
        }
        for &m in &vals {
            if m > U256::from(1) {
                let n1 = m - U256::from(1);
                check(n1, n1, m);
                check(n1, U256::from(2), m);
            }
        }
    }

    #[test]
    fn random_operands_match_ruint() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for round in 0..4000u32 {
            let mut limbs = [[0u64; 4]; 3];
            for (i, l) in limbs.iter_mut().enumerate() {
                // Vary the limb count (1..=4) so every ruint division path
                // (nx1, nx2, nxm) and short operands get exercised.
                let n = 1 + ((round as usize >> (2 * i)) & 3);
                for x in l.iter_mut().take(n) {
                    *x = next();
                }
                if round % 7 == 0 {
                    l[n - 1] |= 1 << 63;
                }
            }
            let [a, b, m] = limbs.map(U256::from_limbs);
            check(a, b, m);
            check(a, b, m & !U256::from(1));
            if !m.is_zero() {
                check(a % m, b % m, m);
            }
        }
    }
}
