//! U256 arithmetic on the Jolt BIGINT256_MUL inline (256×256→512-bit product,
//! 141 rows; `jolt-inlines/bigint`).

use alloc::vec::Vec;
use alloy_primitives::{ruint::algorithms, U256};
use jolt_inlines_bigint::bigint256_mul_inline;

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
        bigint256_mul_inline(
            a.as_limbs().as_ptr(),
            b.as_limbs().as_ptr(),
            product.as_mut_ptr(),
        );
        algorithms::div(&mut product, modulus.as_limbs_mut());
    }
}

/// MODEXP precompile arithmetic (`base^exp mod modulus`, big-endian operands)
/// for an odd modulus of 9..=32 significant bytes and a base of at most 32:
/// a 4-limb Montgomery ladder whose products come from the inline. Any other
/// shape returns `None` for the caller's software fallback (aurora beats the
/// fixed-width ladder on one-limb moduli: 569 vs 783 rows per exponent bit).
/// The result is the minimal big-endian encoding (`[0]` for zero); revm pads
/// or truncates it to the declared modulus length, so the precompile output
/// matches aurora-engine-modexp byte for byte even though aurora keeps whole
/// limbs.
pub fn modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> Option<Vec<u8>> {
    fn strip(bytes: &[u8]) -> &[u8] {
        let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
        &bytes[first..]
    }
    let (base, exp, modulus) = (strip(base), strip(exp), strip(modulus));
    if modulus.len() <= 8
        || modulus.len() > 32
        || base.len() > 32
        || modulus[modulus.len() - 1] & 1 == 0
    {
        return None;
    }
    let n = U256::from_be_slice(modulus);
    if exp.is_empty() {
        return Some(alloc::vec![1]);
    }
    // -n^-1 mod 2^64 by Newton iteration (n0 is odd, so n0 is its own inverse mod 8).
    let n0 = n.as_limbs()[0];
    let mut inv = n0;
    for _ in 0..5 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(n0.wrapping_mul(inv)));
    }
    let n_prime = inv.wrapping_neg();
    // R mod n with R = 2^256; every ladder value stays in Montgomery form (< n).
    let r = U256::ZERO.wrapping_sub(n) % n;
    let mut a_bar = n;
    mul_mod(&(U256::from_be_slice(base) % n), &r, &mut a_bar);
    let mut x = r;
    for &byte in exp {
        for bit in (0..8).rev() {
            x = mont_mul(&x, &x, &n, n_prime);
            if (byte >> bit) & 1 == 1 {
                x = mont_mul(&x, &a_bar, &n, n_prime);
            }
        }
    }
    let out = mont_mul(&x, &U256::from(1), &n, n_prime);
    Some(if out.is_zero() {
        alloc::vec![0]
    } else {
        out.to_be_bytes_trimmed_vec()
    })
}

/// `a * b * 2^-256 mod n` for `a, b < n` (odd `n`, `n_prime = -n^-1 mod 2^64`):
/// inline product, then word-serial REDC.
#[inline(always)]
fn mont_mul(a: &U256, b: &U256, n: &U256, n_prime: u64) -> U256 {
    let mut t = [0u64; 9];
    // SAFETY: as in `mul_mod`; `t` has room for the 8 product limbs.
    unsafe {
        bigint256_mul_inline(a.as_limbs().as_ptr(), b.as_limbs().as_ptr(), t.as_mut_ptr());
    }
    let limbs = n.as_limbs();
    for i in 0..4 {
        let m = t[i].wrapping_mul(n_prime);
        let mut carry = 0u64;
        for j in 0..4 {
            let wide = (m as u128) * (limbs[j] as u128) + (t[i + j] as u128) + (carry as u128);
            t[i + j] = wide as u64;
            carry = (wide >> 64) as u64;
        }
        let mut k = i + 4;
        while carry != 0 {
            let (sum, c) = t[k].overflowing_add(carry);
            t[k] = sum;
            carry = c as u64;
            k += 1;
        }
    }
    let u = U256::from_limbs([t[4], t[5], t[6], t[7]]);
    if t[8] != 0 || u >= *n {
        u.wrapping_sub(*n)
    } else {
        u
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use alloy_primitives::hex;

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

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
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
        for round in 0..4000u32 {
            let mut limbs = [[0u64; 4]; 3];
            for (i, l) in limbs.iter_mut().enumerate() {
                // Vary the limb count (1..=4) so every ruint division path
                // (nx1, nx2, nxm) and short operands get exercised.
                let n = 1 + ((round as usize >> (2 * i)) & 3);
                for x in l.iter_mut().take(n) {
                    *x = xorshift(&mut state);
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

    /// revm's `left_pad_vec_be`: the precompile returns exactly `len` bytes.
    fn pad(data: &[u8], len: usize) -> Vec<u8> {
        if data.len() < len {
            [vec![0; len - data.len()], data.to_vec()].concat()
        } else {
            data[data.len() - len..].to_vec()
        }
    }

    /// Shapes the ladder must take: odd modulus of 9..=32 significant bytes,
    /// base of at most 32.
    fn ladder_shape(base: &[u8], modulus: &[u8]) -> bool {
        let strip = |b: &[u8]| b.iter().skip_while(|&&x| x == 0).count();
        let (b, m) = (strip(base), strip(modulus));
        (9..=32).contains(&m) && b <= 32 && modulus[modulus.len() - 1] & 1 == 1
    }

    /// Runs the inline ladder, checks that it accepts exactly the shapes it
    /// is meant to, and compares accepted outputs with aurora-engine-modexp
    /// (revm's software path) at the precompile level.
    fn check_modexp(base: &[u8], exp: &[u8], modulus: &[u8]) -> bool {
        let got = modexp(base, exp, modulus);
        assert_eq!(got.is_some(), ladder_shape(base, modulus));
        if let Some(got) = &got {
            let want = aurora_engine_modexp::modexp(base, exp, modulus);
            assert!(got.len() <= modulus.len());
            assert_eq!(
                pad(got, modulus.len()),
                pad(&want, modulus.len()),
                "base={} exp={} modulus={}",
                hex::encode(base),
                hex::encode(exp),
                hex::encode(modulus)
            );
        }
        got.is_some()
    }

    fn be(x: U256) -> [u8; 32] {
        x.to_be_bytes()
    }

    const BN254_P: U256 = U256::from_limbs([
        0x3C208C16D87CFD47,
        0x97816A916871CA8D,
        0xB85045B68181585D,
        0x30644E72E131A029,
    ]);
    const SECP256K1_N: U256 = U256::from_limbs([
        0xBFD25E8CD0364141,
        0xBAAEDCE6AF48A03B,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
    ]);

    fn odd_moduli() -> Vec<U256> {
        let one = U256::from(1);
        let mut out = vec![
            one,
            U256::from(3),
            U256::from(5),
            U256::from(7),
            U256::from(0xff),
            U256::from(u64::MAX),
            (one << 64) + one,
            (one << 128) - one,
            (one << 128) + one,
            (one << 192) + one,
            (one << 255) + one,
            (one << 255) - U256::from(19),
            U256::MAX,
            U256::MAX - (one << 128),
            BN254_P,
            SECP256K1_N,
        ];
        out.extend(edge_values().iter().filter(|m| m.bit(0)).copied());
        out
    }

    #[test]
    fn modexp_edge_inputs_match_aurora() {
        let one = U256::from(1);
        let exps: Vec<Vec<u8>> = vec![
            vec![],
            vec![0],
            vec![0; 5],
            vec![1],
            vec![2],
            vec![3],
            vec![1, 0, 1],
            [vec![0x80], vec![0; 31]].concat(),
            vec![0xff; 32],
            vec![0xff; 33],
            be(BN254_P - U256::from(2)).to_vec(),
            be(U256::MAX - one).to_vec(),
        ];
        for m in odd_moduli() {
            let bases = [
                U256::ZERO,
                one,
                U256::from(2),
                U256::from(3),
                m - one,
                m,
                m + one,
                one << 255,
                U256::MAX,
            ];
            let want = m > U256::from(u64::MAX);
            for b in bases {
                for e in &exps {
                    assert_eq!(check_modexp(&be(b), e, &be(m)), want);
                    // Minimal encodings and extra leading zeros give the same answer.
                    assert_eq!(
                        check_modexp(
                            &b.to_be_bytes_trimmed_vec(),
                            e,
                            &m.to_be_bytes_trimmed_vec()
                        ),
                        want
                    );
                    assert_eq!(
                        check_modexp(
                            &[vec![0; 9], be(b).to_vec()].concat(),
                            &[vec![0; 3], e.clone()].concat(),
                            &[vec![0; 17], be(m).to_vec()].concat()
                        ),
                        want
                    );
                }
            }
        }
    }

    #[test]
    fn modexp_declines_unsupported_shapes() {
        let one = U256::from(1);
        let m = be(BN254_P);
        for even in [
            U256::ZERO,
            U256::from(2),
            U256::from(4),
            one << 64,
            U256::MAX - one,
        ] {
            assert!(!check_modexp(&be(U256::from(3)), &[5], &be(even)));
        }
        assert!(!check_modexp(&be(U256::from(3)), &[5], &[]));
        assert!(!check_modexp(&be(U256::from(3)), &[5], &[0; 32]));
        assert!(!check_modexp(
            &[vec![1], be(U256::from(3)).to_vec()].concat(),
            &[5],
            &m
        ));
        assert!(!check_modexp(
            &be(U256::from(3)),
            &[5],
            &[vec![1], m.to_vec()].concat()
        ));
        assert!(check_modexp(
            &[vec![0], be(U256::from(3)).to_vec()].concat(),
            &[5],
            &m
        ));
        // One-limb moduli stay on the software path, two limbs take the ladder.
        assert!(!check_modexp(&[3], &[5], &[0xff; 8]));
        assert!(!check_modexp(&[3], &[5], &be(U256::from(u64::MAX))));
        assert!(check_modexp(
            &[3],
            &[5],
            &[vec![1], vec![0; 7], vec![1]].concat()
        ));
        assert!(check_modexp(&[3], &[5], &be((one << 64) + one)));
    }

    #[test]
    fn modexp_random_inputs_match_aurora() {
        let mut state = 0xD1B5_4A32_D192_ED03u64;
        let bytes = |len: usize, state: &mut u64| -> Vec<u8> {
            (0..len).map(|_| xorshift(state) as u8).collect()
        };
        for round in 0..1500usize {
            let mut m = bytes(1 + round % 32, &mut state);
            let last = m.len() - 1;
            m[last] |= 1;
            if round % 5 == 0 {
                m[0] |= 0x80;
            }
            let b = bytes(round % 33, &mut state);
            let e = bytes(round % 41, &mut state);
            check_modexp(&b, &e, &m);
            if round % 3 == 0 {
                // Even modulus of the same size stays on the software path.
                m[last] &= !1;
                assert!(!check_modexp(&b, &e, &m));
            }
        }
    }
}
