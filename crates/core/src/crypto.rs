//! revm and EIP-7702 recovery through deferred, checked secp256k1 equations.

use crate::advice::{advice_assert_eq, advice_u64};
use crate::recovery_batch::{self, Equation};
#[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
use alloc::vec::Vec;
use alloy_primitives::{B256, U256};
use jolt_inlines_secp256k1::{Secp256k1Fq, Secp256k1Fr, Secp256k1Point, Secp256k1PointExt};
use reth_evm::revm::precompile::{Crypto, PrecompileHalt};

/// secp256k1 curve order n (little-endian limbs).
pub(crate) const N: U256 = U256::from_limbs([
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
]);
/// Base field modulus p (little-endian limbs).
const P: U256 = U256::from_limbs([
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
]);
/// (p+1)/4 — sqrt exponent for p ≡ 3 (mod 4), little-endian u64 limbs.
#[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
const SQRT_EXP: [u64; 4] = [
    0xFFFFFFFFBFFFFF0C,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0x3FFFFFFFFFFFFFFF,
];

/// Install the Jolt-accelerated crypto providers (call once at guest start):
/// revm's `Crypto` (ecrecover precompile) AND alloy-consensus's pluggable
/// `CryptoProvider` backend — the latter covers EIP-7702 authority recovery
/// (alloy-evm's `TxEnv` conversion calls
/// `alloy_consensus::crypto::secp256k1::recover_signer` per authorization;
/// software k256 measured ~1.5M rows/authorization vs ~230k inline — 16% of
/// block 25698070).
pub fn install_jolt_crypto() -> bool {
    let consensus_ok = alloy_consensus::crypto::backend::install_default_provider(
        alloc::sync::Arc::new(JoltCryptoProvider),
    )
    .is_ok();
    reth_evm::revm::precompile::install_crypto(JoltCrypto) && consensus_ok
}

/// alloy-consensus pluggable crypto backend routing signature recovery through
/// the Jolt secp256k1 inline.
///
/// Parity notes vs the k256 compile-time backend it replaces:
/// - `recover_from_prehash` recovers with the given (r, s, recid) directly;
///   [`inline_ecrecover`] normalizes high-s and flips the recovery parity —
///   an identity transformation (Q = r⁻¹(sR − zG) is invariant under
///   (s, R) → (n−s, −R)), so accept/reject sets and outputs coincide.
/// - v ∈ {2,3} (x-reduced r) is handled identically (r + n, reject ≥ p).
#[derive(Debug)]
struct JoltCryptoProvider;

impl alloy_consensus::crypto::backend::CryptoProvider for JoltCryptoProvider {
    fn recover_signer_unchecked(
        &self,
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<alloy_primitives::Address, alloy_consensus::crypto::RecoveryError> {
        let sig64: &[u8; 64] = sig[..64].try_into().unwrap();
        inline_ecrecover(sig64, sig[64], msg)
            .map(|hash| alloy_primitives::Address::from_slice(&hash[12..]))
            .ok_or_else(alloy_consensus::crypto::RecoveryError::new)
    }

    fn verify_and_compute_signer_unchecked(
        &self,
        pubkey: &[u8; 65],
        sig: &[u8; 64],
        msg: &[u8; 32],
    ) -> Result<alloy_primitives::Address, alloy_consensus::crypto::RecoveryError> {
        let signature = alloy_primitives::Signature::new(
            U256::from_be_slice(&sig[..32]),
            U256::from_be_slice(&sig[32..]),
            false, // parity is irrelevant for verification against a known key
        );
        crate::recover::inline_verify_pubkey(pubkey, &signature, B256::from_slice(msg))
            .map_err(|_| alloy_consensus::crypto::RecoveryError::new())
    }
}

#[derive(Debug)]
struct JoltCrypto;

impl Crypto for JoltCrypto {
    #[inline]
    fn secp256k1_ecrecover(
        &self,
        sig: &[u8; 64],
        recid: u8,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileHalt> {
        inline_ecrecover(sig, recid, msg).ok_or(PrecompileHalt::Secp256k1RecoverFailed)
    }

    /// GLV scalar multiplication: half the doublings of revm's double-and-add.
    #[inline]
    fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileHalt> {
        crate::bn254::g1_mul(point, scalar)
    }

    /// RIP-7212 P256VERIFY via the Jolt P-256 inline (guest only; the native
    /// reference keeps revm's `p256` software path).
    #[cfg(all(feature = "p256-inline", target_arch = "riscv64"))]
    #[inline]
    fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        crate::p256::verify(msg, sig, pk)
    }
}

/// Recover `keccak(pubkey)` from a prehash signature via the Jolt secp256k1
/// inline. The claimed outcome is authenticated by `recovery_batch::verify`
/// before validation output; callers must not omit that check. Public so the
/// guest binary can expose it to the vendored alloy-eip7702 (EIP-7702
/// authority recovery) through an `extern "C"` hook.
pub fn inline_ecrecover(sig: &[u8; 64], recid: u8, msg: &[u8; 32]) -> Option<[u8; 32]> {
    recovery_batch::recover(sig, recid, msg)
}

pub(crate) fn prepare_recovery(sig: &[u8; 64], mut recid: u8, msg: &[u8; 32]) -> Option<Equation> {
    if recid > 3 {
        return None;
    }
    // Parse r, s — canonical (< n) and nonzero, like k256's Signature::from_slice.
    let r_int = U256::from_be_slice(&sig[..32]);
    let mut s_int = U256::from_be_slice(&sig[32..]);
    if r_int.is_zero() || s_int.is_zero() || r_int >= N || s_int >= N {
        return None;
    }

    // normalize_s + recovery-id parity flip (k256 backend behavior).
    if s_int > N >> 1 {
        s_int = N - s_int;
        recid ^= 1;
    }

    // R.x = r (+ n when recid bit 1 signals a reduced x); must be a base field element.
    let mut x_int = r_int;
    if recid & 2 != 0 {
        x_int = x_int.checked_add(N)?;
        if x_int >= P {
            return None;
        }
    }
    let x = Secp256k1Fq::from_u64_arr(x_int.as_limbs()).ok()?;

    let y2 = x.square().mul(&x).add(&Secp256k1Fq::seven());
    #[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
    let (is_square, root) = {
        let root = fq_pow(&y2, &SQRT_EXP);
        if root.square().e() == y2.e() {
            (1u64, root.e())
        } else {
            (0u64, fq_pow(&y2.neg(), &SQRT_EXP).e())
        }
    };
    let square = advice_u64!(is_square);
    assert!(square <= 1, "quadratic residue advice flag");
    let mut limbs = [0; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = advice_u64!(root[i]);
        let _ = i;
    }
    let mut y = Secp256k1Fq::from_u64_arr(&limbs).expect("canonical square root advice");
    let expected = if square == 1 { y2 } else { y2.neg() };
    for (actual, expected) in y.square().e().into_iter().zip(expected.e()) {
        advice_assert_eq!(actual, expected);
    }
    if square == 0 {
        // -1 is nonsquare in Fq; a nonzero square root of -y2 proves y2 nonsquare.
        assert!(!y.is_zero(), "nonresidue certificate must be nonzero");
        return None;
    }
    let y_is_odd = y.e()[0] & 1 == 1;
    if y_is_odd != (recid & 1 == 1) {
        y = y.neg();
    }
    let r_point = Secp256k1Point::new_unchecked(x, y); // on-curve by construction

    Some(Equation {
        nonce: r_point,
        message: *msg,
        r: Secp256k1Fr::from_u64_arr(r_int.as_limbs()).ok()?,
        s: Secp256k1Fr::from_u64_arr(s_int.as_limbs()).ok()?,
        key: Secp256k1Point::infinity(),
    })
}

#[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
pub(crate) fn recover_point(equation: &Equation) -> Secp256k1Point {
    let z = recovery_batch::scalar(equation.message);
    let r_fr = &equation.r;
    let s_fr = &equation.s;
    let r_point = &equation.nonce;
    // Q = (-z/r)·G + (s/r)·R (r is nonzero — checked above).
    let u1 = z.div(r_fr).neg();
    let u2 = s_fr.div(r_fr);

    let decomp_u = u1.as_u128_pair();
    let decomp_v = u2.glv_decompose();
    let scalars = [decomp_u.0, decomp_u.1, decomp_v[0].1, decomp_v[1].1];
    let points = [
        conditional_negate(r_point.clone(), decomp_v[0].0),
        conditional_negate(r_point.endomorphism(), decomp_v[1].0),
    ];
    mul_4x128(scalars, points)
}

/// Square-and-multiply exponentiation over Fq (MSB-first; exponent LE limbs).
#[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
fn fq_pow(base: &Secp256k1Fq, exp: &[u64; 4]) -> Secp256k1Fq {
    let mut started = false;
    let mut acc = base.clone();
    for limb_idx in (0..4).rev() {
        for bit in (0..64).rev() {
            if started {
                acc = acc.square();
            }
            if (exp[limb_idx] >> bit) & 1 == 1 {
                if started {
                    acc = acc.mul(base);
                } else {
                    acc = base.clone();
                    started = true;
                }
            }
        }
    }
    acc
}

#[inline(always)]
#[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
fn conditional_negate(x: Secp256k1Point, cond: bool) -> Secp256k1Point {
    if cond {
        x.neg()
    } else {
        x
    }
}

#[inline(always)]
#[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
fn scalars_to_index(scalars: &[u128; 4], bit_index: usize) -> usize {
    let mut idx = 0;
    for (j, scalar) in scalars.iter().enumerate() {
        if (scalar >> bit_index) & 1 == 1 {
            idx |= 1 << j;
        }
    }
    idx
}

/// 4×128-bit multi-scalar multiplication; first two scalar slots multiply
/// G and 2^128·G (precomputed), the last two the supplied points.
#[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
fn mul_4x128(scalars: [u128; 4], points: [Secp256k1Point; 2]) -> Secp256k1Point {
    let mut lookup = Vec::<Secp256k1Point>::with_capacity(16);
    lookup.push(Secp256k1Point::infinity());
    lookup.push(Secp256k1Point::generator());
    lookup.push(Secp256k1Point::generator_times_2_pow_128());
    lookup.push(Secp256k1Point::generator_times_2_pow_128_plus_1());
    lookup.push(points[0].clone());
    lookup.push(lookup[1].add(&lookup[4]));
    lookup.push(lookup[2].add(&lookup[4]));
    lookup.push(lookup[1].add(&lookup[6]));
    lookup.push(points[1].clone());
    for i in 1..8 {
        lookup.push(lookup[i].add(&lookup[8]));
    }
    let mut res = lookup[scalars_to_index(&scalars, 127)].clone();
    for i in (0..127).rev() {
        let idx = scalars_to_index(&scalars, i);
        if idx != 0 {
            res = res.double_and_add(&lookup[idx]);
        } else {
            res = res.double();
        }
    }
    res
}
