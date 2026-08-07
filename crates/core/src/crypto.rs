//! revm `Crypto` override: EVM ecrecover precompile (0x01) via the Jolt
//! secp256k1 inline.
//!
//! Mirrors revm's k256 backend semantics exactly (`revm_precompile::secp256k1::k256`):
//! r/s must be canonical nonzero; high-s is normalized with the recovery-id
//! parity flipped; z is the prehash reduced mod n; R is decompressed from
//! r (+n when recid bit 1) with the parity bit; Q = (-z/r)·G + (s/r)·R;
//! identity → failure; output = keccak(Q)[12..] left-padded.
//!
//! The multi-scalar ladder mirrors `jolt-inlines-secp256k1`'s (private)
//! `secp256k1_4x128_inner_scalar_mul` (MIT/Apache-2.0, a16z). Any math error
//! here is self-checked downstream: a wrong precompile output diverges the
//! block's execution and the post-state root assertion fails the run.

use alloc::vec::Vec;
use alloy_primitives::{keccak256, B256, U256};
use jolt_inlines_secp256k1::{Secp256k1Fq, Secp256k1Fr, Secp256k1Point, Secp256k1PointExt};
use reth_evm::revm::precompile::{Crypto, PrecompileHalt};

/// secp256k1 curve order n (little-endian limbs).
const N: U256 = U256::from_limbs([
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
}

/// Recover `keccak(pubkey)` from a prehash signature via the Jolt secp256k1
/// inline — k256 backend semantics exactly (see module docs). Public so the
/// guest binary can expose it to the vendored alloy-eip7702 (EIP-7702
/// authority recovery) through an `extern "C"` hook.
pub fn inline_ecrecover(sig: &[u8; 64], mut recid: u8, msg: &[u8; 32]) -> Option<[u8; 32]> {
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

    // y = sqrt(x³ + 7) with the requested parity; reject non-residues.
    let y2 = x.square().mul(&x).add(&Secp256k1Fq::seven());
    let mut y = fq_pow(&y2, &SQRT_EXP);
    if y.square().e() != y2.e() {
        return None;
    }
    let y_is_odd = y.e()[0] & 1 == 1;
    if y_is_odd != (recid & 1 == 1) {
        y = y.neg();
    }
    let r_point = Secp256k1Point::new_unchecked(x, y); // on-curve by construction

    // z = prehash reduced mod n (k256 reduces rather than rejects).
    let mut z_int = U256::from_be_bytes(*msg);
    if z_int >= N {
        z_int -= N;
    }
    let z = Secp256k1Fr::from_u64_arr(z_int.as_limbs()).ok()?;
    let r_fr = Secp256k1Fr::from_u64_arr(r_int.as_limbs()).ok()?;
    let s_fr = Secp256k1Fr::from_u64_arr(s_int.as_limbs()).ok()?;

    // Q = (-z/r)·G + (s/r)·R (r is nonzero — checked above).
    let u1 = z.div(&r_fr).neg();
    let u2 = s_fr.div(&r_fr);

    let decomp_u = u1.as_u128_pair();
    let decomp_v = u2.glv_decompose();
    let scalars = [decomp_u.0, decomp_u.1, decomp_v[0].1, decomp_v[1].1];
    let points = [
        conditional_negate(r_point.clone(), decomp_v[0].0),
        conditional_negate(r_point.endomorphism(), decomp_v[1].0),
    ];
    let q = mul_4x128(scalars, points);
    if q.is_infinity() {
        return None;
    }

    // keccak(x_be || y_be), address in the low 20 bytes.
    let mut pubkey = [0u8; 64];
    pubkey[..32].copy_from_slice(&fq_to_be(&q.x()));
    pubkey[32..].copy_from_slice(&fq_to_be(&q.y()));
    let mut hash: B256 = keccak256(pubkey);
    hash[..12].fill(0);
    Some(hash.0)
}

#[inline]
fn fq_to_be(f: &Secp256k1Fq) -> [u8; 32] {
    U256::from_limbs(f.e()).to_be_bytes()
}

/// Square-and-multiply exponentiation over Fq (MSB-first; exponent LE limbs).
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
fn conditional_negate(x: Secp256k1Point, cond: bool) -> Secp256k1Point {
    if cond {
        x.neg()
    } else {
        x
    }
}

#[inline(always)]
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
