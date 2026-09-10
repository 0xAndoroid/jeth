//! revm and EIP-7702 recovery through deferred, checked secp256k1 equations.

use crate::advice::{advice_assert_eq, advice_u64};
use crate::recovery_batch::{self, Equation};
#[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
use alloc::vec::Vec;
use alloy_primitives::{B256, U256};
use jolt_inlines_secp256k1::{Secp256k1Fq, Secp256k1Fr, Secp256k1Point, Secp256k1PointExt};
#[cfg(all(feature = "sha2-inline", target_arch = "riscv64"))]
use jolt_inlines_sha2::Sha256;
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

    /// SHA-256 on the Jolt inline; the native build keeps revm's default so `run-native` stays
    /// the independent reference.
    #[cfg(all(feature = "sha2-inline", target_arch = "riscv64"))]
    #[inline]
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        Sha256::digest(input)
    }

    /// The Jolt BLAKE2b inline is the fixed 12-round compression with a 64-bit counter, so only
    /// `rounds == 12 && t[1] == 0` calls take it; every other (rounds, t) stays on revm's
    /// software compress, whose sigma schedule (`SIGMA[r % 10]`) and IV the inline matches for
    /// those 12 rounds.
    #[cfg(all(feature = "blake2-inline", target_arch = "riscv64"))]
    #[inline]
    fn blake2_compress(&self, rounds: u32, h: &mut [u64; 8], m: &[u64; 16], t: &[u64; 2], f: bool) {
        if rounds == 12 && t[1] == 0 {
            blake2b_compress_inline(h, m, t[0], f);
        } else {
            reth_evm::revm::precompile::blake2::algo::compress(rounds as usize, h, m, t, f);
        }
    }

    #[cfg(all(feature = "p256-inline", target_arch = "riscv64"))]
    #[inline]
    fn secp256r1_verify_signature(&self, msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
        crate::p256::verify(msg, sig, pk)
    }
}

/// One BLAKE2b compression on the Jolt inline: `h` is updated in place; the inline reads the 16
/// message words, the 64-bit counter and the final flag (0/1) as 18 consecutive words at `rs2`
/// (`Blake2SequenceBuilder` memory contract: 8 words at rs1 read and written, 18 at rs2 read).
#[cfg(all(feature = "blake2-inline", target_arch = "riscv64"))]
fn blake2b_compress_inline(h: &mut [u64; 8], m: &[u64; 16], t0: u64, f: bool) {
    use jolt_inlines_blake2::{BLAKE2_FUNCT3, BLAKE2_FUNCT7, INLINE_OPCODE};
    let block: [u64; 18] = [
        m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13],
        m[14], m[15], t0, f as u64,
    ];
    // SAFETY: both arrays are 8-aligned and exactly the sizes the inline reads/writes.
    unsafe {
        core::arch::asm!(
            ".insn r {opcode}, {funct3}, {funct7}, x0, {rs1}, {rs2}",
            opcode = const INLINE_OPCODE,
            funct3 = const BLAKE2_FUNCT3,
            funct7 = const BLAKE2_FUNCT7,
            rs1 = in(reg) h.as_mut_ptr(),
            rs2 = in(reg) block.as_ptr(),
            options(nostack)
        );
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

// Native models of the two inlines (the `host` fallbacks of the inline crates, which is what the
// tracer executes too) against the software implementations they replace in the guest.
#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use reth_evm::revm::precompile::blake2::algo::compress;

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    fn random_bytes(rng: &mut u64, len: usize) -> Vec<u8> {
        (0..len).map(|_| xorshift(rng) as u8).collect()
    }

    /// Every length through 600 (padding boundaries 55/56/63/64/119/120 included), the harness
    /// sizes, and all-0xff inputs, against the sha2 crate revm's default `sha256` uses.
    #[test]
    fn sha256_inline_model_matches_sha2() {
        use sha2::Digest;
        let mut rng = 0x9e37_79b9_7f4a_7c15u64;
        let lens = (0..=600usize).chain([1024, 8192, 20_000]);
        for len in lens {
            let msg = random_bytes(&mut rng, len);
            let want: [u8; 32] = sha2::Sha256::digest(&msg).into();
            assert_eq!(jolt_inlines_sha2::Sha256::digest(&msg), want, "len {len}");
            let ones: Vec<u8> = core::iter::repeat_n(0xff, len).collect();
            let want: [u8; 32] = sha2::Sha256::digest(&ones).into();
            assert_eq!(
                jolt_inlines_sha2::Sha256::digest(&ones),
                want,
                "0xff len {len}"
            );
        }
    }

    fn inline_model(h: &mut [u64; 8], m: &[u64; 16], t0: u64, f: bool) {
        let mut block = [0u64; 18];
        block[..16].copy_from_slice(m);
        block[16] = t0;
        block[17] = f as u64;
        jolt_inlines_blake2::exec::execute_blake2b_compression(h, &block);
    }

    /// Random (h, m, t0, f) with counter edge values, 12 rounds, t[1] == 0: the routed case.
    #[test]
    fn blake2_inline_model_matches_revm_compress_for_12_rounds() {
        let mut rng = 0xb1a2_e2f0_0d15_ea5eu64;
        for i in 0..4000u64 {
            let mut h = [0u64; 8];
            h.iter_mut().for_each(|w| *w = xorshift(&mut rng));
            let mut m = [0u64; 16];
            m.iter_mut().for_each(|w| *w = xorshift(&mut rng));
            let t0 = match i % 4 {
                0 => 0,
                1 => u64::MAX,
                2 => xorshift(&mut rng),
                _ => 128 * i,
            };
            let f = i % 2 == 1;
            let mut want = h;
            compress(12, &mut want, &m, &[t0, 0], f);
            let mut got = h;
            inline_model(&mut got, &m, t0, f);
            assert_eq!(got, want, "case {i}");
        }
    }

    /// EIP-152 vectors 5 (f = 1) and 6 (f = 0): rounds 12, h = BLAKE2b-512 IV with the
    /// parameter block, m = "abc" zero-padded, t = 3.
    #[test]
    fn blake2_inline_model_matches_eip152_vectors() {
        let mut h = jolt_inlines_blake2::IV;
        h[0] ^= 0x0101_0000 ^ 64;
        let mut m = [0u64; 16];
        m[0] = 0x0063_6261;
        let expected: [(bool, [u64; 8]); 2] = [
            (
                true,
                [
                    0x0d4d_1c98_3fa5_80ba,
                    0xe9f6_129f_b697_276a,
                    0xb7c4_5a68_142f_214c,
                    0xd1a2_ffdb_6fbb_124b,
                    0x2d79_ab2a_39c5_877d,
                    0x95cc_3345_ded5_52c2,
                    0x5a92_f1db_a88a_d318,
                    0x2399_00d4_ed86_23b9,
                ],
            ),
            (
                false,
                [
                    0x2c56_0a19_d369_ab75,
                    0x7527_1c8f_d8f8_ae51,
                    0x2cc4_7072_4044_6987,
                    0x5287_d226_2c25_4498,
                    0xf2a2_5e6d_7f3e_7498,
                    0x1bd3_9c03_26d2_e8d3,
                    0x66d6_d3f2_c46a_424e,
                    0x3547_de6f_11c2_10a6,
                ],
            ),
        ];
        for (f, want) in expected {
            let mut got = h;
            inline_model(&mut got, &m, 3, f);
            assert_eq!(got, want, "f = {f}");
            let mut sw = h;
            compress(12, &mut sw, &m, &[3, 0], f);
            assert_eq!(sw, want, "revm f = {f}");
        }
    }
}
