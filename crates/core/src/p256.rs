//! RIP-7212 `P256VERIFY` through the Jolt P-256 inline.
//!
//! Accept set = revm's software path (`p256` 0.13 / `ecdsa` 0.16): `pk` decodes
//! to an on-curve point ≠ O with canonical coordinates, `r, s ∈ [1, n−1]` (no
//! low-s rule), and `x(u1·G + u2·Q) mod n == r` with `z = msg mod n`. The
//! inline rejects `z == 0`, which the software path accepts, so that case is
//! rewritten into an equivalent nonzero-z instance.

use alloy_primitives::U256;
use jolt_inlines_p256::{ecdsa_verify, P256Fr, P256Point, P256PointExt, P256_ORDER};

const N: U256 = U256::from_limbs(P256_ORDER);

pub(crate) fn verify(msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> bool {
    let mut limbs = [0; 8];
    limbs[..4].copy_from_slice(U256::from_be_slice(&pk[..32]).as_limbs());
    limbs[4..].copy_from_slice(U256::from_be_slice(&pk[32..]).as_limbs());
    let (Ok(q), Ok(r), Ok(s)) = (
        P256Point::from_u64_arr(&limbs),
        P256Fr::from_u64_arr(U256::from_be_slice(&sig[..32]).as_limbs()),
        P256Fr::from_u64_arr(U256::from_be_slice(&sig[32..]).as_limbs()),
    ) else {
        return false;
    };
    if q.is_infinity() {
        return false;
    }
    // n > 2^255, so one subtraction fully reduces a 256-bit integer.
    let mut z = U256::from_be_bytes(*msg);
    if z >= N {
        z -= N;
    }
    let (z, q) = if z.is_zero() {
        // u1 = 0 leaves R = (r/s)·Q. Verify the same point as
        // (r/s)·G + (r/s)·(Q − G), or −(r/s)·G + (r/s)·2G when Q = G.
        let g = P256Point::generator();
        if q.to_u64_arr() == g.to_u64_arr() {
            (r.neg(), g.double())
        } else {
            (r.clone(), q.add(&g.neg()))
        }
    } else {
        (
            P256Fr::from_u64_arr(z.as_limbs()).expect("reduced mod n"),
            q,
        )
    };
    ecdsa_verify(z, r, s, q).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
    use reth_evm::revm::precompile::secp256r1::verify_impl;

    /// P-256 base field modulus p (big-endian).
    const P: U256 = U256::from_limbs(jolt_inlines_p256::P256_MODULUS);

    fn compare(msg: [u8; 32], sig: [u8; 64], pk: [u8; 64]) -> bool {
        let mut input = [0; 160];
        input[..32].copy_from_slice(&msg);
        input[32..96].copy_from_slice(&sig);
        input[96..].copy_from_slice(&pk);
        let software = verify_impl(&input);
        assert_eq!(
            verify(&msg, &sig, &pk),
            software,
            "msg={msg:?} sig={sig:?} pk={pk:?}"
        );
        software
    }

    fn keypair(scalar: U256) -> (SigningKey, [u8; 64]) {
        let key = SigningKey::from_bytes(&scalar.to_be_bytes::<32>().into()).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        let mut pk = [0; 64];
        pk.copy_from_slice(&point.as_bytes()[1..]);
        (key, pk)
    }

    fn sign(key: &SigningKey, prehash: [u8; 32]) -> [u8; 64] {
        let signature: Signature = key.sign_prehash(&prehash).unwrap();
        let mut sig = [0; 64];
        sig.copy_from_slice(&signature.to_bytes());
        sig
    }

    fn with(sig: [u8; 64], r: Option<U256>, s: Option<U256>) -> [u8; 64] {
        let mut out = sig;
        if let Some(r) = r {
            out[..32].copy_from_slice(&r.to_be_bytes::<32>());
        }
        if let Some(s) = s {
            out[32..].copy_from_slice(&s.to_be_bytes::<32>());
        }
        out
    }

    fn split(sig: [u8; 64]) -> (U256, U256) {
        (
            U256::from_be_slice(&sig[..32]),
            U256::from_be_slice(&sig[32..]),
        )
    }

    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn bytes(&mut self) -> [u8; 32] {
            let mut out = [0; 32];
            for chunk in out.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_be_bytes());
            }
            out
        }

        fn flip<const L: usize>(&mut self, mut bytes: [u8; L]) -> [u8; L] {
            let bit = self.next() as usize % (8 * L);
            bytes[bit / 8] ^= 1 << (bit % 8);
            bytes
        }
    }

    #[test]
    fn signature_and_key_edge_vectors_match_software() {
        let (key, pk) = keypair(U256::from(0x1111_2222_3333_4444u64));
        let msg = [0x42; 32];
        let sig = sign(&key, msg);
        let (r, s) = split(sig);
        assert!(compare(msg, sig, pk));
        // high-s twin (no low-s rule).
        assert!(compare(msg, with(sig, None, Some(N - s)), pk));
        for bad in [
            with(sig, Some(U256::ZERO), None),
            with(sig, None, Some(U256::ZERO)),
            with(sig, Some(N), None),
            with(sig, None, Some(N)),
            with(sig, Some(N - U256::from(1)), None),
            with(sig, Some(U256::MAX), None),
            with(sig, None, Some(U256::MAX)),
            with(sig, Some(r + U256::from(1)), None),
        ] {
            assert!(!compare(msg, bad, pk));
        }
        let mut wrong_msg = msg;
        wrong_msg[0] ^= 1;
        assert!(!compare(wrong_msg, sig, pk));

        let (x, y) = (
            U256::from_be_slice(&pk[..32]),
            U256::from_be_slice(&pk[32..]),
        );
        let point = |x: U256, y: U256| {
            let mut out = [0; 64];
            out[..32].copy_from_slice(&x.to_be_bytes::<32>());
            out[32..].copy_from_slice(&y.to_be_bytes::<32>());
            out
        };
        for bad in [
            point(P, y),
            point(x + P, y),
            point(x, P),
            point(x, y + P),
            point(x, y + U256::from(1)),
            point(x + U256::from(1), y),
            point(U256::ZERO, U256::ZERO),
            point(U256::MAX, U256::MAX),
            point(x, P - y),
        ] {
            assert!(!compare(msg, bad, pk));
        }
        // −Q is on the curve but not the signer's key.
        assert!(!compare(msg, sig, point(x, P - y)));
    }

    #[test]
    fn message_reduction_matches_software() {
        let (key, pk) = keypair(U256::from(7));
        // z = 1 signed; msg = n + 1 reduces to it.
        let one = U256::from(1).to_be_bytes::<32>();
        let sig = sign(&key, one);
        assert!(compare(one, sig, pk));
        assert!(compare((N + U256::from(1)).to_be_bytes::<32>(), sig, pk));
        assert!(!compare((N + U256::from(2)).to_be_bytes::<32>(), sig, pk));
        // msg = 2^256 − 1 reduces to 2^256 − 1 − n.
        let top = U256::MAX - N;
        let sig = sign(&key, top.to_be_bytes::<32>());
        assert!(compare(U256::MAX.to_be_bytes::<32>(), sig, pk));
        assert!(!compare(
            (U256::MAX - U256::from(1)).to_be_bytes::<32>(),
            sig,
            pk
        ));
        // msg = n − 1 is already reduced.
        let sig = sign(&key, (N - U256::from(1)).to_be_bytes::<32>());
        assert!(compare((N - U256::from(1)).to_be_bytes::<32>(), sig, pk));
    }

    #[test]
    fn zero_message_hash_matches_software() {
        // Q = G, 2G (R1 == R2 inside the rewritten instance), −G, −2G (Q − G is a
        // doubling) and a generic key.
        let keys = [
            U256::from(1),
            U256::from(2),
            U256::from(3),
            N - U256::from(1),
            N - U256::from(2),
            U256::from(0xdead_beefu64),
        ];
        for d in keys {
            let (key, pk) = keypair(d);
            let sig = sign(&key, [0; 32]);
            assert!(compare([0; 32], sig, pk));
            assert!(compare(N.to_be_bytes::<32>(), sig, pk));
            let (r, s) = split(sig);
            assert!(compare([0; 32], with(sig, None, Some(N - s)), pk));
            assert!(!compare(
                [0; 32],
                with(sig, Some(r + U256::from(1)), None),
                pk
            ));
            assert!(!compare(
                [0; 32],
                with(sig, None, Some(s + U256::from(1))),
                pk
            ));
            assert!(!compare(U256::from(1).to_be_bytes::<32>(), sig, pk));
            assert!(!compare([0; 32], with(sig, Some(U256::ZERO), None), pk));
            assert!(!compare([0; 32], with(sig, None, Some(U256::ZERO)), pk));
            // z = 0 only constrains x((r/s)·Q): a signature for Q also verifies for −Q.
            for other in keys {
                let (_, other_pk) = keypair(other);
                assert_eq!(
                    compare([0; 32], sig, other_pk),
                    other == d || other + d == N
                );
            }
        }
    }

    #[test]
    fn randomized_vectors_match_software() {
        let mut rng = Xorshift(0x9E37_79B9_7F4A_7C15);
        let mut valid = 0;
        for _ in 0..200 {
            let d = U256::from_be_bytes(rng.bytes());
            if d.is_zero() || d >= N {
                continue;
            }
            let (key, pk) = keypair(d);
            let msg = rng.bytes();
            let sig = sign(&key, msg);
            assert!(compare(msg, sig, pk));
            valid += 1;
            compare(msg, rng.flip(sig), pk);
            compare(msg, sig, rng.flip(pk));
            compare(rng.flip(msg), sig, pk);
            let sig = sign(&key, [0; 32]);
            assert!(compare([0; 32], sig, pk) && compare(N.to_be_bytes::<32>(), sig, pk));
        }
        assert!(valid > 150);
        // Garbage inputs: random (msg, r, s, x, y).
        for _ in 0..200 {
            let (mut sig, mut pk) = ([0; 64], [0; 64]);
            sig[..32].copy_from_slice(&rng.bytes());
            sig[32..].copy_from_slice(&rng.bytes());
            pk[..32].copy_from_slice(&rng.bytes());
            pk[32..].copy_from_slice(&rng.bytes());
            assert!(!compare(rng.bytes(), sig, pk));
        }
    }

    #[test]
    fn rip7212_vectors_match_software() {
        // daimo-eth/p256-verifier test vectors (revm's secp256r1 tests): 5 valid + 1 wrong message.
        for (hex, expected) in [
            ("4cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e", true),
            ("3fec5769b5cf4e310a7d150508e82fb8e3eda1c2c94c61492d3bd8aea99e06c9e22466e928fdccef0de49e3503d2657d00494a00e764fd437bdafa05f5922b1fbbb77c6817ccf50748419477e843d5bac67e6a70e97dde5a57e0c983b777e1ad31a80482dadf89de6302b1988c82c29544c9c07bb910596158f6062517eb089a2f54c9a0f348752950094d3228d3b940258c75fe2a413cb70baa21dc2e352fc5", true),
            ("e775723953ead4a90411a02908fd1a629db584bc600664c609061f221ef6bf7c440066c8626b49daaa7bf2bcc0b74be4f7a1e3dcf0e869f1542fe821498cbf2de73ad398194129f635de4424a07ca715838aefe8fe69d1a391cfa70470795a80dd056866e6e1125aff94413921880c437c9e2570a28ced7267c8beef7e9b2d8d1547d76dfcf4bee592f5fefe10ddfb6aeb0991c5b9dbbee6ec80d11b17c0eb1a", true),
            ("b5a77e7a90aa14e0bf5f337f06f597148676424fae26e175c6e5621c34351955289f319789da424845c9eac935245fcddd805950e2f02506d09be7e411199556d262144475b1fa46ad85250728c600c53dfd10f8b3f4adf140e27241aec3c2da3a81046703fccf468b48b145f939efdbb96c3786db712b3113bb2488ef286cdcef8afe82d200a5bb36b5462166e8ce77f2d831a52ef2135b2af188110beaefb1", true),
            ("858b991cfd78f16537fe6d1f4afd10273384db08bdfc843562a22b0626766686f6aec8247599f40bfe01bec0e0ecf17b4319559022d4d9bf007fe929943004eb4866760dedf31b7c691f5ce665f8aae0bda895c23595c834fecc2390a5bcc203b04afcacbb4280713287a2d0c37e23f7513fab898f2c1fefa00ec09a924c335d9b629f1d4fb71901c3e59611afbfea354d101324e894c788d1c01f00b3c251b2", true),
            ("3cee90eb86eaa050036147a12d49004b6b9c72bd725d39d4785011fe190f0b4da73bd4903f0ce3b639bbbf6e8e80d16931ff4bcf5993d58468e8fb19086e8cac36dbcd03009df8c59286b162af3bd7fcc0450c9aa81be5d10d312af6c66b1d604aebd3099c618202fcfe16ae7770b0c49ab5eadf74b754204a3bb6060e44eff37618b065f9832de4ca6ca971a7a1adc826d0f7c00181a5fb2ddf79ae00b4e10e", false),
        ] {
            let input: [u8; 160] = alloy_primitives::hex::decode(hex).unwrap().try_into().unwrap();
            let (msg, sig, pk) = (
                input[..32].try_into().unwrap(),
                input[32..96].try_into().unwrap(),
                input[96..].try_into().unwrap(),
            );
            assert_eq!(compare(msg, sig, pk), expected);
            let (_, s) = split(sig);
            assert_eq!(compare(msg, with(sig, None, Some(N - s)), pk), expected);
        }
    }
}
