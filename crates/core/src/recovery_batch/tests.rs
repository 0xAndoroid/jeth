use super::*;
use crate::crypto::inline_ecrecover;
use alloy_primitives::Signature;
use k256::ecdsa::{RecoveryId, Signature as KSignature, SigningKey, VerifyingKey};
use reth_evm::revm::precompile::secp256k1::k256::ecrecover;

fn signature(r: U256, s: U256) -> [u8; 64] {
    let mut sig = [0; 64];
    sig[..32].copy_from_slice(&r.to_be_bytes::<32>());
    sig[32..].copy_from_slice(&s.to_be_bytes::<32>());
    sig
}

fn generator_r() -> U256 {
    U256::from_limbs(Secp256k1Point::generator().x().e())
}

fn compare(sig: [u8; 64], recid: u8, message: [u8; 32]) -> Option<[u8; 32]> {
    let expected = RecoveryId::from_byte(recid)
        .and_then(|_| ecrecover(&sig.into(), recid, &message.into()).ok())
        .map(|x| x.0);
    let actual = inline_ecrecover(&sig, recid, &message);
    assert_eq!(
        actual, expected,
        "recid={recid}, sig={sig:?}, msg={message:?}"
    );
    verify();
    actual
}

#[test]
fn edge_vectors_match_k256() {
    let r = generator_r();
    let z = U256::from(2).to_be_bytes();
    let p = U256::from_limbs([0xffff_fffe_ffff_fc2f, u64::MAX, u64::MAX, u64::MAX]);
    for (r, s, recid) in [
        (U256::ZERO, U256::from(1), 0),
        (r, U256::ZERO, 0),
        (N, U256::from(1), 0),
        (U256::MAX, U256::from(1), 0),
        (r, N, 0),
        (r, U256::MAX, 0),
        (r, U256::from(1), 2),
        (p - N, U256::from(1), 2),
        (U256::from(1), U256::from(1), 4),
        (r, U256::from(1), 255),
    ] {
        assert!(compare(signature(r, s), recid, z).is_none());
    }
    let mut nonresidue_count = 0;
    for x in 1..32 {
        let sig = signature(U256::from(x), U256::from(1));
        if compare(sig, 0, z).is_none() {
            nonresidue_count += 1;
        }
        compare(sig, 1, z);
        compare(sig, 2, z);
        compare(sig, 3, z);
    }
    assert!(nonresidue_count > 0);
    assert!(compare(signature(r, U256::from(1)), 0, U256::from(1).to_be_bytes()).is_none());
    assert!(compare(signature(r, U256::from(1)), 0, [0; 32]).is_some());
    compare(signature(r, U256::from(1)), 1, N.to_be_bytes());
    compare(signature(r, U256::from(1)), 0, [255; 32]);
}

#[test]
fn high_s_precompile_acceptance_and_tx_low_s_rejection() {
    let r = generator_r();
    let z = U256::from(2).to_be_bytes();
    let low = compare(signature(r, U256::from(1)), 0, z).unwrap();
    let high = compare(signature(r, N - U256::from(1)), 1, z).unwrap();
    assert_eq!(low, high);
    use crate::UncompressedPublicKey;
    use alloy_consensus::TxLegacy;
    use reth_ethereum_primitives::{Transaction, TransactionSigned};
    let tx = TransactionSigned::new_unhashed(
        Transaction::Legacy(TxLegacy::default()),
        Signature::new(r, N - U256::from(1), true),
    );
    let result =
        crate::recover::verify_and_compute_sender(&UncompressedPublicKey([0; 65]), &tx, true);
    assert!(matches!(
        result,
        Err(stateless::validation::StatelessValidationError::HomesteadSignatureNotNormalized)
    ));
}

#[test]
fn evm_rejects_invalid_v_word() {
    use reth_evm::revm::precompile::secp256k1::ec_recover_run;
    crate::install_jolt_crypto();
    let mut input = [0; 128];
    input[..32].copy_from_slice(&U256::from(2).to_be_bytes::<32>());
    input[64..].copy_from_slice(&signature(generator_r(), U256::from(1)));
    for v in [0, 1, 26, 29, 255] {
        input[63] = v;
        assert!(ec_recover_run(&input, 3000).unwrap().bytes.is_empty());
    }
    input[63] = 27;
    assert_eq!(ec_recover_run(&input, 3000).unwrap().bytes.len(), 32);
    verify();
    input[32] = 1;
    assert!(ec_recover_run(&input, 3000).unwrap().bytes.is_empty());
}

fn valid_equation(z: u64) -> Equation {
    let mut equation = prepare_recovery(
        &signature(generator_r(), U256::from(1)),
        0,
        &U256::from(z).to_be_bytes(),
    )
    .unwrap();
    equation.key = crate::crypto::recover_point(&equation);
    equation
}

#[test]
#[should_panic(expected = "invalid recovery batch")]
fn forged_key_must_panic() {
    let mut equation = valid_equation(2);
    equation.key = Secp256k1Point::generator();
    Batch {
        equations: alloc::vec![equation],
    }
    .verify();
}

#[test]
#[should_panic(expected = "invalid recovery batch")]
fn forged_failure_must_panic() {
    let mut equation = valid_equation(2);
    equation.key = Secp256k1Point::infinity();
    Batch {
        equations: alloc::vec![equation],
    }
    .verify();
}

#[test]
fn transcript_binds_count_order_and_every_component() {
    let a = valid_equation(2);
    let b = valid_equation(3);
    let batch = Batch {
        equations: alloc::vec![a.clone(), b.clone()],
    };
    let lambda = challenge(batch.transcript(), 0).e();
    let check = |equations| {
        assert_ne!(lambda, challenge(Batch { equations }.transcript(), 0).e());
    };
    check(alloc::vec![b.clone(), a.clone()]);
    check(alloc::vec![a.clone()]);
    for field in 0..5 {
        let mut changed = a.clone();
        match field {
            0 => changed.nonce = b.nonce.neg(),
            1 => changed.message[0] ^= 1,
            2 => changed.r = b.r.neg(),
            3 => changed.s = b.s.neg(),
            _ => changed.key = b.key.clone(),
        }
        check(alloc::vec![changed, b.clone()]);
    }
    assert_ne!(lambda, challenge(batch.transcript(), 1).e());
}

fn key_point(key: &VerifyingKey) -> Secp256k1Point {
    let bytes = key.to_sec1_point(false);
    let bytes = bytes.as_bytes();
    let mut limbs = [0; 8];
    limbs[..4].copy_from_slice(U256::from_be_slice(&bytes[1..33]).as_limbs());
    limbs[4..].copy_from_slice(U256::from_be_slice(&bytes[33..]).as_limbs());
    Secp256k1Point::from_u64_arr(&limbs).unwrap()
}

fn recovered_equation(i: u64) -> Equation {
    let msg = U256::from(i).to_be_bytes();
    let sig = signature(generator_r(), U256::from(i % 11 + 1));
    let mut equation = prepare_recovery(&sig, (i % 2) as u8, &msg).unwrap();
    let key = VerifyingKey::recover_from_prehash(
        &msg,
        &KSignature::from_slice(&sig).unwrap(),
        RecoveryId::from_byte((i % 2) as u8).unwrap(),
    )
    .unwrap();
    equation.key = key_point(&key);
    equation
}

/// An equation signed by `signing_key` over message `z`; equations from one
/// signing key share their key point.
fn signed_equation(signing_key: &SigningKey, z: u64) -> Equation {
    let msg = U256::from(z).to_be_bytes();
    let (sig, recid) = signing_key.sign_prehash_recoverable(&msg);
    let sig: [u8; 64] = sig.to_bytes().into();
    let mut equation = prepare_recovery(&sig, recid.to_byte(), &msg).unwrap();
    equation.key = key_point(signing_key.verifying_key());
    equation
}

fn shared_key_batch() -> Vec<Equation> {
    let signing_key = SigningKey::from_slice(&U256::from(7).to_be_bytes::<32>()).unwrap();
    alloc::vec![
        signed_equation(&signing_key, 2),
        recovered_equation(5),
        signed_equation(&signing_key, 3),
    ]
}

#[test]
fn shared_key_equations_verify() {
    let equations = shared_key_batch();
    assert_eq!(equations[0].key.to_u64_arr(), equations[2].key.to_u64_arr());
    Batch { equations }.verify();
}

#[test]
#[should_panic(expected = "invalid recovery batch")]
fn forged_equation_behind_a_shared_key_must_panic() {
    let mut equations = shared_key_batch();
    equations[2].message[31] ^= 1;
    Batch { equations }.verify();
}

#[test]
fn pippenger_batch_matches_independent_recovery() {
    let mut equations = Vec::new();
    // Exercise both the intermediate batch of 99 equations and the full 598.
    for i in 2..600u64 {
        equations.push(recovered_equation(i));
        if i == 100 {
            Batch {
                equations: equations.clone(),
            }
            .verify();
        }
    }
    Batch { equations }.verify();
}

#[test]
#[should_panic(expected = "invalid recovery batch")]
fn forged_key_in_wide_batch_must_panic() {
    // Reject one forged key among 598 independently recovered equations.
    let mut equations: Vec<_> = (2..600u64).map(recovered_equation).collect();
    equations[300].key = Secp256k1Point::generator();
    Batch { equations }.verify();
}

#[test]
fn transaction_key_must_be_finite_and_on_curve() {
    let sig = Signature::new(generator_r(), U256::from(1), false);
    let mut key = [0; 65];
    assert!(verify_pubkey(&key, &sig, B256::ZERO).is_none());
    key[0] = 4;
    assert!(verify_pubkey(&key, &sig, B256::ZERO).is_none());
    key[64] = 1;
    assert!(verify_pubkey(&key, &sig, B256::ZERO).is_none());
}

fn randomized_signatures() -> Vec<([u8; 64], u8, [u8; 32])> {
    let mut state = 0xd4e1_8a73_09bc_52f6u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    (0..48)
        .map(|_| {
            let secret = U256::from(next().max(1)).to_be_bytes::<32>();
            let key = SigningKey::from_slice(&secret).unwrap();
            let message = U256::from_limbs(core::array::from_fn(|_| next())).to_be_bytes();
            let (sig, id) = key.sign_prehash_recoverable(&message);
            (sig.to_bytes().into(), id.to_byte(), message)
        })
        .collect()
}

#[test]
fn randomized_deferred_batch_matches_single_recovery() {
    for (sig, id, message) in randomized_signatures() {
        let expected = ecrecover(&sig.into(), id, &message.into()).unwrap().0;
        assert_eq!(inline_ecrecover(&sig, id, &message), Some(expected));
    }
    verify();
}

#[test]
fn one_invalid_signature_among_random_valid_signatures() {
    let signatures = randomized_signatures();
    let (valid, id, message) = signatures[17];
    let r = U256::from_be_slice(&valid[..32]);
    let s = U256::from_be_slice(&valid[32..]);
    let cases = [
        (signature(U256::ZERO, s), id),
        (signature(r, U256::ZERO), id),
        (signature(N, s), id),
        (signature(r, N), id),
        (signature(U256::MAX, s), id),
        (signature(r, U256::MAX), id),
        (valid, 4),
        (valid, 255),
    ];
    for (bad, bad_id) in cases {
        for (index, &(sig, recid, msg)) in signatures.iter().enumerate() {
            let (sig, recid, msg) = if index == 17 {
                (bad, bad_id, message)
            } else {
                (sig, recid, msg)
            };
            let expected = RecoveryId::from_byte(recid)
                .and_then(|_| ecrecover(&sig.into(), recid, &msg.into()).ok())
                .map(|address| address.0);
            assert_eq!(inline_ecrecover(&sig, recid, &msg), expected);
            assert_eq!(expected.is_none(), index == 17);
        }
        verify();
    }
}

#[test]
fn randomized_high_s_and_wrong_parity_match_single_recovery() {
    for (sig, id, msg) in randomized_signatures().into_iter().take(12) {
        let r = U256::from_be_slice(&sig[..32]);
        let s = U256::from_be_slice(&sig[32..]);
        let high = signature(r, N - s);
        assert_eq!(
            inline_ecrecover(&high, id ^ 1, &msg),
            Some(ecrecover(&sig.into(), id, &msg.into()).unwrap().0)
        );
        let expected = ecrecover(&sig.into(), id ^ 1, &msg.into())
            .ok()
            .map(|x| x.0);
        assert_eq!(inline_ecrecover(&sig, id ^ 1, &msg), expected);
    }
    verify();
}

#[test]
#[should_panic(expected = "invalid recovery batch")]
fn one_wrong_key_in_randomized_batch_is_rejected() {
    let mut equations = Vec::new();
    for (sig, id, msg) in randomized_signatures() {
        let key = VerifyingKey::recover_from_prehash(
            &msg,
            &KSignature::from_slice(&sig).unwrap(),
            RecoveryId::from_byte(id).unwrap(),
        )
        .unwrap();
        let mut equation = prepare_recovery(&sig, id, &msg).unwrap();
        equation.key = key_point(&key);
        equations.push(equation);
    }
    equations[17].key = equations[17].key.neg();
    Batch { equations }.verify();
}

#[test]
fn signed_window_reconstruction_including_top_carry() {
    let mut state = 0x7b13_508a_c6f4_219du128;
    for width in 4usize..=12 {
        let windows = 128usize.div_ceil(width);
        let half = 1usize << (width - 1);
        let top_shift = width * (windows - 1);
        let bias = (0..windows - 1).fold(0u128, |acc, i| acc | (half as u128) << (width * i));
        for case in 0..130 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let scalar = match case {
                0 => 0,
                1 => u128::MAX,
                _ => state,
            };
            let (biased, overflow) = scalar.overflowing_add(bias);
            let top = (biased >> top_shift) | (overflow as u128) << (128 - top_shift);
            let mut reconstructed = U256::from(top);
            for window in (0..windows - 1).rev() {
                reconstructed <<= width;
                let digit = ((biased >> (window * width)) as usize & ((1 << width) - 1)) as isize
                    - half as isize;
                if digit < 0 {
                    reconstructed -= U256::from((-digit) as usize);
                } else {
                    reconstructed += U256::from(digit as usize);
                }
            }
            assert_eq!(
                reconstructed,
                U256::from(scalar),
                "width {width} case {case}"
            );
        }
    }
}

#[test]
fn msm_ignores_infinity_terms_and_zero_scalars() {
    let zero = scalar([0; 32]);
    let one = scalar(U256::from(1).to_be_bytes());
    assert!(pippenger(&[
        (one, Secp256k1Point::infinity()),
        (zero, Secp256k1Point::generator()),
    ])
    .is_infinity());
}

#[test]
fn specialized_windows_match_binary_scalar_multiplication() {
    let a = scalar([0xd3; 32]);
    let b = scalar([0x79; 32]);
    let total = a.add(&b.dbl());
    let g = Secp256k1Point::generator();
    let terms = [(a, g.clone()), (b, g.double())];
    let limbs = total.e();
    let mut expected = Secp256k1Point::infinity();
    for bit in (0..256).rev() {
        expected = expected.double();
        if (limbs[bit / 64] >> (bit % 64)) & 1 != 0 {
            expected = expected.add(&g);
        }
    }
    macro_rules! check {
        ($($width:literal),*) => { $(
            assert_eq!(pippenger_width::<$width>(&terms).to_u64_arr(), expected.to_u64_arr());
        )* };
    }
    check!(4, 5, 6, 7, 8, 9, 10, 11, 12);
}
