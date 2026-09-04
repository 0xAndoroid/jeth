use super::*;
use crate::crypto::inline_ecrecover;
use alloy_primitives::Signature;
use k256::ecdsa::{RecoveryId, Signature as KSignature, VerifyingKey};
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

#[test]
fn pippenger_batch_matches_independent_recovery() {
    let r = generator_r();
    let mut equations = Vec::new();
    for i in 2..270u64 {
        let msg = U256::from(i).to_be_bytes();
        let sig = signature(r, U256::from(i % 11 + 1));
        let mut equation = prepare_recovery(&sig, (i % 2) as u8, &msg).unwrap();
        let key = VerifyingKey::recover_from_prehash(
            &msg,
            &KSignature::from_slice(&sig).unwrap(),
            RecoveryId::from_byte((i % 2) as u8).unwrap(),
        )
        .unwrap()
        .to_encoded_point(false);
        let bytes = key.as_bytes();
        let mut limbs = [0; 8];
        limbs[..4].copy_from_slice(U256::from_be_slice(&bytes[1..33]).as_limbs());
        limbs[4..].copy_from_slice(U256::from_be_slice(&bytes[33..]).as_limbs());
        equation.key = Secp256k1Point::from_u64_arr(&limbs).unwrap();
        equations.push(equation);
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
fn transaction_key_must_be_finite_and_on_curve() {
    let sig = Signature::new(generator_r(), U256::from(1), false);
    let mut key = [0; 65];
    assert!(verify_pubkey(&key, &sig, B256::ZERO).is_none());
    key[0] = 4;
    assert!(verify_pubkey(&key, &sig, B256::ZERO).is_none());
    key[64] = 1;
    assert!(verify_pubkey(&key, &sig, B256::ZERO).is_none());
}
