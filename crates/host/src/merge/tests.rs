use super::*;
use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_primitives::Signature;
use reth_consensus::HeaderValidator;
use reth_ethereum_consensus::EthBeaconConsensus;
use reth_primitives_traits::SealedHeader;

/// Fusaka-era (BPO2) timestamps; the child is one slot after the parent.
const PARENT_TIMESTAMP: u64 = 1_789_000_000;

fn parent() -> Header {
    Header {
        number: 25_905_780,
        timestamp: PARENT_TIMESTAMP,
        gas_limit: 45_000_000,
        gas_used: 31_337_000,
        base_fee_per_gas: Some(1_234_567_890),
        excess_blob_gas: Some(5_000_000),
        blob_gas_used: Some(6 * DATA_GAS_PER_BLOB),
        withdrawals_root: Some(B256::ZERO),
        parent_beacon_block_root: Some(B256::repeat_byte(0xbb)),
        requests_hash: Some(B256::ZERO),
        state_root: B256::repeat_byte(0x55),
        parent_hash: B256::repeat_byte(0x11),
        ..Default::default()
    }
}

fn first() -> Header {
    Header {
        number: 25_905_781,
        timestamp: PARENT_TIMESTAMP + 12,
        beneficiary: Address::repeat_byte(0xc0),
        mix_hash: B256::repeat_byte(0x77),
        extra_data: Bytes::from_static(b"jeth"),
        parent_beacon_block_root: Some(B256::repeat_byte(0xbe)),
        ..Default::default()
    }
}

#[test]
fn rewritten_parent_makes_synthetic_header_valid() {
    let chain_spec = Arc::new(jeth_core::mainnet_spec());
    let blob_params = chain_spec
        .blob_params_at_timestamp(first().timestamp)
        .unwrap();
    let original = parent();
    for (gas_limit, base_fee, excess_target) in [
        (321_000_000, 700_000_000, 2_000_000),
        (60_000_000, 1, 0),
        (1_000_000, 1_234_567_890, 5_000_000),
        // Mainnet N2 merge (25905781..2): blob fee above the reserve price, so the
        // solver needs the non-reserve branch (parent blob_gas_used = target).
        (91_000_000, 63_046_102, 177_862_678),
    ] {
        let (rewritten, rewrites) =
            rewrite_parent(&original, gas_limit, base_fee, excess_target, blob_params);
        // Pre-state root and grandparent link survive the rewrite.
        assert_eq!(rewritten.state_root, original.state_root);
        assert_eq!(rewritten.parent_hash, original.parent_hash);
        assert_eq!(rewritten.number, original.number);
        assert!(!rewrites.is_empty());
        // EIP-1559: the parent sat exactly at its gas target, so the fee carries over.
        assert_eq!(
            calc_next_block_base_fee(
                rewritten.gas_used,
                rewritten.gas_limit,
                rewritten.base_fee_per_gas.unwrap(),
                BaseFeeParams::ethereum()
            ),
            base_fee
        );
        let excess = blob_params.next_block_excess_blob_gas_osaka(
            rewritten.excess_blob_gas.unwrap(),
            rewritten.blob_gas_used.unwrap(),
            rewritten.base_fee_per_gas.unwrap(),
        );
        assert_eq!(excess, excess_target, "blob solver missed {excess_target}");

        let header = synthetic_header(&first(), &rewritten, gas_limit, base_fee, excess, &[], &[]);
        let consensus = EthBeaconConsensus::new(chain_spec.clone());
        let sealed = SealedHeader::seal_slow(header);
        consensus.validate_header(&sealed).unwrap();
        consensus
            .validate_header_against_parent(&sealed, &SealedHeader::seal_slow(rewritten))
            .unwrap();
    }
}

#[test]
fn required_gas_limit_covers_every_tx_gas_limit() {
    // Second tx: 5M gas limit with 800k already used → 5.8M of room needed,
    // far above the 900k actually burned; rounds up to the next 1M.
    assert_eq!(
        required_gas_limit([(900_000, 800_000), (5_000_000, 900_000)]),
        6_000_000
    );
    assert_eq!(required_gas_limit([(21_000, 21_000)]), GAS_LIMIT_STEP);
    assert_eq!(required_gas_limit([]), GAS_LIMIT_STEP);
}

#[test]
fn missing_code_aborts_instead_of_dropping_transactions() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/25698189-input.bin"
    ))
    .unwrap();
    let mut input = trace::decode_input(&bytes).unwrap();
    let index = input
        .witness
        .codes
        .iter()
        .enumerate()
        .max_by_key(|(_, code)| code.len())
        .unwrap()
        .0;
    input.witness.codes.remove(index);
    let error = execute(input.block, input.signers, &input.witness, true)
        .err()
        .expect("incomplete code witness must abort");
    let message = error.to_string();
    assert!(message.starts_with("tx #"), "{message}");
    assert!(message.contains("bytecode for"), "{message}");
}

#[test]
fn only_unresolved_nodes_are_droppable_panics() {
    for message in ["MPT: unresolved node access", "MPT: Unresolved node access"] {
        assert!(missing_witness_panic(panic_message(&message)));
        assert!(missing_witness_panic(panic_message(&message.to_string())));
    }
    for message in [
        "MPT: invalid witness node",
        "MPT: Value in branch",
        "overflow",
    ] {
        assert!(!missing_witness_panic(message));
    }
    assert!(!missing_witness_panic(panic_message(&42)));
}

#[test]
fn fidelity_counts_status_and_gas_independently() {
    let mut fidelity = Fidelity::default();
    fidelity.record((false, 30_000), (true, 21_000));
    fidelity.record((true, 21_000), (true, 21_000));
    assert_eq!(fidelity.status_changed, 1);
    assert_eq!(fidelity.gas_changed, 1);
    assert_eq!(fidelity.unchanged, 1);
}

#[test]
fn rlp_cap_uses_completed_header() {
    let transaction = |len| {
        TransactionSigned::from(
            TxLegacy {
                input: vec![0; len].into(),
                ..Default::default()
            }
            .into_signed(Signature::new(U256::from(1), U256::from(1), false)),
        )
    };
    let mut block = Block {
        header: synthetic_header(&first(), &parent(), 10_000_000, 1, 0, &[], &[]),
        body: alloy_consensus::BlockBody {
            transactions: vec![transaction(MAX_RLP_BLOCK_SIZE)],
            ..Default::default()
        },
    };
    let overhead = block.length() - MAX_RLP_BLOCK_SIZE;
    block.body.transactions = vec![transaction(MAX_RLP_BLOCK_SIZE - overhead)];
    assert_eq!(block.length(), MAX_RLP_BLOCK_SIZE);
    block.header.gas_limit = 321_000_000;
    block.header.gas_used = 90_000_000;
    assert!(block.length() > MAX_RLP_BLOCK_SIZE);
    let tx = block.body.transactions[0].clone();
    let mut cands = vec![Cand {
        hash: *tx.hash(),
        tx,
        signer: UncompressedPublicKey([0; 65]),
        sender: Address::ZERO,
        source: block.header.number,
        index: 0,
    }];
    let mut dropped = Vec::new();
    assert!(trim_rlp(&mut block, &mut cands, &mut dropped).unwrap());
    assert_eq!(dropped.len(), 1);
    assert!(cands.is_empty());
    assert!(block.body.transactions.is_empty());
    assert!(block.length() <= MAX_RLP_BLOCK_SIZE);
}

/// A tx reading a trie node no witness carries is dropped on its own: the
/// lenient pass records it, resumes on a fresh executor and finishes the
/// block; the strict pass aborts. Storage leaves (the short nodes) are tried
/// in witness order until one is read during execution rather than only by
/// the post-state root.
#[test]
fn unresolved_node_drops_only_the_reading_tx() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/25698189-input.bin"
    ))
    .unwrap();
    let input = trace::decode_input(&bytes).unwrap();
    let tx_count = input.block.body.transactions.len();
    let leaves: Vec<usize> = input
        .witness
        .state
        .iter()
        .enumerate()
        .filter(|(_, node)| node.len() < 80)
        .map(|(i, _)| i)
        .take(8)
        .collect();
    for index in leaves {
        let mut witness = input.witness.clone();
        witness.state.remove(index);
        let lenient = execute(input.block.clone(), input.signers.clone(), &witness, true);
        let Ok(executed) = lenient else {
            // Only the post-state root needed this node.
            continue;
        };
        if executed.failures.is_empty() {
            continue;
        }
        let first = executed.failures[0].0;
        assert!(
            executed.failures[0]
                .1
                .contains("state outside the witness union"),
            "{}",
            executed.failures[0].1
        );
        assert!(
            executed.failures.len() < tx_count - first,
            "execution did not resume after tx #{first}"
        );
        let strict = execute(input.block.clone(), input.signers.clone(), &witness, false)
            .err()
            .expect("strict execution must abort");
        assert!(
            strict
                .to_string()
                .starts_with(&format!("tx #{first} panicked")),
            "{strict}"
        );
        return;
    }
    panic!("no tried node was read during execution");
}
