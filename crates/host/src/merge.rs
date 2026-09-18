//! Merge consecutive mainnet blocks for gas-limit measurements with the unchanged guest.
//!
//! Block 1 supplies the execution context and pre-state; transactions and
//! withdrawals retain source order. [`rewrite_parent`] changes the parent hash
//! and header economics but preserves its state root and grandparent link.
//!
//! Witness nodes resolve by digest against that pre-state. Extra later-state
//! nodes are harmless; their presence does not replace nodes anchored by the
//! root. Coverage is not guaranteed after execution diverges: per-tx unresolved
//! accesses cause recorded drops, while post-root misses abort the merge.
//! Both native validation paths must accept the completed input.
//!
//! Ancestors form a contiguous chain below block 1. BLOCKHASH(parent) returns
//! the rewritten hash; merged-away block numbers are current/future and return 0.
//!
//! Nonce cascades track transaction senders, not EIP-7702 authorities. Changed
//! authorization nonces are handled by re-execution; valid authorizations may
//! be skipped by the EVM, so a valid merge does not imply authorization fidelity.

use crate::trace;
use alloy_consensus::{
    proofs::{calculate_receipt_root, calculate_transaction_root, calculate_withdrawals_root},
    Header, Transaction as _, TxReceipt, EMPTY_OMMER_ROOT_HASH,
};
use alloy_eips::{
    eip1559::{calc_next_block_base_fee, BaseFeeParams},
    eip4844::DATA_GAS_PER_BLOB,
    eip4895::Withdrawals,
    eip7825::MAX_TX_GAS_LIMIT_OSAKA,
    eip7840::BlobParams,
};
use alloy_primitives::{keccak256, Address, Bloom, Bytes, B256, B64, U256};
use alloy_rlp::Encodable;
use anyhow::{anyhow, bail, ensure, Context, Result};
use jeth_core::{validation::WitnessDatabase, BlockInput, ExecutionWitness, UncompressedPublicKey};
use reth_chainspec::EthChainSpec;
use reth_ethereum_primitives::{Block, EthereumReceipt, TransactionSigned};
use reth_evm::{
    block::{BlockExecutionError, BlockValidationError},
    execute::BlockExecutor,
    revm::database::{states::bundle_state::BundleRetention, State},
    ConfigureEvm,
};
use reth_primitives_traits::{Recovered, RecoveredBlock};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::Arc;
use tries::StatelessTrie;

/// EIP-7934 block RLP cap (`reth_consensus_common::validation::MAX_RLP_BLOCK_SIZE`).
const MAX_RLP_BLOCK_SIZE: usize = 8_388_608;
/// BLOCKHASH ancestor window enforced by the stateless validator.
const ANCESTOR_LIMIT: usize = 256;
/// Default gas-limit rounding granularity.
const GAS_LIMIT_STEP: u64 = 1_000_000;
const MAX_PASSES: usize = 8;

struct Source {
    path: String,
    input_bytes: usize,
    block: Block,
    signers: Vec<UncompressedPublicKey>,
    witness: ExecutionWitness,
}

/// A candidate transaction of the merged block.
#[derive(Clone)]
struct Cand {
    tx: TransactionSigned,
    signer: UncompressedPublicKey,
    sender: Address,
    hash: B256,
    source: u64,
    index: usize,
}

struct Dropped {
    cand: Cand,
    reason: String,
}

/// Native execution result. `failures` lists `(tx index, reason)` for txs the
/// executor rejected or that read outside the witness union; the consensus
/// outputs are only meaningful when it is empty (a failing pass is re-run).
struct Executed {
    failures: Vec<(usize, String)>,
    receipts: Vec<EthereumReceipt>,
    gas_used: u64,
    blob_gas_used: u64,
    requests_hash: B256,
    state_root: B256,
}

pub fn run(inputs: &[String], out: &str, gas_limit_arg: Option<u64>, library: &str) -> Result<()> {
    ensure!(inputs.len() >= 2, "--inputs needs at least two blocks");
    install_panic_hook();
    let chain_spec = jeth_core::mainnet_spec();

    let mut sources = Vec::with_capacity(inputs.len());
    for path in inputs {
        let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
        let BlockInput {
            block,
            signers,
            witness,
        } = trace::decode_input(&bytes).with_context(|| format!("decoding {path}"))?;
        println!(
            "source {}: {} txs, {} gas, base fee {}, excess blob gas {}, {} state nodes, {} codes, {} headers",
            block.header.number,
            block.body.transactions.len(),
            block.header.gas_used,
            block.header.base_fee_per_gas.unwrap_or(0),
            block.header.excess_blob_gas.unwrap_or(0),
            witness.state.len(),
            witness.codes.len(),
            witness.headers.len(),
        );
        sources.push(Source {
            path: path.clone(),
            input_bytes: bytes.len(),
            block,
            signers,
            witness,
        });
    }
    for pair in sources.windows(2) {
        let (a, b) = (&pair[0].block.header, &pair[1].block.header);
        ensure!(
            b.number == a.number + 1 && b.parent_hash == a.hash_slow(),
            "blocks {} and {} are not consecutive",
            a.number,
            b.number
        );
    }
    let first = sources[0].block.header.clone();
    let blob_params = chain_spec
        .blob_params_at_timestamp(first.timestamp)
        .context("blob params at block 1 timestamp")?;

    let mut baseline: BTreeMap<B256, (bool, u64)> = BTreeMap::new();
    for source in &sources {
        let executed = execute(
            source.block.clone(),
            source.signers.clone(),
            &source.witness,
            false,
        )
        .with_context(|| format!("native run of source block {}", source.block.header.number))?;
        ensure!(
            executed.state_root == source.block.header.state_root
                && executed.gas_used == source.block.header.gas_used,
            "source block {} does not reproduce its header",
            source.block.header.number
        );
        for (tx, outcome) in source
            .block
            .body
            .transactions
            .iter()
            .zip(per_tx_outcomes(&executed.receipts))
        {
            baseline.insert(*tx.hash(), outcome);
        }
    }

    let mut cands = Vec::new();
    let mut withdrawals = Vec::new();
    for source in &sources {
        let number = source.block.header.number;
        for (index, (tx, signer)) in source
            .block
            .body
            .transactions
            .iter()
            .zip(&source.signers)
            .enumerate()
        {
            cands.push(Cand {
                tx: tx.clone(),
                signer: signer.clone(),
                sender: Address::from_raw_public_key(&signer.0[1..]),
                hash: *tx.hash(),
                source: number,
                index,
            });
        }
        withdrawals.extend(source.block.body.withdrawals.iter().flatten().cloned());
    }
    let (mut witness, witness_stats) = union_witness(&sources);
    let (library_id, _) = crate::library::filter_witness(&mut witness, library)?;
    ensure!(
        u64::from_le_bytes(library_id[..8].try_into().unwrap())
            == jeth_core::code_library::LIBRARY_ID_LO,
        "library manifest {library} does not match the embedded code library"
    );

    // Lower fees preserve affordability; the executor still checks both fee caps.
    let base_fee = sources
        .iter()
        .map(|s| s.block.header.base_fee_per_gas.unwrap_or(0))
        .min()
        .unwrap();
    let excess_target = sources
        .iter()
        .map(|s| s.block.header.excess_blob_gas.unwrap_or(0))
        .min()
        .unwrap();
    let (ancestors, original_parent) = union_ancestors(&sources)?;

    // Blob gas is bounded by block 1's schedule, including across a BPO boundary.
    let mut dropped = Vec::new();
    let mut poisoned = HashSet::new();
    let max_blob_gas = blob_params.max_blob_gas_per_block();
    let mut blob_gas = 0u64;
    let mut kept = Vec::with_capacity(cands.len());
    for cand in cands {
        let tx_blob_gas = cand.tx.blob_gas_used().unwrap_or(0);
        if poisoned.contains(&cand.sender) {
            dropped.push(Dropped {
                cand,
                reason: "nonce cascade: an earlier tx of this sender was dropped".into(),
            });
        } else if blob_gas + tx_blob_gas > max_blob_gas {
            poisoned.insert(cand.sender);
            dropped.push(Dropped {
                cand,
                reason: format!("blob gas cap: {max_blob_gas} per block at this timestamp"),
            });
        } else {
            blob_gas += tx_blob_gas;
            kept.push(cand);
        }
    }
    let mut cands = kept;

    let user_gas_limit = gas_limit_arg;
    let mut gas_limit = user_gas_limit.unwrap_or_else(|| provisional_gas_limit(&cands));
    let mut passes = 0usize;
    let (parent, rewrites, block, executed) = loop {
        passes += 1;
        ensure!(
            passes <= MAX_PASSES,
            "merge did not converge in {MAX_PASSES} passes"
        );
        let (parent, rewrites) = rewrite_parent(
            &original_parent,
            gas_limit,
            base_fee,
            excess_target,
            blob_params,
        );
        let excess_blob_gas = blob_params.next_block_excess_blob_gas_osaka(
            parent.excess_blob_gas.unwrap_or(0),
            parent.blob_gas_used.unwrap_or(0),
            parent.base_fee_per_gas.unwrap_or(0),
        );
        let (txs, signers) = split_cands(&cands);
        let header = synthetic_header(
            &first,
            &parent,
            gas_limit,
            base_fee,
            excess_blob_gas,
            &txs,
            &withdrawals,
        );
        let mut block = Block {
            header,
            body: alloy_consensus::BlockBody {
                transactions: txs,
                ommers: Vec::new(),
                withdrawals: Some(Withdrawals::new(withdrawals.clone())),
            },
        };
        let mut pass_witness = witness.clone();
        pass_witness.headers = ancestor_records(&ancestors, &parent);
        println!(
            "pass {passes}: {} txs, gas limit {gas_limit}, base fee {base_fee}, excess blob gas {excess_blob_gas}",
            cands.len()
        );
        let executed = execute(block.clone(), signers, &pass_witness, true)?;

        if !executed.failures.is_empty() {
            let failed: BTreeMap<usize, String> = executed.failures.into_iter().collect();
            let mut kept = Vec::with_capacity(cands.len());
            for (i, cand) in cands.into_iter().enumerate() {
                match failed.get(&i) {
                    Some(reason) => {
                        dropped.push(Dropped {
                            cand,
                            reason: reason.clone(),
                        });
                    }
                    None => kept.push(cand),
                }
            }
            cands = kept;
            println!("  dropped {} txs, re-running", failed.len());
            continue;
        }
        if user_gas_limit.is_none() {
            let required =
                required_gas_limit(cands.iter().zip(&executed.receipts).map(|(cand, receipt)| {
                    (capped_gas_limit(&cand.tx), receipt.cumulative_gas_used)
                }));
            if required != gas_limit {
                println!("  gas limit {gas_limit} → {required}, re-running");
                gas_limit = required;
                continue;
            }
        }
        let (receipts_root, logs_bloom) = receipts_root_bloom(&executed.receipts);
        block.header.gas_used = executed.gas_used;
        block.header.receipts_root = receipts_root;
        block.header.logs_bloom = logs_bloom;
        block.header.requests_hash = Some(executed.requests_hash);
        block.header.blob_gas_used = Some(executed.blob_gas_used);
        block.header.state_root = executed.state_root;
        if trim_rlp(&mut block, &mut cands, &mut dropped)? {
            continue;
        }
        witness.headers = pass_witness.headers;
        break (parent, rewrites, block, executed);
    };

    let block_rlp = alloy_rlp::encode(&block);
    let (_, signers) = split_cands(&cands);
    let input_bytes = jeth_core::container::ContainerWriter::write(
        &block_rlp,
        &signers,
        &witness,
        trace::stream_start(trace::Variant::Input),
        jeth_core::code_library::LIBRARY_ID_LO,
    )
    .map_err(anyhow::Error::msg)?;
    let dir = Path::new(out);
    std::fs::create_dir_all(dir)?;
    let input_path = dir.join("input.bin");
    std::fs::write(&input_path, &input_bytes)?;
    println!(
        "wrote {} ({:.1} MB); verifying with run-native",
        input_path.display(),
        input_bytes.len() as f64 / 1e6
    );
    crate::run_native(&input_path.to_string_lossy()).context("merged input failed run-native")?;
    // Default run-native uses upstream stateless; exercise the guest's vendored loop too.
    let input = trace::decode_input(&input_bytes)?;
    jeth_core::recover_block(input.block, input.signers)
        .and_then(|block| jeth_core::validate_recovered(block, input.witness))
        .map_err(|e| anyhow!("merged input failed guest validation: {e}"))?;

    let mut fidelity: BTreeMap<u64, Fidelity> = sources
        .iter()
        .map(|s| {
            (
                s.block.header.number,
                Fidelity {
                    txs: s.block.body.transactions.len(),
                    ..Default::default()
                },
            )
        })
        .collect();
    for d in &dropped {
        fidelity.get_mut(&d.cand.source).unwrap().dropped += 1;
    }
    for (cand, (status, gas)) in cands.iter().zip(per_tx_outcomes(&executed.receipts)) {
        let (base_status, base_gas) = baseline[&cand.hash];
        let f = fidelity.get_mut(&cand.source).unwrap();
        f.record((status, gas), (base_status, base_gas));
    }
    println!("fidelity (per source block):");
    println!("  block      txs  kept  dropped  status_changed  gas_changed");
    for (number, f) in &fidelity {
        println!(
            "  {number}  {:>4}  {:>4}  {:>7}  {:>14}  {:>11}",
            f.txs,
            f.txs - f.dropped,
            f.dropped,
            f.status_changed,
            f.gas_changed
        );
    }

    let meta = json!({
        "format": 1,
        "sources": sources.iter().map(|s| json!({
            "block": s.block.header.number,
            "path": s.path,
            "input_bin_bytes": s.input_bytes,
            "txs": s.block.body.transactions.len(),
            "gas_used": s.block.header.gas_used,
            "gas_limit": s.block.header.gas_limit,
            "base_fee_per_gas": s.block.header.base_fee_per_gas,
            "excess_blob_gas": s.block.header.excess_blob_gas,
            "blob_gas_used": s.block.header.blob_gas_used,
            "withdrawals": s.block.body.withdrawals.as_ref().map(|w| w.len()),
        })).collect::<Vec<_>>(),
        "tx_count": cands.len(),
        "gas_used_total": block.header.gas_used,
        "gas_limit": block.header.gas_limit,
        "gas_limit_rule": if user_gas_limit.is_some() { "--gas-limit" } else {
            "next 1M above max over txs of (cumulative gas before tx + min(tx gas limit, EIP-7825 cap))"
        },
        "base_fee": base_fee,
        "blob_gas_used": block.header.blob_gas_used,
        "excess_blob_gas": block.header.excess_blob_gas,
        "excess_blob_gas_target": excess_target,
        "withdrawals": withdrawals.len(),
        "passes": passes,
        "header": header_json(&block.header),
        "block_hash": block.header.hash_slow(),
        "parent": {
            "original_hash": original_parent.hash_slow(),
            "rewritten_hash": parent.hash_slow(),
            "rewrites": rewrites,
        },
        "ancestor_headers": {
            "count": witness.headers.len(),
            "lowest": ancestors.first().map(|(n, _)| n),
            "highest": ancestors.last().map(|(n, _)| n),
        },
        "dropped_txs": dropped.iter().map(|d| json!({
            "hash": d.cand.hash,
            "source_block": d.cand.source,
            "index_in_source": d.cand.index,
            "sender": d.cand.sender,
            "reason": d.reason,
        })).collect::<Vec<_>>(),
        "fidelity": fidelity.iter().map(|(n, f)| (n.to_string(), json!({
            "txs": f.txs,
            "kept": f.txs - f.dropped,
            "dropped": f.dropped,
            "status_changed": f.status_changed,
            "gas_changed": f.gas_changed,
            "unchanged": f.unchanged,
        }))).collect::<serde_json::Map<_, _>>(),
        "block_rlp_bytes": block_rlp.len(),
        "input_bin_bytes": input_bytes.len(),
        "witness": witness_stats_json(&witness, &witness_stats),
    });
    std::fs::write(
        dir.join("merge-meta.json"),
        serde_json::to_string_pretty(&meta)?,
    )?;
    println!(
        "merged {} blocks → block {}: {} txs, {} gas (limit {}), {} dropped, {:.1} MB input.bin, {} passes",
        sources.len(),
        block.header.number,
        cands.len(),
        block.header.gas_used,
        block.header.gas_limit,
        dropped.len(),
        input_bytes.len() as f64 / 1e6,
        passes,
    );
    Ok(())
}

#[derive(Default)]
struct Fidelity {
    txs: usize,
    dropped: usize,
    status_changed: usize,
    gas_changed: usize,
    unchanged: usize,
}

impl Fidelity {
    fn record(&mut self, outcome: (bool, u64), baseline: (bool, u64)) {
        self.status_changed += usize::from(outcome.0 != baseline.0);
        self.gas_changed += usize::from(outcome.1 != baseline.1);
        self.unchanged += usize::from(outcome == baseline);
    }
}

/// Completed numeric header fields can be wider than block 1's fields.
/// A trimmed body must execute again before its header can be written.
fn trim_rlp(block: &mut Block, cands: &mut Vec<Cand>, dropped: &mut Vec<Dropped>) -> Result<bool> {
    let before = cands.len();
    while block.length() > MAX_RLP_BLOCK_SIZE {
        let cand = cands.pop().context("RLP cap leaves no transactions")?;
        block.body.transactions.pop();
        dropped.push(Dropped {
            cand,
            reason: format!("EIP-7934 block RLP cap: {MAX_RLP_BLOCK_SIZE} bytes"),
        });
    }
    Ok(cands.len() != before)
}

fn split_cands(cands: &[Cand]) -> (Vec<TransactionSigned>, Vec<UncompressedPublicKey>) {
    (
        cands.iter().map(|c| c.tx.clone()).collect(),
        cands.iter().map(|c| c.signer.clone()).collect(),
    )
}

/// Per-tx `(status, gas)` from receipts (cumulative gas differences).
fn per_tx_outcomes(receipts: &[EthereumReceipt]) -> Vec<(bool, u64)> {
    let mut previous = 0u64;
    receipts
        .iter()
        .map(|r| {
            let gas = r.cumulative_gas_used - previous;
            previous = r.cumulative_gas_used;
            (r.success, gas)
        })
        .collect()
}

struct UnionStats {
    state_before: usize,
    codes_before: usize,
}

/// State nodes and codes of all sources, deduplicated by keccak (first-seen
/// order — deterministic, so the advice slot indices are pass-stable).
fn union_witness(sources: &[Source]) -> (ExecutionWitness, UnionStats) {
    let mut seen = BTreeSet::new();
    let mut witness = ExecutionWitness::default();
    let mut stats = UnionStats {
        state_before: 0,
        codes_before: 0,
    };
    for source in sources {
        stats.state_before += source.witness.state.len();
        stats.codes_before += source.witness.codes.len();
        for node in &source.witness.state {
            if seen.insert(keccak256(node)) {
                witness.state.push(node.clone());
            }
        }
    }
    seen.clear();
    for source in sources {
        for code in &source.witness.codes {
            if seen.insert(keccak256(code)) {
                witness.codes.push(code.clone());
            }
        }
    }
    (witness, stats)
}

/// Ancestor headers below block 1 from every source, contiguous from block 1's
/// parent downwards (truncated at the first gap, capped at the BLOCKHASH
/// window). Returns `(number, rlp)` ascending plus the decoded original parent.
fn union_ancestors(sources: &[Source]) -> Result<(Vec<(u64, Bytes)>, Header)> {
    let first = sources[0].block.header.number;
    let mut by_number: BTreeMap<u64, Bytes> = BTreeMap::new();
    for source in sources {
        for bytes in &source.witness.headers {
            let header: Header = alloy_rlp::decode_exact(bytes.as_ref())
                .map_err(|e| anyhow!("ancestor header RLP: {e}"))?;
            if header.number >= first {
                continue;
            }
            if let Some(existing) = by_number.insert(header.number, bytes.clone()) {
                ensure!(
                    existing == *bytes,
                    "conflicting header for {}",
                    header.number
                );
            }
        }
    }
    let parent_bytes = by_number
        .get(&(first - 1))
        .context("block 1's witness carries no parent header")?
        .clone();
    let parent: Header = alloy_rlp::decode_exact(parent_bytes.as_ref()).unwrap();
    let mut chain = vec![(first - 1, parent_bytes)];
    let mut child = parent.clone();
    while chain.len() < ANCESTOR_LIMIT {
        let Some(bytes) = by_number.get(&(child.number.wrapping_sub(1))) else {
            break;
        };
        if keccak256(bytes) != child.parent_hash {
            break;
        }
        child = alloy_rlp::decode_exact(bytes.as_ref()).unwrap();
        chain.push((child.number, bytes.clone()));
    }
    chain.reverse();
    Ok((chain, parent))
}

/// Ancestor records for the witness: the union chain with the parent replaced
/// by its rewritten form.
fn ancestor_records(ancestors: &[(u64, Bytes)], parent: &Header) -> Vec<Bytes> {
    let mut records: Vec<Bytes> = ancestors.iter().map(|(_, b)| b.clone()).collect();
    *records.last_mut().unwrap() = Bytes::from(alloy_rlp::encode(parent));
    records
}

/// Rewrite the parent so the synthetic header passes every parent-dependent
/// rule the guest checks without touching it:
/// - `gas_limit` = synthetic gas limit (1/1024 ramp rule),
/// - `gas_used` = gas target and `base_fee_per_gas` = chosen base fee (EIP-1559
///   derivation returns the parent's fee unchanged),
/// - `excess_blob_gas`/`blob_gas_used` solved so the EIP-7918 derivation yields
///   the chosen excess (original values kept when no solution exists).
///
/// Everything else — notably `state_root` (the pre-state root) and
/// `parent_hash` (the grandparent link) — is untouched. Returns the rewritten
/// header and one `{field, original, rewritten}` record per changed field.
fn rewrite_parent(
    original: &Header,
    gas_limit: u64,
    base_fee: u64,
    excess_target: u64,
    blob_params: BlobParams,
) -> (Header, Vec<Value>) {
    let params = BaseFeeParams::ethereum();
    let mut parent = original.clone();
    parent.gas_limit = gas_limit;
    parent.gas_used = gas_limit / params.elasticity_multiplier as u64;
    parent.base_fee_per_gas = Some(base_fee);
    debug_assert_eq!(
        calc_next_block_base_fee(parent.gas_used, parent.gas_limit, base_fee, params),
        base_fee
    );
    if let Some((excess, used)) = solve_blob_fields(blob_params, excess_target, base_fee) {
        parent.excess_blob_gas = Some(excess);
        parent.blob_gas_used = Some(used);
    }

    let mut rewrites = Vec::new();
    let mut record = |field: &str, before: Option<u64>, after: Option<u64>| {
        if before != after {
            rewrites.push(json!({ "field": field, "original": before, "rewritten": after }));
        }
    };
    record(
        "gas_limit",
        Some(original.gas_limit),
        Some(parent.gas_limit),
    );
    record("gas_used", Some(original.gas_used), Some(parent.gas_used));
    record(
        "base_fee_per_gas",
        original.base_fee_per_gas,
        parent.base_fee_per_gas,
    );
    record(
        "excess_blob_gas",
        original.excess_blob_gas,
        parent.excess_blob_gas,
    );
    record(
        "blob_gas_used",
        original.blob_gas_used,
        parent.blob_gas_used,
    );
    (parent, rewrites)
}

/// Parent `(excess_blob_gas, blob_gas_used)` whose EIP-7918 derivation (at the
/// rewritten parent base fee) equals `target`; small candidate search since the
/// reserve-price branch makes the map non-monotonic.
fn solve_blob_fields(blob_params: BlobParams, target: u64, base_fee: u64) -> Option<(u64, u64)> {
    let target_gas = blob_params.target_blob_gas_per_block();
    let excess_candidates = [
        target,
        target + target_gas,
        target.saturating_sub(target_gas),
        0,
    ];
    for excess in excess_candidates {
        for blobs in 0..=blob_params.max_blob_count {
            let used = blobs * DATA_GAS_PER_BLOB;
            if blob_params.next_block_excess_blob_gas_osaka(excess, used, base_fee) == target {
                return Some((excess, used));
            }
        }
    }
    None
}

/// Block 1's context over the merged body; execution-dependent fields
/// (`gas_used`, `receipts_root`, `logs_bloom`, `requests_hash`,
/// `blob_gas_used`, `state_root`) are zero placeholders until the clean pass.
fn synthetic_header(
    first: &Header,
    parent: &Header,
    gas_limit: u64,
    base_fee: u64,
    excess_blob_gas: u64,
    txs: &[TransactionSigned],
    withdrawals: &[alloy_eips::eip4895::Withdrawal],
) -> Header {
    Header {
        parent_hash: parent.hash_slow(),
        ommers_hash: EMPTY_OMMER_ROOT_HASH,
        beneficiary: first.beneficiary,
        state_root: B256::ZERO,
        transactions_root: calculate_transaction_root(txs),
        receipts_root: B256::ZERO,
        logs_bloom: Bloom::ZERO,
        difficulty: U256::ZERO,
        number: first.number,
        gas_limit,
        gas_used: 0,
        timestamp: first.timestamp,
        extra_data: first.extra_data.clone(),
        mix_hash: first.mix_hash,
        nonce: B64::ZERO,
        base_fee_per_gas: Some(base_fee),
        withdrawals_root: Some(calculate_withdrawals_root(withdrawals)),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(excess_blob_gas),
        parent_beacon_block_root: first.parent_beacon_block_root,
        requests_hash: Some(B256::ZERO),
        block_access_list_hash: None,
        slot_number: None,
    }
}

fn capped_gas_limit(tx: &TransactionSigned) -> u64 {
    tx.gas_limit().min(MAX_TX_GAS_LIMIT_OSAKA)
}

/// First-pass gas limit: nothing is rejected for block gas, so the pass
/// exposes every other invalidity at once.
fn provisional_gas_limit(cands: &[Cand]) -> u64 {
    cands
        .iter()
        .map(|c| capped_gas_limit(&c.tx))
        .sum::<u64>()
        .max(GAS_LIMIT_STEP)
}

/// Smallest gas limit (rounded up to 1M) under which the executor admits every
/// kept tx: each tx needs `cumulative gas before it + min(gas limit, EIP-7825
/// cap)` of block space, which is ≥ the block's total gas used. Items are
/// `(capped tx gas limit, cumulative gas used after the tx)`.
fn required_gas_limit(txs: impl IntoIterator<Item = (u64, u64)>) -> u64 {
    let mut cumulative = 0u64;
    let mut need = 0u64;
    for (gas_limit, cumulative_after) in txs {
        need = need.max(cumulative + gas_limit);
        cumulative = cumulative_after;
    }
    need.max(cumulative)
        .max(GAS_LIMIT_STEP)
        .div_ceil(GAS_LIMIT_STEP)
        * GAS_LIMIT_STEP
}

/// Host-side stateless execution without header-vs-outcome checks: same trie,
/// witness DB and block executor as the guest's validation loop, returning
/// what the header must be completed with.
///
/// `lenient` records invalid transactions (an erroring tx commits nothing),
/// skips later txs of the same sender (nonce cascade) and also survives a tx
/// that reads state outside the witness union: the resolver panics inside
/// core (guest contract), so the unwind is caught here, the tx is recorded as
/// dropped and a fresh EVM continues over the same `State` — the aborted tx
/// never reached `commit`. Read caches may grow; committed transitions are unchanged.
fn execute(
    block: Block,
    signers: Vec<UncompressedPublicKey>,
    witness: &ExecutionWitness,
    lenient: bool,
) -> Result<Executed> {
    let recovered =
        jeth_core::recover_block(block, signers).map_err(|e| anyhow!("signer recovery: {e}"))?;
    let mut ancestor_hashes = BTreeMap::new();
    let mut parent_state_root = None;
    for bytes in &witness.headers {
        let header: Header = alloy_rlp::decode_exact(bytes.as_ref())
            .map_err(|e| anyhow!("ancestor header RLP: {e}"))?;
        let hash = keccak256(bytes);
        if header.number + 1 == recovered.number {
            ensure!(
                hash == recovered.parent_hash,
                "parent header hash does not match the block's parent_hash"
            );
            parent_state_root = Some(header.state_root);
        }
        ancestor_hashes.insert(header.number, hash);
    }
    let parent_state_root = parent_state_root.context("witness has no parent header")?;

    let chain_spec = Arc::new(jeth_core::mainnet_spec());
    let evm_config = jeth_core::EthEvmConfig::new(chain_spec);
    let (mut trie, codes) = jeth_core::Trie::new_with_codes(witness, parent_state_root)
        .map_err(|e| anyhow!("witness reveal failed: {e:?}"))?;
    let db = WitnessDatabase::new(&trie, codes, ancestor_hashes);
    let mut state = State::builder()
        .with_database(db)
        .with_bundle_update()
        .build();

    let mut failures = Vec::new();
    let mut poisoned: HashSet<Address> = HashSet::new();
    let mut start = 0;
    let result = loop {
        match run_segment(
            &evm_config,
            &mut state,
            &recovered,
            start,
            &mut failures,
            &mut poisoned,
            lenient,
        )? {
            Segment::Finished(result) => break result,
            Segment::Aborted { resume_at } => start = resume_at,
        }
    };
    if !failures.is_empty() {
        // Re-run after the drops; the post-state root of this pass is moot.
        return Ok(Executed {
            failures,
            receipts: Vec::new(),
            gas_used: 0,
            blob_gas_used: 0,
            requests_hash: B256::ZERO,
            state_root: B256::ZERO,
        });
    }
    state.merge_transitions(BundleRetention::Reverts);
    let bundle = state.take_bundle();
    drop(state);

    let hashed = trie.hashed_post_state(&bundle.state);
    let state_root = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        trie.calculate_state_root(hashed)
    }))
    .map_err(|payload| {
        anyhow!(
            "post-state root needs nodes outside the witness union ({}); \
             the responsible tx cannot be attributed — narrow the block set",
            panic_message(payload.as_ref())
        )
    })?
    .map_err(|e| anyhow!("state root: {e:?}"))?;
    Ok(Executed {
        failures,
        receipts: result.receipts,
        gas_used: result.gas_used,
        blob_gas_used: result.blob_gas_used,
        requests_hash: result.requests.requests_hash(),
        state_root,
    })
}

enum Segment {
    Finished(reth_evm::block::BlockExecutionResult<EthereumReceipt>),
    /// A tx panicked inside the resolver (state outside the witness union);
    /// the executor is gone, resume from `resume_at` with a fresh one.
    Aborted {
        resume_at: usize,
    },
}

/// Execute txs `start..` on a fresh block executor over `state`. Only the
/// first segment applies the pre-execution system calls; only the segment
/// that reaches the end applies the post-execution changes. A pass with an
/// aborted segment loses that executor's receipts, which is fine: it has
/// failures and is re-run after the drops.
fn run_segment(
    evm_config: &jeth_core::EthEvmConfig,
    state: &mut State<WitnessDatabase<'_, jeth_core::Trie>>,
    recovered: &RecoveredBlock<Block>,
    start: usize,
    failures: &mut Vec<(usize, String)>,
    poisoned: &mut HashSet<Address>,
    lenient: bool,
) -> Result<Segment> {
    let mut executor = evm_config
        .executor_for_block(state, recovered.sealed_block())
        .map_err(|e| anyhow!("executor: {e}"))?;
    if start == 0 {
        executor
            .apply_pre_execution_changes()
            .map_err(|e| anyhow!("pre-execution changes: {e}"))?;
    }
    let senders = recovered.senders();
    let txs = &recovered.body().transactions;
    for i in start..txs.len() {
        let sender = senders[i];
        if poisoned.contains(&sender) {
            failures.push((
                i,
                "nonce cascade: an earlier tx of this sender was dropped".into(),
            ));
            continue;
        }
        let tx = Recovered::new_unchecked(&txs[i], sender);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            executor.execute_transaction(tx)
        }));
        match outcome {
            Ok(Ok(_)) => {}
            Ok(Err(e))
                if lenient
                    && matches!(
                        e,
                        BlockExecutionError::Validation(
                            BlockValidationError::InvalidTx { .. }
                                | BlockValidationError::TransactionGasLimitMoreThanAvailableBlockGas { .. }
                        )
                    ) =>
            {
                poisoned.insert(sender);
                failures.push((i, e.to_string()));
            }
            Ok(Err(e)) => bail!("tx #{i} failed: {e}"),
            Err(payload) => {
                let message = panic_message(payload.as_ref());
                ensure!(
                    lenient && missing_witness_panic(message),
                    "tx #{i} panicked: {message}"
                );
                poisoned.insert(sender);
                failures.push((
                    i,
                    format!("state outside the witness union (block-context-dependent divergence): {message}"),
                ));
                return Ok(Segment::Aborted { resume_at: i + 1 });
            }
        }
    }
    let result = executor
        .apply_post_execution_changes()
        .map_err(|e| anyhow!("post-execution changes: {e}"))?;
    Ok(Segment::Finished(result))
}

fn panic_message(payload: &(dyn std::any::Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("non-string panic")
}

fn missing_witness_panic(message: &str) -> bool {
    matches!(
        message,
        "MPT: unresolved node access" | "MPT: Unresolved node access"
    )
}

/// Expected resolver panics ("MPT: unresolved node access") are caught per tx;
/// keep them off stderr, forward anything else to the default hook.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if !missing_witness_panic(panic_message(info.payload())) {
            default_hook(info);
        }
    }));
}

fn receipts_root_bloom(receipts: &[EthereumReceipt]) -> (B256, Bloom) {
    let with_bloom: Vec<_> = receipts.iter().map(TxReceipt::with_bloom_ref).collect();
    let root = calculate_receipt_root(&with_bloom);
    let bloom = with_bloom
        .iter()
        .fold(Bloom::ZERO, |bloom, r| bloom | r.logs_bloom);
    (root, bloom)
}

fn header_json(header: &Header) -> Value {
    json!({
        "parent_hash": header.parent_hash,
        "beneficiary": header.beneficiary,
        "state_root": header.state_root,
        "transactions_root": header.transactions_root,
        "receipts_root": header.receipts_root,
        "number": header.number,
        "gas_limit": header.gas_limit,
        "gas_used": header.gas_used,
        "timestamp": header.timestamp,
        "extra_data": header.extra_data,
        "mix_hash": header.mix_hash,
        "base_fee_per_gas": header.base_fee_per_gas,
        "withdrawals_root": header.withdrawals_root,
        "blob_gas_used": header.blob_gas_used,
        "excess_blob_gas": header.excess_blob_gas,
        "parent_beacon_block_root": header.parent_beacon_block_root,
        "requests_hash": header.requests_hash,
    })
}

fn witness_stats_json(witness: &ExecutionWitness, stats: &UnionStats) -> Value {
    json!({
        "state_nodes": witness.state.len(),
        "state_nodes_before_dedup": stats.state_before,
        "state_bytes": witness.state.iter().map(|b| b.len()).sum::<usize>(),
        "codes": witness.codes.len(),
        "codes_before_dedup": stats.codes_before,
        "code_bytes": witness.codes.iter().map(|b| b.len()).sum::<usize>(),
        "headers": witness.headers.len(),
    })
}

#[cfg(test)]
mod tests;
