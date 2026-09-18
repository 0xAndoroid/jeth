//! `jeth merge`: concatenate the transactions of N consecutive mainnet blocks
//! into one synthetic block, validate it natively, write it as a JEF input.bin
//! the UNCHANGED guest accepts (so cycle counts stay comparable).
//!
//! The synthetic block is block 1's header context (number, timestamp,
//! coinbase, prevrandao, parent beacon root, extra data) over the concatenated
//! txs and withdrawals of blocks 1..N, executed from block 1's pre-state.
//! Parent-dependent header rules are satisfied by rewriting the PARENT header
//! in the ancestor list ([`rewrite_parent`]); its hash changes, so the
//! synthetic `parent_hash` is the rewritten hash while the grandparent link and
//! the pre-state root (parent's `state_root`) stay untouched.
//!
//! # Why the witness union suffices
//!
//! The merged block runs against block 1's pre-state: every resolver miss is a
//! block-1-pre node (account trie, or a storage trie anchored at a block-1-pre
//! storage root); nodes created by earlier merged txs are in memory. Take a
//! block-1-pre node at trie prefix `P` that the merged execution resolves — a
//! node on the path of a key some block `k` accessed, or a branch-collapse
//! sibling of a deletion in block `k`. Let `j ≤ k` be the first block whose
//! execution touched a key under `P` (block `k` qualifies). Blocks `1..j-1`
//! left the subtree under `P` intact, so the block-1-pre node at `P` IS the
//! block-`j`-pre node at `P`, which block `j`'s own witness carries (its
//! pre-state walk visits `P`; geth records collapse siblings too). Hence the
//! node is in the union. The vendored trie reveals lazily from the pre-state
//! root and resolves stubs by digest, so the later-block versions of modified
//! nodes are simply never touched (they cost input bytes, not hashing — the
//! resolver keccaks an entry only on first resolve). The argument assumes the
//! merged execution replays the chain's write sequence; where a dropped or
//! outcome-changed tx breaks that, a missing node surfaces as a hard native
//! failure ("MPT: unresolved node access"), never as a silent divergence.
//!
//! Ancestor headers are the union of the sources' headers below block 1 (a
//! later block's BLOCKHASH window reaching below block 1 is contiguous with
//! block 1's parent); BLOCKHASH of a merged-away block returns 0 (number ≥
//! current), which is an accepted fidelity loss.

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
use anyhow::{anyhow, bail, ensure, Context, Result};
use jeth_core::{validation::WitnessDatabase, BlockInput, ExecutionWitness, UncompressedPublicKey};
use reth_chainspec::EthChainSpec;
use reth_ethereum_primitives::{Block, EthereumReceipt, TransactionSigned};
use reth_evm::{
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

    // 1. Decode. `decode_input` rejects any container whose library id differs
    //    from the embedded library, so all sources share one id by construction.
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

    // 2. Source fidelity baseline: per-tx (status, gas) from each block's own run.
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

    // 3. Concatenate txs + withdrawals + signers; union the witness.
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

    // 4. Header economics: min base fee / min excess blob gas over the sources,
    //    so no source tx becomes fee-invalid; the parent is rewritten to derive them.
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

    // 5. Static drops: blob gas cap (in order), then EIP-7934 RLP cap (trailing).
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
    loop {
        let (txs, _) = split_cands(&cands);
        let block = Block {
            header: first.clone(),
            body: alloy_consensus::BlockBody {
                transactions: txs,
                ommers: Vec::new(),
                withdrawals: Some(Withdrawals::new(withdrawals.clone())),
            },
        };
        if alloy_rlp::encode(&block).len() <= MAX_RLP_BLOCK_SIZE {
            break;
        }
        let cand = cands.pop().context("RLP cap leaves no transactions")?;
        poisoned.insert(cand.sender);
        dropped.push(Dropped {
            cand,
            reason: format!("EIP-7934 block RLP cap: {MAX_RLP_BLOCK_SIZE} bytes"),
        });
    }

    // 6. Execute → drop offenders (nonce cascade) → re-execute until clean and
    //    the gas limit is stable; the clean pass yields the header fields.
    let user_gas_limit = gas_limit_arg;
    let mut gas_limit = user_gas_limit.unwrap_or_else(|| provisional_gas_limit(&cands));
    let mut passes = 0usize;
    let (parent, rewrites, final_block, executed) = loop {
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
        let block = Block {
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
                        poisoned.insert(cand.sender);
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
        witness.headers = pass_witness.headers;
        break (parent, rewrites, block, executed);
    };

    // 7. Complete the header from the clean pass and write the container.
    let (receipts_root, logs_bloom) = receipts_root_bloom(&executed.receipts);
    let mut block = final_block;
    block.header.gas_used = executed.gas_used;
    block.header.receipts_root = receipts_root;
    block.header.logs_bloom = logs_bloom;
    block.header.requests_hash = Some(executed.requests_hash);
    block.header.blob_gas_used = Some(executed.blob_gas_used);
    block.header.state_root = executed.state_root;
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

    // 8. Fidelity + meta.
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
        if status != base_status {
            f.status_changed += 1;
        } else if gas != base_gas {
            f.gas_changed += 1;
        } else {
            f.unchanged += 1;
        }
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
    need.max(cumulative).div_ceil(GAS_LIMIT_STEP) * GAS_LIMIT_STEP
}

/// Host-side stateless execution without header-vs-outcome checks: same trie,
/// witness DB and block executor as the guest's validation loop, returning
/// what the header must be completed with.
///
/// `lenient` records per-tx executor errors (an erroring tx commits nothing),
/// skips later txs of the same sender (nonce cascade) and also survives a tx
/// that reads state outside the witness union: the resolver panics inside
/// core (guest contract), so the unwind is caught here, the tx is recorded as
/// dropped and a fresh EVM continues over the same `State` — the aborted tx
/// never reached `commit`, so the cache and transitions are untouched.
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
            panic_message(&payload)
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
            Ok(Err(e)) if lenient => {
                poisoned.insert(sender);
                failures.push((i, e.to_string()));
            }
            Ok(Err(e)) => bail!("tx #{i} failed: {e}"),
            Err(payload) => {
                let message = panic_message(&payload);
                ensure!(lenient, "tx #{i} panicked: {message}");
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

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic".into())
}

/// Expected resolver panics ("MPT: unresolved node access") are caught per tx;
/// keep them off stderr, forward anything else to the default hook.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_default();
        if !message.starts_with("MPT:") {
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
mod tests {
    use super::*;
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

            let header =
                synthetic_header(&first(), &rewritten, gas_limit, base_fee, excess, &[], &[]);
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
        assert_eq!(required_gas_limit([]), 0);
    }

    // Integration test (merge two fixture blocks + run-native): skipped —
    // fixtures/ ships a single block (25698189); a consecutive pair with
    // matching library id is needed. Covered by the N=2..10 inputs under
    // /Volumes/Dev/jeth-inputs/merged instead.
}
