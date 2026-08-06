//! `jeth fetch`: block RLP + execution witness + recovered pubkeys → postcard input.bin.

use crate::rpc::{parse_hex_bytes, parse_quantity, RpcClient, DEFAULT_ENDPOINTS};
use anyhow::{Context, Result};
use jeth_core::{BlockInput, ExecutionWitness, UncompressedPublicKey};
use reth_ethereum_primitives::{Block, TransactionSigned};
use serde_json::{json, Value};

/// Fetch block + witness + pubkeys; returns the path to the written input.bin.
pub fn run(
    block: Option<u64>,
    latest_minus: u64,
    rpc_list: Option<Vec<String>>,
    out_root: &str,
) -> Result<std::path::PathBuf> {
    let endpoints =
        rpc_list.unwrap_or_else(|| DEFAULT_ENDPOINTS.iter().map(|s| s.to_string()).collect());
    let client = RpcClient::new(endpoints);

    // 1. Pick the target block.
    let target = match block {
        Some(n) => n,
        None => {
            let (head, ep) = client.call("eth_blockNumber", json!([]))?;
            let head = parse_quantity(&head)?;
            let target = head - latest_minus;
            println!("head {head} (via {ep}) → target {target} (head-{latest_minus})");
            target
        }
    };
    let tag = format!("0x{target:x}");

    // 2. Raw block RLP (skips all JSON block parsing; RLP is also the guest wire format).
    let (raw, ep_block) = client.call("debug_getRawBlock", json!([tag]))?;
    let raw = parse_hex_bytes(&raw)?;
    let block: Block = alloy_rlp::decode_exact(raw.as_slice())
        .map_err(|e| anyhow::anyhow!("block RLP decode failed: {e}"))?;
    println!(
        "block {} via {ep_block}: {} txs, gas {}, {} bytes RLP",
        block.header.number,
        block.body.transactions.len(),
        block.header.gas_used,
        raw.len()
    );
    anyhow::ensure!(
        block.header.number == target,
        "endpoint returned wrong block"
    );

    // 3. Execution witness. Shape varies by node (BlockPI emits `headers` as JSON
    //    objects instead of RLP hex; `keys` population varies) — parse inside the
    //    failover so a non-conforming endpoint falls through to the next.
    let ((witness_json, witness), ep_wit) =
        client.call_validated("debug_executionWitness", json!([tag]), |result| {
            let mut witness_json = result.clone();
            if witness_json.get("keys").is_none() {
                witness_json["keys"] = json!([]);
            }
            let witness: ExecutionWitness = serde_json::from_value(witness_json.clone())
                .context("witness JSON → ExecutionWitness")?;
            Ok((witness_json, witness))
        })?;
    let wit_stats = WitnessStats::of(&witness);
    println!(
        "witness via {ep_wit}: {} state nodes ({:.1} MB), {} codes ({:.1} MB), {} headers, {} keys",
        wit_stats.state_count,
        wit_stats.state_bytes as f64 / 1e6,
        wit_stats.code_count,
        wit_stats.code_bytes as f64 / 1e6,
        wit_stats.header_count,
        wit_stats.key_count,
    );

    // 4. Recover per-tx uncompressed pubkeys (host-side; the guest only verifies).
    let signers = recover_signers(&block.body.transactions)?;
    println!("recovered {} tx pubkeys", signers.len());

    // 5. Assemble + serialize.
    let input = BlockInput {
        block,
        signers,
        witness,
    };
    let input_bytes = postcard::to_stdvec(&input)?;

    let dir = std::path::Path::new(out_root).join(target.to_string());
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join("input.bin"), &input_bytes)?;
    std::fs::write(dir.join("witness.json"), serde_json::to_vec(&witness_json)?)?;

    let meta = meta_json(
        &input.block,
        &raw,
        &input_bytes,
        &wit_stats,
        &ep_block,
        &ep_wit,
    );
    std::fs::write(dir.join("meta.json"), serde_json::to_string_pretty(&meta)?)?;

    println!(
        "wrote {} ({:.1} MB input.bin)",
        dir.display(),
        input_bytes.len() as f64 / 1e6
    );
    Ok(dir.join("input.bin"))
}

fn recover_signers(txs: &[TransactionSigned]) -> Result<Vec<UncompressedPublicKey>> {
    txs.iter()
        .enumerate()
        .map(|(i, tx)| {
            let vk = tx
                .signature()
                .recover_from_prehash(&tx.signature_hash())
                .with_context(|| format!("pubkey recovery failed for tx #{i}"))?;
            let point = vk.to_encoded_point(false);
            Ok(UncompressedPublicKey(
                point.as_bytes().try_into().expect("65-byte sec1 point"),
            ))
        })
        .collect()
}

struct WitnessStats {
    state_count: usize,
    state_bytes: usize,
    code_count: usize,
    code_bytes: usize,
    header_count: usize,
    key_count: usize,
}

impl WitnessStats {
    fn of(w: &ExecutionWitness) -> Self {
        Self {
            state_count: w.state.len(),
            state_bytes: w.state.iter().map(|b| b.len()).sum(),
            code_count: w.codes.len(),
            code_bytes: w.codes.iter().map(|b| b.len()).sum(),
            header_count: w.headers.len(),
            key_count: w.keys.len(),
        }
    }
}

fn meta_json(
    block: &Block,
    raw_rlp: &[u8],
    input_bytes: &[u8],
    w: &WitnessStats,
    ep_block: &str,
    ep_witness: &str,
) -> Value {
    let mut tx_type_counts = std::collections::BTreeMap::<u8, usize>::new();
    for tx in &block.body.transactions {
        *tx_type_counts.entry(tx.tx_type() as u8).or_default() += 1;
    }
    json!({
        "block_number": block.header.number,
        "timestamp": block.header.timestamp,
        "gas_used": block.header.gas_used,
        "gas_limit": block.header.gas_limit,
        "tx_count": block.body.transactions.len(),
        "tx_type_counts": tx_type_counts,
        "withdrawals": block.body.withdrawals.as_ref().map(|w| w.len()),
        "block_rlp_bytes": raw_rlp.len(),
        "input_bin_bytes": input_bytes.len(),
        "witness": {
            "state_nodes": w.state_count,
            "state_bytes": w.state_bytes,
            "codes": w.code_count,
            "code_bytes": w.code_bytes,
            "headers": w.header_count,
            "keys": w.key_count,
        },
        "endpoints": { "block": ep_block, "witness": ep_witness },
        "fetched_at": chrono_free_now(),
    })
}

/// ISO-ish UTC timestamp without pulling chrono.
fn chrono_free_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    format!("unix:{}", now.as_secs())
}
