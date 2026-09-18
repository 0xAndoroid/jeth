//! `jeth touches`: native state-touch census over an input.bin (see
//! `jeth_core::census`). Prints the per-block table and, with `--json`, the
//! full report.

use anyhow::{Context, Result};
use jeth_core::census::{CensusReport, KeyStats};
use std::time::Instant;

pub fn run(
    input_path: &str,
    json: Option<&str>,
    top: usize,
    dump_digests: Option<&str>,
) -> Result<()> {
    let bytes = std::fs::read(input_path)?;
    let input = crate::trace::decode_input(&bytes)?;
    if let Some(path) = dump_digests {
        // One keccak per witness state node, sorted hex, one per line: the
        // cross-block reuse census diffs these sets between consecutive blocks.
        let mut digests: Vec<String> = input
            .witness
            .state
            .iter()
            .map(|node| alloy_primitives::hex::encode(alloy_primitives::keccak256(node)))
            .collect();
        digests.sort_unstable();
        std::fs::write(path, digests.join("\n") + "\n")
            .with_context(|| format!("writing {path}"))?;
    }
    let number = input.block.header.number;
    println!(
        "block {number}: {} txs (census)",
        input.block.body.transactions.len()
    );

    let start = Instant::now();
    #[cfg(feature = "secp-inline")]
    jeth_core::install_jolt_crypto();
    let block = jeth_core::recover_block(input.block, input.signers)
        .map_err(|e| anyhow::anyhow!("signature verification FAILED: {e}"))?;
    let report = jeth_core::census::run(block, input.witness, top)
        .map_err(|e| anyhow::anyhow!("stateless validation FAILED: {e}"))?;
    println!("✅ validated in {:.2?}", start.elapsed());
    print_report(&report);

    if let Some(path) = json {
        std::fs::write(path, serde_json::to_string_pretty(&to_json(&report))?)
            .with_context(|| format!("writing {path}"))?;
        println!("json: {path}");
    }
    Ok(())
}

fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        100.0 * part as f64 / whole as f64
    }
}

fn print_keys(label: &str, k: &KeyStats) {
    println!(
        "  {label}: distinct={} tx_loads={} ({:.2}/key) repeated_keys={} ({:.1}%) \
         repeated_tx_loads={} ({:.1}%) ops={} ops_on_repeated={} ({:.1}%) written={}",
        k.distinct,
        k.tx_loads,
        k.tx_loads as f64 / k.distinct.max(1) as f64,
        k.repeated,
        pct(k.repeated, k.distinct),
        k.repeated_tx_loads,
        pct(k.repeated_tx_loads, k.tx_loads),
        k.op_accesses,
        k.repeated_op_accesses,
        pct(k.repeated_op_accesses, k.op_accesses),
        k.written,
    );
}

fn print_report(r: &CensusReport) {
    let o = &r.ops;
    println!(
        "block {} hash=0x{} gas_used={} txs={} witness_nodes={} witness_codes={}",
        r.block,
        alloy_primitives::hex::encode(r.block_hash),
        r.gas_used,
        r.txs,
        r.witness_nodes,
        r.witness_codes
    );
    println!(
        "  ops: steps={} SLOAD={} SSTORE={} BALANCE={} SELFBALANCE={} EXTCODESIZE={} \
         EXTCODEHASH={} EXTCODECOPY={} CALL={} CALLCODE={} DELEGATECALL={} STATICCALL={} \
         CREATE={} CREATE2={}",
        o.steps,
        o.sload,
        o.sstore,
        o.balance,
        o.selfbalance,
        o.extcodesize,
        o.extcodehash,
        o.extcodecopy,
        o.call,
        o.callcode,
        o.delegatecall,
        o.staticcall,
        o.create,
        o.create2
    );
    let d = &r.db;
    println!(
        "  db misses: basic={} (none={}) storage={} (zero={}) code_by_hash={} (library={}) \
         block_hash={}",
        d.basic,
        d.basic_none,
        d.storage,
        d.storage_zero,
        d.code_by_hash,
        d.code_from_library,
        d.block_hash
    );
    print_keys("accounts", &r.accounts);
    print_keys("slots", &r.slots);
    let c = &r.codes;
    println!(
        "  codes: frames={} (initcode={}) distinct_hashes={} in_2plus_txs={} ({:.1}%) \
         frames_on_repeated={} ({:.1}%)",
        c.frames,
        c.initcode_frames,
        c.distinct_hashes,
        c.hashes_in_2plus_txs,
        pct(c.hashes_in_2plus_txs, c.distinct_hashes),
        c.frames_on_repeated,
        pct(c.frames_on_repeated, c.frames)
    );
    println!(
        "  hottest {} accounts (by txs; {} of {} txs touch at least one):",
        r.hottest.len(),
        r.hottest_union_txs,
        r.txs
    );
    for h in &r.hottest {
        println!(
            "    {} txs={} slots={} slot_ops={} address_ops={}",
            h.address, h.txs, h.slots_loaded, h.slot_ops, h.address_ops
        );
    }
}

fn to_json(r: &CensusReport) -> serde_json::Value {
    let keys = |k: &KeyStats| {
        serde_json::json!({
            "distinct": k.distinct,
            "tx_loads": k.tx_loads,
            "repeated": k.repeated,
            "repeated_tx_loads": k.repeated_tx_loads,
            "op_accesses": k.op_accesses,
            "repeated_op_accesses": k.repeated_op_accesses,
            "written": k.written,
        })
    };
    let o = &r.ops;
    let d = &r.db;
    let c = &r.codes;
    serde_json::json!({
        "block": r.block,
        "block_hash": format!("0x{}", alloy_primitives::hex::encode(r.block_hash)),
        "gas_used": r.gas_used,
        "txs": r.txs,
        "witness_nodes": r.witness_nodes,
        "witness_codes": r.witness_codes,
        "ops": {
            "steps": o.steps, "sload": o.sload, "sstore": o.sstore, "balance": o.balance,
            "selfbalance": o.selfbalance, "extcodesize": o.extcodesize,
            "extcodehash": o.extcodehash, "extcodecopy": o.extcodecopy, "call": o.call,
            "callcode": o.callcode, "delegatecall": o.delegatecall,
            "staticcall": o.staticcall, "create": o.create, "create2": o.create2,
        },
        "db_misses": {
            "basic": d.basic, "basic_none": d.basic_none, "storage": d.storage,
            "storage_zero": d.storage_zero, "code_by_hash": d.code_by_hash,
            "code_from_library": d.code_from_library, "block_hash": d.block_hash,
        },
        "accounts": keys(&r.accounts),
        "slots": keys(&r.slots),
        "codes": {
            "frames": c.frames, "initcode_frames": c.initcode_frames,
            "distinct_hashes": c.distinct_hashes, "hashes_in_2plus_txs": c.hashes_in_2plus_txs,
            "frames_on_repeated": c.frames_on_repeated,
        },
        "hottest": r.hottest.iter().map(|h| serde_json::json!({
            "address": h.address.to_string(), "txs": h.txs, "slots_loaded": h.slots_loaded,
            "slot_ops": h.slot_ops, "address_ops": h.address_ops,
        })).collect::<Vec<_>>(),
        "hottest_union_txs": r.hottest_union_txs,
    })
}
