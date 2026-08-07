//! `jeth txprofile`: per-transaction cycle attribution.
//!
//! Builds the guest with per-tx cycle markers (`pertx` feature), runs the
//! tracer in-process with a capturing `tracing` layer (the emulator reports
//! every marker span as an INFO event), and joins the per-tx cycle counts with
//! tx metadata + per-tx gas from a native run of the same vendored validation
//! loop. Output: ranked table + `txprofile.json` next to the input.

use anyhow::{Context, Result};
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tracing_subscriber::layer::SubscriberExt;

/// Captured `tracing` event messages (the tracer's cycle-marker reports).
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

struct MessageVisitor(Option<String>);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor(None);
        event.record(&mut visitor);
        if let Some(msg) = visitor.0 {
            self.0.lock().unwrap().push(msg);
        }
    }
}

#[derive(serde::Serialize)]
struct TxRow {
    index: usize,
    hash: String,
    cycles: u64,
    gas_used: u64,
    cycles_per_gas: f64,
    to: Option<String>,
    selector: Option<String>,
    tx_type: u8,
    input_len: usize,
}

pub fn run(input_path: &str, top: usize, skip_build: bool) -> Result<()> {
    let variant = crate::trace::Variant::Input;
    let features = ["pertx"];
    let elf_file = crate::trace::elf_path_with(variant, &features);
    if !skip_build || !elf_file.exists() {
        crate::trace::build_guest_features(variant, &features)?;
    }
    let elf = std::fs::read(&elf_file).context("reading guest ELF")?;

    let raw = std::fs::read(input_path).context("reading input.bin")?;
    let wrapped = postcard::to_stdvec(&raw)?;
    let memory_config = crate::trace::memory_config(&elf, variant);

    // ---- native pass: tx metadata + per-tx gas from receipts ----------------
    /// (hash, to, selector, tx_type, input_len)
    type TxMeta = (String, Option<String>, Option<String>, u8, usize);
    let input: jeth_core::BlockInput = postcard::from_bytes(&raw)?;
    let block_number = input.block.header.number;
    let txs_meta: Vec<TxMeta> = {
        use alloy_consensus::transaction::Transaction as _;
        input
            .block
            .body
            .transactions
            .iter()
            .map(|tx| {
                let hash = format!("{:#x}", tx.tx_hash());
                let to = tx.to().map(|a| format!("{a:#x}"));
                let selector = (tx.input().len() >= 4)
                    .then(|| format!("0x{}", alloy_primitives::hex::encode(&tx.input()[..4])));
                (hash, to, selector, tx.tx_type() as u8, tx.input().len())
            })
            .collect()
    };
    println!("native validation (per-tx gas from receipts)...");
    let recovered = jeth_core::recover_block(input.block, input.signers)
        .map_err(|e| anyhow::anyhow!("native recover failed: {e}"))?;
    let chain_spec = std::sync::Arc::new(jeth_core::mainnet_spec());
    let evm_config = jeth_core::EthEvmConfig::new(chain_spec.clone());
    let validated = jeth_core::validation::validate_recovered_pertx(
        recovered,
        input.witness,
        chain_spec,
        evm_config,
    )
    .map_err(|e| anyhow::anyhow!("native validation failed: {e}"))?;
    let mut gas_per_tx = Vec::with_capacity(validated.receipts.len());
    let mut prev = 0u64;
    for receipt in &validated.receipts {
        gas_per_tx.push(receipt.cumulative_gas_used - prev);
        prev = receipt.cumulative_gas_used;
    }

    // ---- guest pass: per-tx cycles via markers ------------------------------
    let capture = Capture::default();
    let subscriber = tracing_subscriber::registry().with(capture.clone());

    println!("tracing with per-tx markers (execute-only streaming count)...");
    let start = Instant::now();
    let (trace_rows, device, _advice) = tracing::subscriber::with_default(subscriber, || {
        tracer::execute(
            &elf,
            Some(&elf_file),
            &wrapped,
            &[],
            &[],
            &memory_config,
            None,
        )
    });
    let wall = start.elapsed();
    anyhow::ensure!(!device.panic, "guest PANICKED after {trace_rows} cycles");
    let result: jeth_core::ValidationResult = postcard::from_bytes(&device.outputs)?;
    anyhow::ensure!(
        result.gas_used == validated.gas_used && result.block_hash == validated.block_hash.0,
        "guest output diverged from native run"
    );
    println!(
        "trace: {trace_rows} rows in {wall:.1?} ({:.1} MHz)",
        trace_rows as f64 / wall.as_secs_f64() / 1e6
    );

    // Marker report: "txNNNN": R RV64IMAC cycles + V virtual instructions = T total cycles
    let marker_re = regex_lite::Regex::new(
        r#""([^"]+)": (\d+) RV64IMAC cycles \+ (\d+) virtual instructions = (\d+) total cycles"#,
    )
    .unwrap();
    let mut tx_cycles: Vec<Option<u64>> = vec![None; txs_meta.len()];
    let mut phase_cycles: Vec<(String, u64)> = Vec::new();
    for line in capture.0.lock().unwrap().iter() {
        let Some(caps) = marker_re.captures(line) else {
            continue;
        };
        let label = &caps[1];
        let total: u64 = caps[4].parse()?;
        if let Some(idx) = label
            .strip_prefix("tx")
            .and_then(|s| s.parse::<usize>().ok())
        {
            if idx < tx_cycles.len() {
                tx_cycles[idx] = Some(total);
                continue;
            }
        }
        phase_cycles.push((label.to_string(), total));
    }
    let measured = tx_cycles.iter().flatten().count();
    anyhow::ensure!(
        measured == txs_meta.len(),
        "captured {measured} tx markers, expected {}",
        txs_meta.len()
    );

    let mut rows: Vec<TxRow> = txs_meta
        .into_iter()
        .enumerate()
        .map(|(i, (hash, to, selector, tx_type, input_len))| TxRow {
            index: i,
            hash,
            cycles: tx_cycles[i].unwrap(),
            gas_used: gas_per_tx[i],
            cycles_per_gas: tx_cycles[i].unwrap() as f64 / gas_per_tx[i] as f64,
            to,
            selector,
            tx_type,
            input_len,
        })
        .collect();

    let exec_total: u64 = rows.iter().map(|r| r.cycles).sum();
    rows.sort_by_key(|r| std::cmp::Reverse(r.cycles));

    println!("\n=== phases ===");
    for (label, total) in &phase_cycles {
        println!("{:>14}  {label}", fmt_u64(*total));
    }
    println!(
        "\n=== per-tx: {} txs, {} cycles in tx execution ({:.1}% of {} total rows) ===",
        rows.len(),
        fmt_u64(exec_total),
        100.0 * exec_total as f64 / trace_rows as f64,
        fmt_u64(trace_rows as u64),
    );
    let mut cum = 0u64;
    let header = format!(
        "{:>5} {:>13} {:>9} {:>7} {:>6} {:>5}  {:44} selector",
        "#", "cycles", "gas", "c/g", "cum%", "type", "to"
    );
    println!("{header}");
    for row in rows.iter().take(top) {
        cum += row.cycles;
        println!(
            "{:>5} {:>13} {:>9} {:>7.1} {:>5.1}% {:>5}  {:44} {}",
            row.index,
            fmt_u64(row.cycles),
            row.gas_used,
            row.cycles_per_gas,
            100.0 * cum as f64 / exec_total as f64,
            row.tx_type,
            row.to.as_deref().unwrap_or("(create)"),
            row.selector.as_deref().unwrap_or("-"),
        );
    }

    // Concentration summary (whale check).
    let n = rows.len().max(1);
    let share = |k: usize| -> f64 {
        100.0 * rows.iter().take(k).map(|r| r.cycles).sum::<u64>() as f64 / exec_total as f64
    };
    println!(
        "\nconcentration: top-1 {:.1}% | top-5 {:.1}% | top-10 {:.1}% | top-{} (10%) {:.1}%",
        share(1),
        share(5),
        share(10),
        n / 10,
        share(n / 10)
    );

    let out_path = std::path::Path::new(input_path).with_file_name("txprofile.json");
    let mut file = std::fs::File::create(&out_path)?;
    let summary = serde_json::json!({
        "block_number": block_number,
        "input": input_path,
        "trace_rows_total": trace_rows,
        "tx_exec_cycles": exec_total,
        "phases": phase_cycles.iter().map(|(l, c)| serde_json::json!({"label": l, "cycles": c})).collect::<Vec<_>>(),
        "txs": rows,
    });
    file.write_all(serde_json::to_string_pretty(&summary)?.as_bytes())?;
    println!("per-tx profile → {}", out_path.display());
    Ok(())
}

fn fmt_u64(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
