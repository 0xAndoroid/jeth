//! `jeth profile`: PC-sampling profiler over the Jolt emulator.
//!
//! Drives the emulator tick-by-tick (execute-only speed), samples the guest PC
//! every `--every` ticks, buckets samples by ELF symbol, and prints a top-N
//! table. Requires a guest built with symbols (JOLT_BACKTRACE=1 — symbol
//! metadata only, no codegen change).

use anyhow::{Context, Result};
use object::{Object, ObjectSymbol};
use std::collections::HashMap;
use std::time::Instant;

#[allow(clippy::too_many_arguments)]
pub fn run(
    input_path: &str,
    every: u64,
    top: usize,
    callers_of: Option<String>,
    rows: bool,
    split_markers: bool,
    json_out: Option<String>,
    guest_features: &[&str],
) -> Result<()> {
    let variant = crate::trace::Variant::Input;
    // --split-markers needs the per-tx marker build (plus symbols either way).
    let mut features: Vec<&str> = guest_features.to_vec();
    if split_markers && !features.contains(&"pertx") {
        features.push("pertx");
    }
    crate::trace::build_guest_symbols_features(variant, &features)?;
    let elf_file = crate::trace::elf_path_with(variant, &features);
    let elf = std::fs::read(&elf_file).context("reading guest ELF")?;

    // Symbol table → sorted (addr, size, name).
    let obj = object::File::parse(&*elf).context("parsing guest ELF")?;
    let mut symbols: Vec<(u64, u64, String)> = obj
        .symbols()
        .filter(|s| s.kind() == object::SymbolKind::Text && s.size() > 0)
        .map(|s| {
            (
                s.address(),
                s.size(),
                rustc_demangle::demangle(s.name().unwrap_or("?")).to_string(),
            )
        })
        .collect();
    symbols.sort_by_key(|(addr, _, _)| *addr);
    anyhow::ensure!(
        !symbols.is_empty(),
        "guest ELF has no symbols — build with JOLT_BACKTRACE=1"
    );
    println!("{} text symbols", symbols.len());

    let raw = std::fs::read(input_path).context("reading input.bin")?;
    let input_bytes = postcard::to_stdvec(&raw)?;
    let memory_config = crate::trace::memory_config(&elf, variant);

    let mut emulator = tracer::create_emulator(
        &elf,
        Some(&elf_file),
        &input_bytes,
        &[],
        &[],
        &memory_config,
        None,
    );

    let lookup = |pc: u64, symbols: &[(u64, u64, String)]| -> usize {
        // Index of the symbol containing pc (or nearest preceding).
        match symbols.binary_search_by(|(addr, _, _)| addr.cmp(&pc)) {
            Ok(i) => i,
            Err(0) => usize::MAX,
            Err(i) => i - 1,
        }
    };

    // --callers-of: restrict to samples whose PC is inside a matching symbol and
    // bucket the RETURN ADDRESS (ra/x1) instead — a one-level caller profile.
    let target_range: Option<(u64, u64)> = callers_of.as_deref().map(|needle| {
        let (addr, size, name) = symbols
            .iter()
            .find(|(_, _, n)| n.contains(needle))
            .unwrap_or_else(|| panic!("no symbol matching {needle:?}"));
        println!("caller profile of {name} @ {addr:#x}+{size:#x}");
        (*addr, *addr + *size)
    });

    // --split-markers: track the guest's active cycle-marker (phase / per-tx)
    // by watching the entry PC of the jeth_phase_start/end hooks and reading the
    // label bytes out of guest memory. Rows are attributed to (innermost marker,
    // symbol) — a full phase × component matrix in one run.
    let hook_addr = |name: &str| -> Option<u64> {
        symbols
            .iter()
            .find(|(_, _, n)| n == name)
            .map(|(a, _, _)| *a)
    };
    let (hook_start, hook_end) = if split_markers {
        let hs = hook_addr("jeth_phase_start").context("no jeth_phase_start symbol")?;
        let he = hook_addr("jeth_phase_end").context("no jeth_phase_end symbol")?;
        (Some(hs), Some(he))
    } else {
        (None, None)
    };

    println!(
        "profiling (sampling every {every} ticks; rows={rows}, split_markers={split_markers})..."
    );
    let start = Instant::now();
    let mut samples: HashMap<usize, u64> = HashMap::new();
    // (marker label id, symbol idx) -> rows; label id 0 = outside any marker.
    let mut marker_samples: HashMap<(u16, usize), u64> = HashMap::new();
    let mut labels: Vec<String> = vec!["(outside markers)".into()];
    let mut label_ids: HashMap<String, u16> = HashMap::new();
    let mut marker_stack: Vec<u16> = Vec::new();
    let mut prev_pc: u64 = 0;
    let mut ticks: u64 = 0;
    if rows && split_markers {
        let mut prev_rows = emulator.get_cpu().trace_len as u64;
        loop {
            let pc = emulator.get_cpu().read_pc();
            if pc == prev_pc {
                break;
            }
            if Some(pc) == hook_start {
                let ptr = emulator.get_cpu().read_register(10) as u64;
                let len = (emulator.get_cpu().read_register(11) as u64).min(64);
                let mmu = emulator.get_mut_cpu().get_mut_mmu();
                let bytes: Vec<u8> = (0..len).map(|i| mmu.load_raw(ptr + i)).collect();
                let label = String::from_utf8_lossy(&bytes).into_owned();
                let id = *label_ids.entry(label.clone()).or_insert_with(|| {
                    labels.push(label);
                    (labels.len() - 1) as u16
                });
                marker_stack.push(id);
            } else if Some(pc) == hook_end {
                marker_stack.pop();
            }
            let cur = marker_stack.last().copied().unwrap_or(0);
            emulator.tick(None);
            let now_rows = emulator.get_cpu().trace_len as u64;
            *marker_samples
                .entry((cur, lookup(pc, &symbols)))
                .or_default() += now_rows - prev_rows;
            prev_rows = now_rows;
            prev_pc = pc;
            ticks += 1;
        }
    } else if rows {
        // Exact TRACE-ROW attribution: every tick's row delta (1 real row +
        // virtual-sequence/inline expansion rows) is charged to the executing
        // symbol — or, with --callers-of, to the RETURN ADDRESS while the PC
        // is inside the target symbol. Slower than sampling but exact.
        let mut prev_rows = emulator.get_cpu().trace_len as u64;
        loop {
            let pc = emulator.get_cpu().read_pc();
            if pc == prev_pc {
                break;
            }
            emulator.tick(None);
            let now_rows = emulator.get_cpu().trace_len as u64;
            let delta = now_rows - prev_rows;
            match target_range {
                None => *samples.entry(lookup(pc, &symbols)).or_default() += delta,
                Some((lo, hi)) if pc >= lo && pc < hi => {
                    let ra = emulator.get_cpu().read_register(1) as u64;
                    *samples.entry(lookup(ra, &symbols)).or_default() += delta;
                }
                Some(_) => {}
            }
            prev_rows = now_rows;
            prev_pc = pc;
            ticks += 1;
        }
    } else {
        loop {
            let pc = emulator.get_cpu().read_pc();
            if pc == prev_pc {
                break;
            }
            if ticks.is_multiple_of(every) {
                match target_range {
                    None => *samples.entry(lookup(pc, &symbols)).or_default() += 1,
                    Some((lo, hi)) if pc >= lo && pc < hi => {
                        let ra = emulator.get_cpu().read_register(1) as u64;
                        *samples.entry(lookup(ra, &symbols)).or_default() += 1;
                    }
                    Some(_) => {}
                }
            }
            emulator.tick(None);
            prev_pc = pc;
            ticks += 1;
        }
    }
    let total_rows = emulator.get_cpu().trace_len;
    let wall = start.elapsed();
    println!(
        "done: {ticks} real instrs, {total_rows} trace rows in {wall:.1?} ({:.1} MHz)",
        ticks as f64 / wall.as_secs_f64() / 1e6
    );

    if split_markers {
        // Per-marker totals + top symbols inside each marker span.
        let mut per_label: HashMap<u16, u64> = HashMap::new();
        for ((label, _), n) in &marker_samples {
            *per_label.entry(*label).or_default() += n;
        }
        let mut ranked_labels: Vec<(u16, u64)> = per_label.into_iter().collect();
        ranked_labels.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

        let sym_name = |idx: usize| -> &str {
            if idx == usize::MAX {
                "<unknown>"
            } else {
                &symbols[idx].2
            }
        };

        println!("\n=== rows by marker (innermost) ===");
        for (label_id, n) in ranked_labels.iter().take(30) {
            println!(
                "{:6.2}%  {:>13}  {}",
                100.0 * *n as f64 / total_rows as f64,
                n,
                labels[*label_id as usize]
            );
        }

        if let Some(path) = json_out {
            // Full (marker, symbol) matrix for offline analysis.
            let mut by_label: HashMap<u16, Vec<(usize, u64)>> = HashMap::new();
            for ((label, sym), n) in &marker_samples {
                by_label.entry(*label).or_default().push((*sym, *n));
            }
            let json = serde_json::json!({
                "input": input_path,
                "total_rows": total_rows,
                "markers": ranked_labels.iter().map(|(label_id, n)| {
                    let mut syms = by_label.remove(label_id).unwrap_or_default();
                    syms.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
                    serde_json::json!({
                        "label": labels[*label_id as usize],
                        "rows": n,
                        // full list (tiny entries dropped) — downstream aggregation
                        // over 400+ tx labels needs untruncated symbol rows.
                        "symbols": syms.iter().take_while(|(_, n)| *n >= 256).map(|(sym, n)| {
                            serde_json::json!({"symbol": sym_name(*sym), "rows": n})
                        }).collect::<Vec<_>>(),
                    })
                }).collect::<Vec<_>>(),
            });
            std::fs::write(&path, serde_json::to_string(&json)?)?;
            println!("marker × symbol matrix → {path}");
        }
        return Ok(());
    }

    let total: u64 = samples.values().sum();
    let mut ranked: Vec<(usize, u64)> = samples.into_iter().collect();
    ranked.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

    let unit = if rows {
        "exact trace-row"
    } else {
        "sampled real-instruction"
    };
    println!("\n=== top {top} symbols by {unit} share ===");
    for (sym_idx, n) in ranked.iter().take(top) {
        let name = if *sym_idx == usize::MAX {
            "<unknown>"
        } else {
            &symbols[*sym_idx].2
        };
        println!(
            "{:6.2}%  {:>12}  {}",
            100.0 * *n as f64 / total as f64,
            n,
            name
        );
    }
    Ok(())
}
