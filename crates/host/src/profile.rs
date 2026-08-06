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

pub fn run(input_path: &str, every: u64, top: usize) -> Result<()> {
    crate::trace::build_guest_with_symbols()?;
    let elf_file = crate::trace::elf_path();
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

    let input_bytes = std::fs::read(input_path).context("reading input.bin")?;
    let memory_config = crate::trace::memory_config(&elf);

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

    println!("profiling (sampling every {every} ticks)...");
    let start = Instant::now();
    let mut samples: HashMap<usize, u64> = HashMap::new();
    let mut prev_pc: u64 = 0;
    let mut ticks: u64 = 0;
    loop {
        let pc = emulator.get_cpu().read_pc();
        if pc == prev_pc {
            break;
        }
        if ticks.is_multiple_of(every) {
            *samples.entry(lookup(pc, &symbols)).or_default() += 1;
        }
        emulator.tick(None);
        prev_pc = pc;
        ticks += 1;
    }
    let rows = emulator.get_cpu().trace_len;
    let wall = start.elapsed();
    println!(
        "done: {ticks} real instrs, {rows} trace rows in {wall:.1?} ({:.1} MHz)",
        ticks as f64 / wall.as_secs_f64() / 1e6
    );

    let total: u64 = samples.values().sum();
    let mut ranked: Vec<(usize, u64)> = samples.into_iter().collect();
    ranked.sort_by_key(|(_, n)| std::cmp::Reverse(*n));

    println!("\n=== top {top} symbols by sampled real-instruction share ===");
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
