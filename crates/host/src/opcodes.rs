//! `jeth opcodes`: exact dynamic RV-opcode histogram (execs × trace rows).
//!
//! Drives the emulator tick-by-tick like `profile --rows`, but buckets each
//! tick's row delta by the DECODED instruction class at the pre-tick PC
//! (compressed forms folded into their expanded class). Sizes the sub-word
//! load/store pool for the Jolt ISA lane without touching the guest.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::Instant;

/// Sub-word ops split by `imm & 7 == 0` (`/a` aligned-imm, `/u` not): the
/// aligned-imm fast path can reuse the base register's low address bits.
fn classify(insn: u32, compressed: bool) -> &'static str {
    if compressed {
        let quadrant = insn & 3;
        let funct3 = (insn >> 13) & 7;
        // C.LW/C.SW scale a 5-bit uimm by 4: imm&7 ∈ {0, 4}.
        let cw_imm_al = |i: u32| {
            let uimm = ((i >> 4) & 4) | ((i >> 7) & 0x38) | ((i << 1) & 0x40);
            if uimm & 7 == 0 {
                "/a"
            } else {
                "/u"
            }
        };
        return match (quadrant, funct3) {
            (0, 2) => {
                if cw_imm_al(insn) == "/a" {
                    "LW/a"
                } else {
                    "LW/u"
                }
            }
            (2, 2) => {
                // C.LWSP: uimm = insn[3:2]<<6 | insn[12]<<5 | insn[6:4]<<2
                let uimm =
                    ((insn >> 4) & 7) << 2 | ((insn >> 12) & 1) << 5 | ((insn >> 2) & 3) << 6;
                if uimm & 7 == 0 {
                    "LW/a"
                } else {
                    "LW/u"
                }
            }
            (0, 6) => {
                if cw_imm_al(insn) == "/a" {
                    "SW/a"
                } else {
                    "SW/u"
                }
            }
            (2, 6) => {
                // C.SWSP: uimm = insn[8:7]<<6 | insn[12:9]<<2
                let uimm = ((insn >> 9) & 0xf) << 2 | ((insn >> 7) & 3) << 6;
                if uimm & 7 == 0 {
                    "SW/a"
                } else {
                    "SW/u"
                }
            }
            (0, 3) | (2, 3) => "LD",
            (0, 7) | (2, 7) => "SD",
            _ => "C.other",
        };
    }
    let opcode = insn & 0x7f;
    let funct3 = (insn >> 12) & 7;
    let funct7 = (insn >> 25) & 0x7f;
    let i_imm_al = if (insn >> 20) & 7 == 0 { "/a" } else { "/u" };
    let s_imm_al = if ((insn >> 7) & 7) == 0 { "/a" } else { "/u" };
    match opcode {
        0x03 => match (funct3, i_imm_al) {
            (0, "/a") => "LB/a",
            (0, _) => "LB/u",
            (1, "/a") => "LH/a",
            (1, _) => "LH/u",
            (2, "/a") => "LW/a",
            (2, _) => "LW/u",
            (3, _) => "LD",
            (4, "/a") => "LBU/a",
            (4, _) => "LBU/u",
            (5, "/a") => "LHU/a",
            (5, _) => "LHU/u",
            (6, "/a") => "LWU/a",
            (6, _) => "LWU/u",
            _ => "load?",
        },
        0x23 => match (funct3, s_imm_al) {
            (0, "/a") => "SB/a",
            (0, _) => "SB/u",
            (1, "/a") => "SH/a",
            (1, _) => "SH/u",
            (2, "/a") => "SW/a",
            (2, _) => "SW/u",
            (3, _) => "SD",
            _ => "store?",
        },
        0x33 | 0x3b => {
            if funct7 == 1 {
                match funct3 {
                    0..=3 => "MUL*",
                    _ => "DIV/REM",
                }
            } else {
                "ALU-R"
            }
        }
        0x13 | 0x1b => "ALU-I",
        0x63 => "BRANCH",
        0x6f => "JAL",
        0x67 => "JALR",
        0x37 | 0x17 => "LUI/AUIPC",
        0x73 => "SYSTEM",
        0x2f => "AMO",
        0x0f => "FENCE",
        0x0b => "INLINE(custom-0)",
        0x2b => "INLINE(custom-1)",
        0x5b => "INLINE(custom-2)",
        _ => "other32",
    }
}

pub fn run(input_path: &str, skip_build: bool, symbols_for: Option<String>) -> Result<()> {
    let variant = crate::trace::Variant::Input;
    // Symbol attribution needs the symbols guest build (JOLT_BACKTRACE=1).
    let elf_file = if symbols_for.is_some() {
        crate::trace::build_guest_symbols_features(variant, &[])?;
        crate::trace::elf_path_with(variant, &[])
    } else {
        let f = crate::trace::elf_path_with(variant, &[]);
        if !skip_build || !f.exists() {
            crate::trace::build_guest_features(variant, &[])?;
        }
        f
    };
    let elf = std::fs::read(&elf_file).context("reading guest ELF")?;

    // Optional: symbol table for per-kind caller attribution.
    let symbols: Vec<(u64, u64, String)> = if symbols_for.is_some() {
        use object::{Object, ObjectSymbol};
        let obj = object::File::parse(&*elf).context("parsing guest ELF")?;
        let mut syms: Vec<(u64, u64, String)> = obj
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
        syms.sort_by_key(|(addr, _, _)| *addr);
        syms
    } else {
        Vec::new()
    };
    let target_kinds: Vec<&str> = symbols_for
        .as_deref()
        .map(|s| s.split(',').collect())
        .unwrap_or_default();

    let raw = std::fs::read(input_path).context("reading input.bin")?;
    let input_bytes = crate::trace::wrap_input(&raw)?;
    let memory_config = crate::trace::memory_config(&elf, variant);
    let tape = crate::trace::advice_pass1(variant, &[], skip_build, &input_bytes, &[])?;

    let mut emulator = tracer::create_emulator(
        &elf,
        Some(&elf_file),
        &input_bytes,
        &[],
        &[],
        &memory_config,
        Some(tape),
    );

    println!("opcode histogram (exact rows)...");
    let start = Instant::now();
    // kind -> (execs, rows)
    let mut buckets: HashMap<&'static str, (u64, u64)> = HashMap::new();
    // (kind, symbol idx) -> (execs, rows), only for kinds in --symbols-for.
    let mut sym_buckets: HashMap<(&'static str, usize), (u64, u64)> = HashMap::new();
    let lookup = |pc: u64| -> usize {
        match symbols.binary_search_by(|(addr, _, _)| addr.cmp(&pc)) {
            Ok(i) => i,
            Err(0) => usize::MAX,
            Err(i) => i - 1,
        }
    };
    let mut prev_pc: u64 = 0;
    let mut ticks: u64 = 0;
    let mut prev_rows = emulator.get_cpu().trace_len as u64;
    loop {
        let pc = emulator.get_cpu().read_pc();
        if pc == prev_pc {
            break;
        }
        let (insn, compressed) = {
            let mmu = emulator.get_mut_cpu().get_mut_mmu();
            let lo = mmu.load_raw(pc) as u32 | ((mmu.load_raw(pc + 1) as u32) << 8);
            if lo & 3 == 3 {
                let hi = mmu.load_raw(pc + 2) as u32 | ((mmu.load_raw(pc + 3) as u32) << 8);
                (lo | (hi << 16), false)
            } else {
                (lo, true)
            }
        };
        emulator.tick(None);
        let now_rows = emulator.get_cpu().trace_len as u64;
        let kind = classify(insn, compressed);
        let entry = buckets.entry(kind).or_default();
        entry.0 += 1;
        entry.1 += now_rows - prev_rows;
        if !target_kinds.is_empty() && target_kinds.iter().any(|t| kind.starts_with(t)) {
            let e = sym_buckets.entry((kind, lookup(pc))).or_default();
            e.0 += 1;
            e.1 += now_rows - prev_rows;
        }
        prev_rows = now_rows;
        prev_pc = pc;
        ticks += 1;
    }
    let total_rows = emulator.get_cpu().trace_len as u64;
    let wall = start.elapsed();
    println!(
        "done: {ticks} real instrs, {total_rows} trace rows in {wall:.1?} ({:.1} MHz)",
        ticks as f64 / wall.as_secs_f64() / 1e6
    );

    let mut ranked: Vec<(&'static str, (u64, u64))> = buckets.into_iter().collect();
    ranked.sort_by_key(|(_, (_, rows))| std::cmp::Reverse(*rows));
    println!(
        "\n{:<18} {:>14} {:>15} {:>9} {:>7}",
        "kind", "execs", "rows", "rows/ex", "share"
    );
    for (kind, (execs, rows)) in &ranked {
        println!(
            "{:<18} {:>14} {:>15} {:>9.3} {:>6.2}%",
            kind,
            execs,
            rows,
            *rows as f64 / *execs as f64,
            100.0 * *rows as f64 / total_rows as f64
        );
    }

    if !sym_buckets.is_empty() {
        // Aggregate by symbol across matched kinds, then top-30.
        let mut by_sym: HashMap<usize, (u64, u64)> = HashMap::new();
        for ((_, sym), (execs, rows)) in &sym_buckets {
            let e = by_sym.entry(*sym).or_default();
            e.0 += execs;
            e.1 += rows;
        }
        let mut ranked: Vec<(usize, (u64, u64))> = by_sym.into_iter().collect();
        ranked.sort_by_key(|(_, (_, rows))| std::cmp::Reverse(*rows));
        println!("\n=== top symbols for kinds {target_kinds:?} ===");
        for (sym, (execs, rows)) in ranked.iter().take(30) {
            let name = if *sym == usize::MAX {
                "<unknown>"
            } else {
                &symbols[*sym].2
            };
            println!("{:>12} rows {:>11} execs  {}", rows, execs, name);
        }
    }
    Ok(())
}
