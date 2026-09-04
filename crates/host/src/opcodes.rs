//! `jeth opcodes`: exact dynamic RV-opcode histogram (execs × trace rows).
//!
//! Drives the emulator tick-by-tick like `profile --rows`, but buckets each
//! tick's row delta by the DECODED instruction class at the pre-tick PC
//! (compressed forms folded into their expanded class). Sizes the sub-word
//! load/store pool for the Jolt ISA lane without touching the guest.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::time::Instant;

fn classify(insn: u32, compressed: bool) -> &'static str {
    if compressed {
        let quadrant = insn & 3;
        let funct3 = (insn >> 13) & 7;
        return match (quadrant, funct3) {
            (0, 2) | (2, 2) => "LW",
            (0, 3) | (2, 3) => "LD",
            (0, 6) | (2, 6) => "SW",
            (0, 7) | (2, 7) => "SD",
            _ => "C.other",
        };
    }
    let opcode = insn & 0x7f;
    let funct3 = (insn >> 12) & 7;
    let funct7 = (insn >> 25) & 0x7f;
    match opcode {
        0x03 => match funct3 {
            0 => "LB",
            1 => "LH",
            2 => "LW",
            3 => "LD",
            4 => "LBU",
            5 => "LHU",
            6 => "LWU",
            _ => "load?",
        },
        0x23 => match funct3 {
            0 => "SB",
            1 => "SH",
            2 => "SW",
            3 => "SD",
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

pub fn run(input_path: &str, skip_build: bool) -> Result<()> {
    let variant = crate::trace::Variant::Input;
    let elf_file = crate::trace::elf_path_with(variant, &[]);
    if !skip_build || !elf_file.exists() {
        crate::trace::build_guest_features(variant, &[])?;
    }
    let elf = std::fs::read(&elf_file).context("reading guest ELF")?;

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
        let entry = buckets.entry(classify(insn, compressed)).or_default();
        entry.0 += 1;
        entry.1 += now_rows - prev_rows;
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
    Ok(())
}
