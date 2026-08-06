//! `jeth trace`: run the guest over an input on the Jolt RV64IMAC emulator —
//! execute-only streaming count (no trace materialization, no proving).

use anyhow::{bail, Context, Result};
use jolt_common::jolt_device::MemoryConfig;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

// Register the keccak256 + secp256k1 inline opcode handlers with the tracer (inventory).
extern crate jolt_inlines_keccak256 as _;
extern crate jolt_inlines_secp256k1 as _;

/// Must match the `#[jolt::provable(...)]` attributes in crates/guest/src/lib.rs.
const MAX_INPUT_SIZE: u64 = 33554432; // 32 MiB
const MAX_OUTPUT_SIZE: u64 = 4096;
const HEAP_SIZE: u64 = 1610612736; // 1.5 GiB
const STACK_SIZE: u64 = 33554432; // 32 MiB
const MAX_ADVICE_SIZE: u64 = 4096; // jolt defaults (attrs unset)

const RAM_START_ADDRESS: u64 = 0x8000_0000;

const GUEST_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../guest");
const GUEST_TARGET_DIR: &str = "/Volumes/Dev/cargo-target/jeth-guest";
const DEFAULT_JOLT_CLI: &str = "/Volumes/Dev/cargo-target/jolt-cli/release/jolt";

pub fn elf_path() -> PathBuf {
    PathBuf::from(GUEST_TARGET_DIR)
        .join("riscv64imac-unknown-none-elf/release")
        .join("jeth-guest")
}

/// Compute the emulator memory config for a guest ELF (must mirror the guest's
/// `#[jolt::provable]` attributes — see constants above).
pub fn memory_config(elf: &[u8]) -> MemoryConfig {
    let (_, _, program_end, _) = tracer::decode(elf);
    MemoryConfig {
        max_input_size: MAX_INPUT_SIZE,
        max_output_size: MAX_OUTPUT_SIZE,
        max_trusted_advice_size: MAX_ADVICE_SIZE,
        max_untrusted_advice_size: MAX_ADVICE_SIZE,
        stack_size: STACK_SIZE,
        heap_size: HEAP_SIZE,
        program_size: Some(program_end - RAM_START_ADDRESS),
    }
}

/// Build with symbols preserved (JOLT_BACKTRACE=1 — metadata only, identical code).
pub fn build_guest_with_symbols() -> Result<()> {
    build_guest_inner(true)
}

/// Build the guest ELF via the `jolt` CLI (branch merge-1717-main build recipe:
/// lower-atomic pass, custom linker script from --stack-size/--heap-size, etc.).
pub fn build_guest() -> Result<()> {
    build_guest_inner(false)
}

fn build_guest_inner(symbols: bool) -> Result<()> {
    let jolt_cli = std::env::var("JOLT_PATH").unwrap_or_else(|_| DEFAULT_JOLT_CLI.to_string());
    let args = [
        "build",
        "-p",
        "jeth-guest",
        "--backtrace",
        "off",
        "--stack-size",
        "33554432",
        "--heap-size",
        "1610612736",
        "--",
        "--release",
        "--target-dir",
        GUEST_TARGET_DIR,
        "--features",
        "guest",
    ];
    println!("building guest: {jolt_cli} {}", args.join(" "));
    let start = Instant::now();
    let mut cmd = Command::new(&jolt_cli);
    cmd.args(args)
        .current_dir(GUEST_DIR)
        .env("JOLT_FUNC_NAME", "validate_block");
    if symbols {
        cmd.env("JOLT_BACKTRACE", "1");
    }
    let output = cmd
        .output()
        .with_context(|| format!("failed to run jolt CLI at {jolt_cli}"))?;
    if !output.status.success() {
        bail!(
            "guest build failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    println!(
        "guest built in {:.1?} → {}",
        start.elapsed(),
        elf_path().display()
    );
    Ok(())
}

pub fn run(input_path: &str, skip_build: bool) -> Result<()> {
    let elf_file = elf_path();
    if !skip_build || !elf_file.exists() {
        build_guest()?;
    }

    let elf = std::fs::read(&elf_file).context("reading guest ELF")?;
    println!("guest ELF: {:.1} MB", elf.len() as f64 / 1e6);

    let input_bytes = std::fs::read(input_path).context("reading input.bin")?;
    println!(
        "input: {} ({:.1} MB)",
        input_path,
        input_bytes.len() as f64 / 1e6
    );
    if input_bytes.len() as u64 > MAX_INPUT_SIZE {
        bail!(
            "input {} bytes exceeds guest max_input_size {}",
            input_bytes.len(),
            MAX_INPUT_SIZE
        );
    }

    // program_size for the emulator's memory layout — mirror jolt's Program::execute.
    let memory_config = memory_config(&elf);

    // Execute-only streaming pass: counts trace rows (real + virtual/inline
    // expansions — the prover-relevant "cycles") without materializing anything.
    // Cycle markers print via tracing::info as the guest hits them.
    println!("tracing (execute-only streaming count)...");
    let start = Instant::now();
    let (trace_rows, device, _advice) = tracer::execute(
        &elf,
        Some(&elf_file),
        &input_bytes,
        &[],
        &[],
        &memory_config,
        None,
    );
    let wall = start.elapsed();

    if device.panic {
        bail!(
            "guest PANICKED after {trace_rows} cycles ({wall:.1?}) — validation failed inside the guest"
        );
    }

    let result: jeth_core::ValidationResult = postcard::from_bytes(&device.outputs)
        .context("decoding guest output (ValidationResult)")?;

    let mhz = trace_rows as f64 / wall.as_secs_f64() / 1e6;
    println!("\n=== trace complete ===");
    println!(
        "block_hash:  0x{}",
        alloy_primitives::hex::encode(result.block_hash)
    );
    println!("gas_used:    {}", result.gas_used);
    println!("trace rows (total cycles): {trace_rows}");
    println!("wall time:   {wall:.1?} ({mhz:.2} MHz)");
    println!(
        "cycles/gas:  {:.2}",
        trace_rows as f64 / result.gas_used as f64
    );

    // Persist a machine-readable summary next to the input for report assembly.
    let summary = serde_json::json!({
        "input": input_path,
        "elf_bytes": elf.len(),
        "trace_rows_total": trace_rows,
        "gas_used": result.gas_used,
        "block_hash": format!("0x{}", alloy_primitives::hex::encode(result.block_hash)),
        "cycles_per_gas": trace_rows as f64 / result.gas_used as f64,
        "wall_seconds": wall.as_secs_f64(),
        "effective_mhz": mhz,
        "guest_panicked": device.panic,
    });
    let summary_path = std::path::Path::new(input_path).with_file_name("trace-summary.json");
    std::fs::write(&summary_path, serde_json::to_string_pretty(&summary)?)?;
    println!("summary → {}", summary_path.display());

    Ok(())
}
