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
const TRUSTED_DIGEST_ADVICE_SIZE: u64 = 4194304; // 4 MiB (validate_block_trusted)

const RAM_START_ADDRESS: u64 = 0x8000_0000;

const GUEST_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../guest");
const GUEST_TARGET_DIR: &str = "/Volumes/Dev/cargo-target/jeth-guest";
const DEFAULT_JOLT_CLI: &str = "/Volumes/Dev/cargo-target/jolt-cli/release/jolt";

/// Guest entry point variant.
#[derive(Clone, Copy, PartialEq)]
pub enum Variant {
    /// Committed input (fully self-verifying — the headline configuration).
    Input,
    /// Whole payload via trusted advice (prover-side commitment savings only).
    Advice,
    /// Committed input + pre-computed witness digests via trusted advice
    /// (reveal skips keccak; digest map is verifier-trusted — see RESULTS.md).
    Trusted,
}

impl Variant {
    pub fn func(self) -> &'static str {
        match self {
            Variant::Input => "validate_block",
            Variant::Advice => "validate_block_advice",
            Variant::Trusted => "validate_block_trusted",
        }
    }
}

pub fn elf_path(variant: Variant) -> PathBuf {
    PathBuf::from(format!("{GUEST_TARGET_DIR}-{}", variant.func()))
        .join("riscv64imac-unknown-none-elf/release")
        .join("jeth-guest")
}

/// Compute the emulator memory config for a guest ELF (must mirror the guest's
/// `#[jolt::provable]` attributes — see constants above / guest lib.rs).
pub fn memory_config(elf: &[u8], variant: Variant) -> MemoryConfig {
    let (_, _, program_end, _) = tracer::decode(elf);
    let (input_size, trusted_size) = match variant {
        Variant::Input => (MAX_INPUT_SIZE, MAX_ADVICE_SIZE),
        Variant::Advice => (MAX_ADVICE_SIZE, MAX_INPUT_SIZE),
        Variant::Trusted => (MAX_INPUT_SIZE, TRUSTED_DIGEST_ADVICE_SIZE),
    };
    MemoryConfig {
        max_input_size: input_size,
        max_output_size: MAX_OUTPUT_SIZE,
        max_trusted_advice_size: trusted_size,
        max_untrusted_advice_size: MAX_ADVICE_SIZE,
        stack_size: STACK_SIZE,
        heap_size: HEAP_SIZE,
        program_size: Some(program_end - RAM_START_ADDRESS),
    }
}

/// Build with symbols preserved (JOLT_BACKTRACE=1 — metadata only, identical code).
pub fn build_guest_with_symbols(variant: Variant) -> Result<()> {
    build_guest_inner(variant, true)
}

/// Build the guest ELF via the `jolt` CLI (branch merge-1717-main build recipe:
/// lower-atomic pass, custom linker script from --stack-size/--heap-size, etc.).
pub fn build_guest(variant: Variant) -> Result<()> {
    build_guest_inner(variant, false)
}

fn build_guest_inner(variant: Variant, symbols: bool) -> Result<()> {
    let jolt_cli = std::env::var("JOLT_PATH").unwrap_or_else(|_| DEFAULT_JOLT_CLI.to_string());
    let func = variant.func();
    let target_dir = format!("{GUEST_TARGET_DIR}-{func}");
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
        &target_dir,
        "--features",
        "guest",
    ];
    println!("building guest ({func}): {jolt_cli} {}", args.join(" "));
    let start = Instant::now();
    let mut cmd = Command::new(&jolt_cli);
    cmd.args(args)
        .current_dir(GUEST_DIR)
        .env("JOLT_FUNC_NAME", func);
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
        elf_path(variant).display()
    );
    Ok(())
}

/// Pre-compute witness-node digests + code hashes for the trusted variant.
/// Blob: u32 LE state count | state digests | code hashes (32 B each).
fn digest_blob_for(input_bin: &[u8]) -> Result<Vec<u8>> {
    let input: jeth_core::BlockInput =
        postcard::from_bytes(input_bin).context("parsing input.bin for digest precompute")?;
    let mut blob =
        Vec::with_capacity(4 + 32 * (input.witness.state.len() + input.witness.codes.len()));
    blob.extend_from_slice(&(input.witness.state.len() as u32).to_le_bytes());
    for node in &input.witness.state {
        blob.extend_from_slice(alloy_primitives::keccak256(node).as_slice());
    }
    for code in &input.witness.codes {
        blob.extend_from_slice(alloy_primitives::keccak256(code).as_slice());
    }
    println!(
        "digest blob: {} state + {} code digests ({} bytes)",
        input.witness.state.len(),
        input.witness.codes.len(),
        blob.len()
    );
    Ok(blob)
}

pub fn run(input_path: &str, skip_build: bool, variant: Variant) -> Result<()> {
    let elf_file = elf_path(variant);
    if !skip_build || !elf_file.exists() {
        build_guest(variant)?;
    }

    let elf = std::fs::read(&elf_file).context("reading guest ELF")?;
    println!(
        "guest ELF: {:.1} MB ({})",
        elf.len() as f64 / 1e6,
        variant.func()
    );

    let raw = std::fs::read(input_path).context("reading input.bin")?;
    println!("input: {} ({:.1} MB)", input_path, raw.len() as f64 / 1e6);
    // The guest fn takes `&[u8]` — postcard-wrap the payload (varint len + bytes).
    let wrapped = postcard::to_stdvec(&raw)?;
    if wrapped.len() as u64 > MAX_INPUT_SIZE {
        bail!(
            "input {} bytes exceeds guest size budget {}",
            wrapped.len(),
            MAX_INPUT_SIZE
        );
    }
    let digest_blob = match variant {
        Variant::Trusted => Some(postcard::to_stdvec(&digest_blob_for(&raw)?)?),
        _ => None,
    };
    let (input_stream, trusted_stream): (&[u8], &[u8]) = match variant {
        Variant::Input => (&wrapped, &[]),
        Variant::Advice => (&[], &wrapped),
        Variant::Trusted => (&wrapped, digest_blob.as_deref().unwrap()),
    };

    // program_size for the emulator's memory layout — mirror jolt's Program::execute.
    let memory_config = memory_config(&elf, variant);

    // Execute-only streaming pass: counts trace rows (real + virtual/inline
    // expansions — the prover-relevant "cycles") without materializing anything.
    // Cycle markers print via tracing::info as the guest hits them.
    println!("tracing (execute-only streaming count)...");
    let start = Instant::now();
    let (trace_rows, device, _advice) = tracer::execute(
        &elf,
        Some(&elf_file),
        input_stream,
        &[],
        trusted_stream,
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
        "variant": variant.func(),
        "elf_bytes": elf.len(),
        "trace_rows_total": trace_rows,
        "gas_used": result.gas_used,
        "block_hash": format!("0x{}", alloy_primitives::hex::encode(result.block_hash)),
        "cycles_per_gas": trace_rows as f64 / result.gas_used as f64,
        "wall_seconds": wall.as_secs_f64(),
        "effective_mhz": mhz,
        "guest_panicked": device.panic,
    });
    let summary_name = match variant {
        Variant::Input => "trace-summary.json",
        Variant::Advice => "trace-summary-advice.json",
        Variant::Trusted => "trace-summary-trusted.json",
    };
    let summary_path = std::path::Path::new(input_path).with_file_name(summary_name);
    std::fs::write(&summary_path, serde_json::to_string_pretty(&summary)?)?;
    println!("summary → {}", summary_path.display());

    Ok(())
}
