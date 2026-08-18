//! `jeth trace`: run the guest over an input on the Jolt RV64IMAC emulator —
//! execute-only streaming count (no trace materialization, no proving).

use anyhow::{bail, Context, Result};
use jolt_common::jolt_device::{MemoryConfig, MemoryLayout};
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
const GUEST_TARGET_DIR: &str = "/Volumes/Dev/cargo-target/jeth-campaign-2x-guest";
const DEFAULT_JOLT_CLI: &str = "/Volumes/Dev/cargo-target/jolt-cli-main/release/jolt";

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

/// ELF path for a build with extra guest features (each feature set gets its
/// own target dir so switching configurations doesn't thrash rebuilds).
pub fn elf_path_with(variant: Variant, extra_features: &[&str]) -> PathBuf {
    let suffix: String = extra_features.iter().map(|f| format!("-{f}")).collect();
    PathBuf::from(format!("{GUEST_TARGET_DIR}-{}{suffix}", variant.func()))
        .join("riscv64imac-unknown-none-elf/release")
        .join("jeth-guest")
}

/// Compute the emulator memory config for a guest ELF (must mirror the guest's
/// `#[jolt::provable]` attributes — see constants above / guest lib.rs).
pub fn memory_config(elf: &[u8], variant: Variant) -> MemoryConfig {
    let (_, _, program_end, _) = tracer::decode(elf);
    memory_config_for_program(program_end - RAM_START_ADDRESS, variant)
}

fn memory_config_for_program(program_size: u64, variant: Variant) -> MemoryConfig {
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
        program_size: Some(program_size),
    }
}

/// Address at which the postcard stream for the first guest argument is mapped.
///
/// The JEF self-align prefix only depends on this address mod 8; every region
/// start is 8-aligned by `MemoryLayout` construction, which is what lets one
/// input.bin serve all three variants (Advice maps it at trusted_advice_start).
pub fn stream_start(variant: Variant) -> u64 {
    let layout = MemoryLayout::new(&memory_config_for_program(0, variant));
    match variant {
        Variant::Advice => layout.trusted_advice_start,
        Variant::Input | Variant::Trusted => layout.input_start,
    }
}

/// Address at which the Trusted variant's digest blob (second argument,
/// trusted advice) is mapped.
fn digest_stream_start() -> u64 {
    MemoryLayout::new(&memory_config_for_program(0, Variant::Trusted)).trusted_advice_start
}

pub fn wrap_input(raw: &[u8]) -> Result<Vec<u8>> {
    Ok(postcard::to_stdvec(&raw)?)
}

pub fn decode_input(raw: &[u8]) -> Result<jeth_core::BlockInput> {
    let stream: &'static [u8] = Box::leak(wrap_input(raw)?.into_boxed_slice());
    let bytes: &'static [u8] = postcard::from_bytes(stream).context("decoding JEF argument")?;
    jeth_core::decode_container(bytes).map_err(anyhow::Error::msg)
}

/// Build with symbols preserved (JOLT_BACKTRACE=1 — metadata only, identical
/// code), plus optional extra guest features.
pub fn build_guest_symbols_features(variant: Variant, extra_features: &[&str]) -> Result<()> {
    build_guest_inner(variant, true, extra_features)
}

/// Build the guest ELF via the `jolt` CLI (main-2026-09-04 build recipe:
/// lower-atomic pass, custom linker script from --stack-size/--heap-size, etc.)
/// with extra guest cargo features (e.g. `pertx` for per-tx markers).
pub fn build_guest_features(variant: Variant, extra_features: &[&str]) -> Result<()> {
    build_guest_inner(variant, false, extra_features)
}

fn build_guest_inner(variant: Variant, symbols: bool, extra_features: &[&str]) -> Result<()> {
    let jolt_cli = std::env::var("JOLT_PATH").unwrap_or_else(|_| DEFAULT_JOLT_CLI.to_string());
    let func = variant.func();
    let suffix: String = extra_features.iter().map(|f| format!("-{f}")).collect();
    let target_dir = format!("{GUEST_TARGET_DIR}-{func}{suffix}");
    let features: String = core::iter::once("guest")
        .chain(extra_features.iter().copied())
        .collect::<Vec<_>>()
        .join(",");
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
        &features,
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
        elf_path_with(variant, extra_features).display()
    );
    Ok(())
}

/// Pre-compute witness-node digests + code hashes for the trusted variant.
/// Blob: u32 LE state count | state digests | code hashes (32 B each).
fn digest_blob_for(input_bin: &[u8]) -> Result<Vec<u8>> {
    let stream = wrap_input(input_bin)?;
    let bytes: &[u8] = postcard::from_bytes(&stream).context("decoding JEF argument")?;
    let input = jeth_core::container::ContainerReader::read(bytes).map_err(anyhow::Error::msg)?;
    let mut blob = Vec::with_capacity(4 + 32 * (input.state.len() + input.codes.len()));
    blob.extend_from_slice(&(input.state.len() as u32).to_le_bytes());
    for node in &input.state {
        blob.extend_from_slice(alloy_primitives::keccak256(node).as_slice());
    }
    for code in &input.codes {
        blob.extend_from_slice(alloy_primitives::keccak256(code).as_slice());
    }
    let blob = jeth_core::container::self_align(blob, digest_stream_start(), 4)
        .map_err(anyhow::Error::msg)?;
    println!(
        "digest blob: {} state + {} code digests ({} bytes)",
        input.state.len(),
        input.codes.len(),
        blob.len()
    );
    Ok(blob)
}

/// Build (unless `skip_build` and both ELFs exist) the proven + `compute_advice`
/// ELF pair, run pass 1 (full emulation of the compute ELF — writes the advice
/// tape; its rows never count), and return the tape positioned for reading.
///
/// Advice-trie two-pass (spec §6): jeth drives builds itself, so the SDK's
/// automatic two-pass does not apply. The two builds are DIFFERENT ELFs with
/// the same `JOLT_FUNC_NAME`; a forgotten tape panics the proven pass at the
/// smoke sentinel.
pub fn advice_pass1(
    variant: Variant,
    extra_features: &[&str],
    skip_build: bool,
    input_stream: &[u8],
    trusted_stream: &[u8],
) -> Result<tracer::AdviceTape> {
    let compute_features: Vec<&str> = extra_features
        .iter()
        .copied()
        .chain(["compute_advice"])
        .collect();
    let compute_elf_file = elf_path_with(variant, &compute_features);
    if !skip_build || !compute_elf_file.exists() {
        build_guest_features(variant, &compute_features)?;
    }
    let compute_elf = std::fs::read(&compute_elf_file).context("reading compute-advice ELF")?;
    let memory_config = memory_config(&compute_elf, variant);

    println!("advice pass 1 (compute_advice ELF, full emulation)...");
    let start = Instant::now();
    let (_, device, mut tape) = tracer::execute(
        &compute_elf,
        Some(&compute_elf_file),
        input_stream,
        &[],
        trusted_stream,
        &memory_config,
        None,
    );
    if device.panic {
        bail!("compute_advice pass PANICKED — advice bodies failed");
    }
    tape.reset_read_position();
    println!(
        "advice tape: {} bytes in {:.1?}",
        tape.len(),
        start.elapsed()
    );
    Ok(tape)
}

pub fn run(
    input_path: &str,
    skip_build: bool,
    variant: Variant,
    extra_features: &[&str],
) -> Result<()> {
    let elf_file = elf_path_with(variant, extra_features);
    if !skip_build || !elf_file.exists() {
        build_guest_features(variant, extra_features)?;
    }

    let elf = std::fs::read(&elf_file).context("reading guest ELF")?;
    println!(
        "guest ELF: {:.1} MB ({})",
        elf.len() as f64 / 1e6,
        variant.func()
    );

    let raw = std::fs::read(input_path).context("reading input.bin")?;
    println!("input: {} ({:.1} MB)", input_path, raw.len() as f64 / 1e6);
    // Jolt's generated entry point adds only the &[u8] argument length prefix.
    let wrapped = wrap_input(&raw)?;
    if wrapped.len() as u64 > MAX_INPUT_SIZE {
        bail!(
            "input {} bytes exceeds guest size budget {}",
            wrapped.len(),
            MAX_INPUT_SIZE
        );
    }
    let digest_blob = match variant {
        Variant::Trusted => Some(wrap_input(&digest_blob_for(&raw)?)?),
        _ => None,
    };
    let (input_stream, trusted_stream): (&[u8], &[u8]) = match variant {
        Variant::Input => (&wrapped, &[]),
        Variant::Advice => (&[], &wrapped),
        Variant::Trusted => (&wrapped, digest_blob.as_deref().unwrap()),
    };

    // Advice two-pass: pass 1 populates the tape from the compute_advice ELF.
    let tape = advice_pass1(
        variant,
        extra_features,
        skip_build,
        input_stream,
        trusted_stream,
    )?;

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
        Some(tape),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The JEF self-align prefix is computed against one region start but the
    /// same input.bin is mapped at a different region per variant. That only
    /// works while every stream start is 8-aligned — pin it against jolt
    /// MemoryLayout drift.
    #[test]
    fn all_stream_starts_are_8_aligned() {
        for variant in [Variant::Input, Variant::Advice, Variant::Trusted] {
            assert_eq!(stream_start(variant) % 8, 0);
        }
        assert_eq!(digest_stream_start() % 8, 0);
    }
}
