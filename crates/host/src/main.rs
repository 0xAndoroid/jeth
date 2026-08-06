//! jeth — Jolt-trace stateless Ethereum block validation.
//!
//! Subcommands:
//! - `fetch`      block + execution witness + recovered pubkeys → `data/<N>/input.bin`
//! - `run-native` native `stateless_validation` over an input (witness-compatibility gate)
//! - `trace`      run the input through the Jolt guest on the RISC-V tracer (no proving)

mod fetch;
mod profile;
mod rpc;
mod trace;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "jeth",
    about = "Jolt-trace stateless Ethereum block validation"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fetch a recent block + witness, recover tx pubkeys, write input.bin.
    Fetch {
        /// Explicit block number (default: head minus --latest-minus).
        #[arg(long)]
        block: Option<u64>,
        /// How far behind head to target when --block is not given.
        #[arg(long, default_value_t = 8)]
        latest_minus: u64,
        /// Comma-separated JSON-RPC endpoint list (ordered failover).
        #[arg(long, value_delimiter = ',')]
        rpc_list: Option<Vec<String>>,
        /// Output root directory.
        #[arg(long, default_value = "data")]
        out: String,
    },
    /// Natively validate an input.bin (geth-witness compatibility gate).
    RunNative {
        #[arg(long)]
        input: String,
    },
    /// Trace the guest over an input.bin on the Jolt RV64IMAC emulator (streaming count).
    Trace {
        #[arg(long)]
        input: String,
        /// Skip rebuilding the guest ELF if it already exists.
        #[arg(long)]
        skip_build: bool,
        /// Deliver the payload as TRUSTED ADVICE instead of committed input.
        #[arg(long)]
        advice: bool,
    },
    /// PC-sampling profile of the guest run (symbol histogram).
    Profile {
        #[arg(long)]
        input: String,
        /// Sample every N ticks.
        #[arg(long, default_value_t = 64)]
        every: u64,
        /// Show top N symbols.
        #[arg(long, default_value_t = 40)]
        top: usize,
        /// Bucket return addresses while PC is inside the first symbol matching
        /// this substring (one-level caller profile).
        #[arg(long)]
        callers_of: Option<String>,
    },
    /// End-to-end: fetch a fresh block, validate natively, trace in the guest.
    Bench {
        /// How far behind head to target.
        #[arg(long, default_value_t = 8)]
        latest_minus: u64,
        /// Comma-separated JSON-RPC endpoint list (ordered failover).
        #[arg(long, value_delimiter = ',')]
        rpc_list: Option<Vec<String>>,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    match Cli::parse().command {
        Command::Fetch {
            block,
            latest_minus,
            rpc_list,
            out,
        } => fetch::run(block, latest_minus, rpc_list, &out).map(|_| ()),
        Command::RunNative { input } => run_native(&input),
        Command::Trace {
            input,
            skip_build,
            advice,
        } => {
            let variant = if advice {
                trace::Variant::Advice
            } else {
                trace::Variant::Input
            };
            trace::run(&input, skip_build, variant)
        }
        Command::Profile {
            input,
            every,
            top,
            callers_of,
        } => profile::run(&input, every, top, callers_of),
        Command::Bench {
            latest_minus,
            rpc_list,
        } => {
            let input = fetch::run(None, latest_minus, rpc_list, "data")?;
            let input = input.to_string_lossy();
            run_native(&input)?;
            trace::run(&input, false, trace::Variant::Input)
        }
    }
}

fn run_native(input_path: &str) -> Result<()> {
    use std::time::Instant;

    let bytes = std::fs::read(input_path)?;
    println!("input: {} ({:.1} MB)", input_path, bytes.len() as f64 / 1e6);

    let start = Instant::now();
    let input: jeth_core::BlockInput = postcard::from_bytes(&bytes)?;
    println!("deserialized in {:.2?}", start.elapsed());

    let number = input.block.header.number;
    let header_gas = input.block.header.gas_used;
    let txs = input.block.body.transactions.len();
    println!("block {number}: {txs} txs, {header_gas} gas (header)");

    let start = Instant::now();
    let result = jeth_core::validate_mainnet(input)
        .map_err(|e| anyhow::anyhow!("stateless validation FAILED: {e}"))?;
    let elapsed = start.elapsed();

    println!(
        "✅ stateless validation passed in {elapsed:.2?}\n   block_hash: 0x{}\n   gas_used:   {}",
        alloy_primitives::hex::encode(result.block_hash),
        result.gas_used,
    );
    Ok(())
}
