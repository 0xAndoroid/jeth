//! jeth — Jolt-trace stateless Ethereum block validation.
//!
//! Subcommands:
//! - `fetch`      block + execution witness + recovered pubkeys → `data/<N>/input.bin`
//! - `run-native` native `stateless_validation` over an input (witness-compatibility gate)
//! - `trace`      run the input through the Jolt guest on the RISC-V tracer (no proving)

mod fetch;
mod library;
mod opcodes;
mod profile;
mod repack;
mod rpc;
mod trace;
mod txprofile;

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
        /// Embedded code-library manifest used to omit covered witness codes.
        #[arg(long, default_value = library::DEFAULT_MANIFEST)]
        library: String,
    },
    /// Natively validate an input.bin (geth-witness compatibility gate).
    RunNative {
        #[arg(long)]
        input: String,
    },
    /// Rebuild JEF input.bin from a cached block and witness.
    Repack {
        /// Cached block directory containing witness.json and block.rlp.
        #[arg(long)]
        dir: String,
        /// Embedded code-library manifest used to omit covered witness codes.
        #[arg(long, default_value = library::DEFAULT_MANIFEST)]
        library: String,
    },
    /// Build program-image-committed contract code artifacts.
    Library {
        #[command(subcommand)]
        command: LibraryCommand,
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
        /// Supply pre-computed witness digests as trusted advice (reveal skips
        /// keccak; digest map is verifier-trusted — see RESULTS.md caveat).
        #[arg(long)]
        trusted_digests: bool,
        /// Extra guest cargo features (comma-separated), e.g. `lazy` for
        /// deferred bytecode analysis. Each set builds into its own target dir.
        #[arg(long, value_delimiter = ',', default_value = "")]
        guest_features: Vec<String>,
    },
    /// Exact dynamic RV-opcode histogram (execs × trace rows).
    Opcodes {
        #[arg(long)]
        input: String,
        /// Skip rebuilding the guest ELF if it already exists.
        #[arg(long)]
        skip_build: bool,
        /// Comma-separated kind prefixes (e.g. "LBU,SB") to attribute to ELF
        /// symbols (uses the symbols guest build).
        #[arg(long)]
        symbols_for: Option<String>,
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
        /// Exact trace-row attribution (real + virtual/inline rows) per symbol.
        #[arg(long)]
        rows: bool,
        /// With --rows: per-PC row histogram inside the first symbol matching
        /// this substring (splits a function into its phases).
        #[arg(long)]
        pcs_of: Option<String>,
        /// With --rows: count entries (PC == symbol start) of every symbol
        /// containing one of these substrings (comma-separated) — call counts.
        #[arg(long, value_delimiter = ',')]
        entries: Vec<String>,
        /// Skip rebuilding the (symbolized) guest ELF pair if it already exists.
        #[arg(long)]
        skip_build: bool,
        /// With --rows: attribute rows per (marker, symbol) — phase AND per-tx
        /// spans (builds the guest with the pertx feature).
        #[arg(long)]
        split_markers: bool,
        /// With --split-markers: write the full marker × symbol matrix here.
        #[arg(long)]
        json: Option<String>,
        /// Extra guest cargo features (comma-separated), e.g. `lazy`.
        #[arg(long, value_delimiter = ',', default_value = "")]
        guest_features: Vec<String>,
    },
    /// Per-transaction cycle attribution (guest built with per-tx markers).
    Txprofile {
        #[arg(long)]
        input: String,
        /// Show top N transactions.
        #[arg(long, default_value_t = 30)]
        top: usize,
        /// Skip rebuilding the guest ELF if it already exists.
        #[arg(long)]
        skip_build: bool,
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

#[derive(Subcommand)]
enum LibraryCommand {
    /// Build a deterministic library from cached block witness directories.
    Build {
        #[arg(long, required = true, value_delimiter = ',', num_args = 1..)]
        blocks: Vec<String>,
        #[arg(long)]
        top_n: Option<usize>,
        #[arg(long)]
        out: String,
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
            library,
        } => fetch::run(block, latest_minus, rpc_list, &out, &library).map(|_| ()),
        Command::RunNative { input } => run_native(&input),
        Command::Repack { dir, library } => repack::run(&dir, &library),
        Command::Library { command } => match command {
            LibraryCommand::Build { blocks, top_n, out } => library::build(&blocks, top_n, &out),
        },
        Command::Trace {
            input,
            skip_build,
            advice,
            trusted_digests,
            guest_features,
        } => {
            let variant = match (advice, trusted_digests) {
                (_, true) => trace::Variant::Trusted,
                (true, _) => trace::Variant::Advice,
                _ => trace::Variant::Input,
            };
            let features: Vec<&str> = guest_features
                .iter()
                .filter(|f| !f.is_empty())
                .map(|f| f.as_str())
                .collect();
            trace::run(&input, skip_build, variant, &features)
        }
        Command::Opcodes {
            input,
            skip_build,
            symbols_for,
        } => opcodes::run(&input, skip_build, symbols_for),
        Command::Profile {
            input,
            every,
            top,
            callers_of,
            rows,
            pcs_of,
            entries,
            skip_build,
            split_markers,
            json,
            guest_features,
        } => {
            let features: Vec<&str> = guest_features
                .iter()
                .filter(|f| !f.is_empty())
                .map(|f| f.as_str())
                .collect();
            let entries: Vec<&str> = entries.iter().map(String::as_str).collect();
            profile::run(
                &input,
                every,
                top,
                callers_of,
                rows,
                pcs_of,
                &entries,
                skip_build,
                split_markers,
                json,
                &features,
            )
        }
        Command::Txprofile {
            input,
            top,
            skip_build,
        } => txprofile::run(&input, top, skip_build),
        Command::Bench {
            latest_minus,
            rpc_list,
        } => {
            let input = fetch::run(
                None,
                latest_minus,
                rpc_list,
                "data",
                library::DEFAULT_MANIFEST,
            )?;
            let input = input.to_string_lossy();
            run_native(&input)?;
            trace::run(&input, false, trace::Variant::Input, &[])
        }
    }
}

fn run_native(input_path: &str) -> Result<()> {
    use std::time::Instant;

    let bytes = std::fs::read(input_path)?;
    println!("input: {} ({:.1} MB)", input_path, bytes.len() as f64 / 1e6);

    let start = Instant::now();
    let input = trace::decode_input(&bytes)?;
    println!("read JEF in {:.2?}", start.elapsed());

    let number = input.block.header.number;
    let header_gas = input.block.header.gas_used;
    let txs = input.block.body.transactions.len();
    #[cfg(feature = "premeasure")]
    let witness_nodes = input.witness.state.len();
    println!("block {number}: {txs} txs, {header_gas} gas (header)");

    let start = Instant::now();
    #[cfg(feature = "secp-inline")]
    let validation = {
        jeth_core::install_jolt_crypto();
        jeth_core::recover_block(input.block, input.signers)
            .and_then(|block| jeth_core::validate_recovered(block, input.witness))
    };
    #[cfg(not(feature = "secp-inline"))]
    let validation = jeth_core::validate_mainnet(input);
    let result = validation.map_err(|e| anyhow::anyhow!("stateless validation FAILED: {e}"))?;
    let elapsed = start.elapsed();

    println!(
        "✅ stateless validation passed in {elapsed:.2?}\n   block_hash: 0x{}\n   gas_used:   {}",
        alloy_primitives::hex::encode(result.block_hash),
        result.gas_used,
    );
    #[cfg(feature = "premeasure")]
    {
        use jeth_core::premeasure as pm;
        let [sb, ee, ph, pr] = [
            pm::STATE_BUILD.get(),
            pm::EXEC_END.get(),
            pm::PRE_STATE_HASH.get(),
            pm::POST_ROOT.get(),
        ];
        let d = |a: [u64; 3], b: [u64; 3]| [b[0] - a[0], b[1] - a[1], b[2] - a[2]];
        let (exec, post_storage, state_hash) = (d(sb, ee), d(ee, ph), d(ph, pr));
        println!("premeasure: witness_state_nodes={witness_nodes}");
        println!(
            "  state_build:         probes={} hits={} decodes={}",
            sb[0], sb[1], sb[2]
        );
        println!(
            "  exec storage builds: probes={} hits={} decodes={}",
            exec[0], exec[1], exec[2]
        );
        println!(
            "  post_root storage:   probes={} hits={} decodes={}",
            post_storage[0], post_storage[1], post_storage[2]
        );
        println!(
            "  post_root state:     probes={} hits={} decodes={}",
            state_hash[0], state_hash[1], state_hash[2]
        );
        println!(
            "  TOTALS: probes={} hits={} decodes={}",
            pr[0], pr[1], pr[2]
        );
    }
    Ok(())
}
