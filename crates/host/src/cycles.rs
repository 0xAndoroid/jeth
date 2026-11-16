//! `jeth cycles`: expanded-cycle counts over the frozen mainnet block set.
//!
//! `run` drives the measured tree's own `jeth repack` and `jeth trace` through
//! `cargo run`, so it measures any tree whose CLI has those two subcommands,
//! including trees that predate this file. The count is the `trace_rows_total`
//! that tree's `trace::run` writes: the rows of the proven pass after
//! virtual-sequence and inline expansion, unpadded.

use alloy_primitives::{hex, B256};
use anyhow::{anyhow, bail, ensure, Context, Result};
use reth_ethereum_primitives::Block;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::fs::File;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

pub const DEFAULT_TREE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

const MANIFEST: &str = include_str!("../../../fixtures/cycles-blocks.json");

/// `trace::Variant::Input` with no extra guest features: the target-dir suffix
/// `trace::elf_path_with` derives for it.
const GUEST_ELF: &str = "-validate_block/riscv64imac-unknown-none-elf/release/jeth-guest";

#[derive(Deserialize)]
struct Manifest {
    /// Release tag whose assets are `<number>.block.rlp` and `<number>.witness.json`.
    release: String,
    blocks: Vec<PinnedBlock>,
}

#[derive(Deserialize)]
struct PinnedBlock {
    number: u64,
    hash: B256,
    state_root: B256,
    receipts_root: B256,
    gas_used: u64,
    block_rlp_sha256: String,
    witness_json_sha256: String,
}

impl PinnedBlock {
    fn files(&self) -> [(&'static str, &str); 2] {
        [
            ("block.rlp", &self.block_rlp_sha256),
            ("witness.json", &self.witness_json_sha256),
        ]
    }
}

#[derive(Serialize, Deserialize)]
struct Report {
    commit: String,
    jolt_rev: String,
    jolt_cli: String,
    guest_elf_sha256: String,
    guest_elf_bytes: usize,
    block_set: String,
    blocks: Vec<BlockResult>,
    /// `None` when any block failed.
    total_rows: Option<u64>,
    total_gas: u64,
}

#[derive(Serialize, Deserialize)]
struct BlockResult {
    number: u64,
    gas_used: u64,
    #[serde(flatten)]
    outcome: Outcome,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Rows(u64),
    Error(String),
}

impl BlockResult {
    fn rows(&self) -> Option<u64> {
        match self.outcome {
            Outcome::Rows(rows) => Some(rows),
            Outcome::Error(_) => None,
        }
    }
}

/// The fields of the `trace-summary.json` that `trace::run` writes which the
/// harness reads.
#[derive(Deserialize)]
struct TraceSummary {
    trace_rows_total: u64,
    gas_used: u64,
    block_hash: B256,
    guest_panicked: bool,
}

struct Tree {
    root: PathBuf,
}

impl Tree {
    /// `cargo <subcommand>` on the tree's `jeth` binary, under the tree's own toolchain.
    fn cargo(&self, subcommand: &str) -> Command {
        let mut cmd = Command::new("cargo");
        cmd.args([subcommand, "--locked", "--release"])
            .args(["-p", "jeth-host", "--bin", "jeth"])
            .current_dir(&self.root)
            // A harness started through `cargo run` carries its own toolchain in
            // RUSTUP_TOOLCHAIN, which overrides the measured tree's rust-toolchain.toml.
            .env_remove("RUSTUP_TOOLCHAIN");
        cmd
    }

    fn jeth(&self) -> Command {
        let mut cmd = self.cargo("run");
        cmd.args(["-q", "--"])
            .env("JETH_GUEST_TARGET_DIR", self.root.join("target/guest"));
        cmd
    }

    fn build_host(&self) -> Result<()> {
        let status = self.cargo("build").status().context("running cargo")?;
        ensure!(
            status.success(),
            "building jeth-host in {} failed",
            self.root.display()
        );
        Ok(())
    }

    fn commit(&self) -> Result<String> {
        let git = |args: &[&str]| -> Result<String> {
            let output = Command::new("git")
                .arg("-C")
                .arg(&self.root)
                .args(args)
                .output()
                .context("running git")?;
            ensure!(output.status.success(), "git {args:?} failed");
            Ok(String::from_utf8(output.stdout)?.trim().to_string())
        };
        let head = git(&["rev-parse", "HEAD"])?;
        let dirty = !git(&["status", "--porcelain", "--untracked-files=no"])?.is_empty();
        Ok(if dirty { format!("{head}-dirty") } else { head })
    }

    /// The `a16z/jolt` rev the root manifest pins for the tracer.
    fn jolt_rev(&self) -> Result<String> {
        let manifest = std::fs::read_to_string(self.root.join("Cargo.toml"))?;
        let pin = regex_lite::Regex::new(r#"(?m)^tracer\s*=.*\brev\s*=\s*"([0-9a-f]+)""#)?;
        let rev = pin
            .captures(&manifest)
            .and_then(|captures| captures.get(1))
            .context("root Cargo.toml pins no rev for the tracer dependency")?;
        Ok(rev.as_str().to_string())
    }

    /// Derives the block's input with the tree's `repack`, traces it with the
    /// tree's guest and checks the guest validated the pinned block.
    fn measure(
        &self,
        pin: &PinnedBlock,
        cache: &Path,
        out: &Path,
        build_guest: bool,
    ) -> Result<u64> {
        let dir = out.join(pin.number.to_string());
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        std::fs::create_dir_all(&dir)?;
        for (file, _) in pin.files() {
            std::fs::copy(cache.join(format!("{}.{file}", pin.number)), dir.join(file))?;
        }
        // `repack` rewrites an existing meta.json and fails without one.
        std::fs::write(dir.join("meta.json"), "{}")?;

        let mut repack = self.jeth();
        repack.arg("repack").arg("--dir").arg(&dir);
        run_logged(repack, &dir.join("repack.log"))?;

        let mut trace = self.jeth();
        trace.arg("trace").arg("--input").arg(dir.join("input.bin"));
        if !build_guest {
            trace.arg("--skip-build");
        }
        run_logged(trace, &dir.join("trace.log"))?;

        let summary: TraceSummary =
            serde_json::from_slice(&std::fs::read(dir.join("trace-summary.json"))?)
                .context("decoding trace-summary.json")?;
        ensure!(!summary.guest_panicked, "guest panicked");
        ensure!(
            summary.block_hash == pin.hash && summary.gas_used == pin.gas_used,
            "guest validated block {} with {} gas, the manifest pins {} with {} gas",
            summary.block_hash,
            summary.gas_used,
            pin.hash,
            pin.gas_used
        );
        Ok(summary.trace_rows_total)
    }
}

/// Runs `cmd` with its output in `log`; a failure reports the log's last line.
fn run_logged(mut cmd: Command, log: &Path) -> Result<()> {
    let file = File::create(log)?;
    let status = cmd
        .stdin(Stdio::null())
        .stdout(file.try_clone()?)
        .stderr(file)
        .status()
        .with_context(|| format!("running {cmd:?}"))?;
    if !status.success() {
        let output = std::fs::read_to_string(log).unwrap_or_default();
        let last = output.lines().rev().find(|line| !line.trim().is_empty());
        bail!("{} (log: {})", last.unwrap_or("no output"), log.display());
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Downloads the block-set files `cache` lacks from `repo`'s release, checking
/// every file's sha256 and every block header against the manifest.
fn fetch_block_set(manifest: &Manifest, repo: &str, cache: &Path) -> Result<()> {
    std::fs::create_dir_all(cache)?;
    for pin in &manifest.blocks {
        for (file, sha256) in pin.files() {
            let asset = format!("{}.{file}", pin.number);
            let path = cache.join(&asset);
            if std::fs::read(&path).is_ok_and(|bytes| sha256_hex(&bytes) == sha256) {
                continue;
            }
            let url = format!(
                "https://github.com/{repo}/releases/download/{}/{asset}",
                manifest.release
            );
            println!("downloading {url}");
            let bytes = ureq::get(&url)
                .call()
                .with_context(|| format!("downloading {url}"))?
                .into_body()
                .with_config()
                // Witnesses exceed ureq's default 10 MiB body limit.
                .limit(u64::MAX)
                .read_to_vec()?;
            ensure!(sha256_hex(&bytes) == sha256, "{url}: sha256 mismatch");
            std::fs::write(&path, bytes)?;
        }
        check_header(
            pin,
            &std::fs::read(cache.join(format!("{}.block.rlp", pin.number)))?,
        )?;
    }
    Ok(())
}

fn check_header(pin: &PinnedBlock, block_rlp: &[u8]) -> Result<()> {
    let block: Block = alloy_rlp::decode_exact(block_rlp)
        .map_err(|error| anyhow!("decoding block {} RLP: {error}", pin.number))?;
    let header = &block.header;
    ensure!(
        header.number == pin.number
            && header.hash_slow() == pin.hash
            && header.state_root == pin.state_root
            && header.receipts_root == pin.receipts_root
            && header.gas_used == pin.gas_used,
        "block {} header differs from the manifest pins",
        pin.number
    );
    Ok(())
}

pub fn run(
    tree: &str,
    repo: &str,
    cache: &str,
    out: Option<&str>,
    jobs: NonZeroUsize,
) -> Result<()> {
    let manifest: Manifest = serde_json::from_str(MANIFEST)?;
    let cache = Path::new(cache).join(&manifest.release);
    fetch_block_set(&manifest, repo, &cache)?;

    let tree = Tree {
        root: std::fs::canonicalize(tree).with_context(|| format!("no tree at {tree}"))?,
    };
    let out = out.map_or_else(|| tree.root.join("target/cycles"), PathBuf::from);
    std::fs::create_dir_all(&out)?;
    // The tree's CLI runs from the tree root, not from this process's directory.
    let out = std::fs::canonicalize(out)?;
    let jolt_rev = tree.jolt_rev()?;
    let jolt_cli = std::env::var("JOLT_PATH").unwrap_or_else(|_| "jolt".to_string());
    let jolt_cli = Command::new(&jolt_cli)
        .arg("--version")
        .output()
        .with_context(|| format!("failed to run jolt CLI at {jolt_cli}"))?;

    println!("measuring {}", tree.root.display());
    let start = Instant::now();
    tree.build_host()?;
    println!("jeth-host built in {:.1?}", start.elapsed());

    let measure = |pin: &PinnedBlock, build_guest: bool| {
        let start = Instant::now();
        let outcome = match tree.measure(pin, &cache, &out, build_guest) {
            Ok(rows) => {
                println!(
                    "block {}: {rows} rows ({:.1?})",
                    pin.number,
                    start.elapsed()
                );
                Outcome::Rows(rows)
            }
            Err(error) => {
                println!("block {}: FAILED: {error:#}", pin.number);
                Outcome::Error(format!("{error:#}"))
            }
        };
        BlockResult {
            number: pin.number,
            gas_used: pin.gas_used,
            outcome,
        }
    };
    let (first, rest) = manifest
        .blocks
        .split_first()
        .context("the manifest pins no blocks")?;
    let mut blocks = vec![measure(first, true)];
    // Only a trace that succeeded after building proves the ELF pair in the
    // tree's target directory belongs to this revision. Until one has, a
    // checkout switched from another revision may still hold that revision's
    // ELFs, so every trace builds for itself, one at a time.
    let (jobs, build_guest) = if blocks[0].rows().is_some() {
        (jobs.get(), false)
    } else {
        (1, true)
    };
    for chunk in rest.chunks(jobs) {
        std::thread::scope(|scope| {
            let workers: Vec<_> = chunk
                .iter()
                .map(|pin| scope.spawn(|| measure(pin, build_guest)))
                .collect();
            for worker in workers {
                blocks.push(
                    worker
                        .join()
                        .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
                );
            }
        });
    }
    ensure!(
        blocks.iter().any(|block| block.rows().is_some()),
        "no block could be measured"
    );
    let elf = std::fs::read(tree.root.join(format!("target/guest{GUEST_ELF}")))
        .context("reading the guest ELF")?;

    let report = Report {
        // Read after the builds: one that rewrites a tracked lockfile leaves the tree dirty.
        commit: tree.commit()?,
        jolt_rev,
        jolt_cli: String::from_utf8(jolt_cli.stdout)?.trim().to_string(),
        guest_elf_sha256: sha256_hex(&elf),
        guest_elf_bytes: elf.len(),
        block_set: manifest.release.clone(),
        total_rows: blocks.iter().map(BlockResult::rows).sum(),
        total_gas: blocks.iter().map(|block| block.gas_used).sum(),
        blocks,
    };
    let table = report.table();
    std::fs::write(
        out.join("cycles.json"),
        serde_json::to_string_pretty(&report)?,
    )?;
    std::fs::write(out.join("cycles.md"), &table)?;
    println!("\n{table}\nwrote {}", out.join("cycles.json").display());

    let failed = report
        .blocks
        .iter()
        .filter(|block| block.rows().is_none())
        .count();
    ensure!(
        failed == 0,
        "{failed} of {} blocks failed",
        report.blocks.len()
    );
    Ok(())
}

pub fn compare(base: &str, head: &str) -> Result<()> {
    let load = |path: &str| -> Result<Report> {
        serde_json::from_slice(&std::fs::read(path).with_context(|| format!("reading {path}"))?)
            .with_context(|| format!("decoding {path}"))
    };
    print!("{}", comparison(&load(base)?, &load(head)?)?);
    Ok(())
}

fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, digit) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

fn cell(rows: Option<u64>) -> String {
    rows.map_or_else(|| "failed".to_string(), grouped)
}

fn per_gas(rows: Option<u64>, gas: u64) -> String {
    rows.map_or_else(
        || "–".to_string(),
        |rows| format!("{:.4}", rows as f64 / gas as f64),
    )
}

impl Report {
    fn table(&self) -> String {
        let mut out = "### Expanded cycles\n\n\
                       | Block | Expanded cycles | Gas | Cycles/gas |\n|---|---:|---:|---:|\n"
            .to_string();
        for block in &self.blocks {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                block.number,
                cell(block.rows()),
                grouped(block.gas_used),
                per_gas(block.rows(), block.gas_used)
            );
        }
        let _ = writeln!(
            out,
            "| **Total** | {} | {} | {} |",
            cell(self.total_rows),
            grouped(self.total_gas),
            per_gas(self.total_rows, self.total_gas)
        );
        let _ = writeln!(
            out,
            "\nCommit `{}`, block set `{}`, Jolt `{}`, guest ELF sha256 `{}` ({} bytes).",
            self.commit, self.block_set, self.jolt_rev, self.guest_elf_sha256, self.guest_elf_bytes
        );
        for block in &self.blocks {
            if let Outcome::Error(error) = &block.outcome {
                let _ = writeln!(out, "\nBlock {} failed: {error}", block.number);
            }
        }
        out
    }
}

/// Markdown table of `head` against `base`, block by block.
fn comparison(base: &Report, head: &Report) -> Result<String> {
    ensure!(
        base.block_set == head.block_set
            && base
                .blocks
                .iter()
                .map(|block| block.number)
                .eq(head.blocks.iter().map(|block| block.number)),
        "the two results cover different block sets"
    );
    let delta = |base: Option<u64>, head: Option<u64>| match (base, head) {
        (Some(base), Some(head)) => {
            let sign = if head < base { '-' } else { '+' };
            let percent = (head as f64 - base as f64) / base as f64 * 100.0;
            format!("{sign}{} | {percent:+.3}%", grouped(head.abs_diff(base)))
        }
        _ => "– | –".to_string(),
    };
    let mut out = "### Expanded cycles against base\n\n\
                   | Block | Base | Head | Δ | Δ % |\n|---|---:|---:|---:|---:|\n"
        .to_string();
    for (base, head) in base.blocks.iter().zip(&head.blocks) {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} |",
            base.number,
            cell(base.rows()),
            cell(head.rows()),
            delta(base.rows(), head.rows())
        );
    }
    let _ = writeln!(
        out,
        "| **Total** | {} | {} | {} |",
        cell(base.total_rows),
        cell(head.total_rows),
        delta(base.total_rows, head.total_rows)
    );
    let _ = writeln!(
        out,
        "\nGas-weighted cycles/gas over {} gas: base {}, head {}.",
        grouped(base.total_gas),
        per_gas(base.total_rows, base.total_gas),
        per_gas(head.total_rows, head.total_gas)
    );
    let _ = writeln!(out, "\nBase `{}`, head `{}`.", base.commit, head.commit);
    if base.guest_elf_sha256 == head.guest_elf_sha256 {
        let _ = writeln!(out, "\nBoth sides built the same guest ELF.");
    }
    if (&base.jolt_rev, &base.jolt_cli) != (&head.jolt_rev, &head.jolt_cli) {
        let _ = writeln!(
            out,
            "\n**Jolt differs between the sides:** base pins `{}` (CLI `{}`), head pins `{}` (CLI `{}`).",
            base.jolt_rev, base.jolt_cli, head.jolt_rev, head.jolt_cli
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(jolt_rev: &str, rows: [Option<u64>; 2]) -> Report {
        let blocks: Vec<_> = [(1, 100), (2, 300)]
            .into_iter()
            .zip(rows)
            .map(|((number, gas_used), rows)| BlockResult {
                number,
                gas_used,
                outcome: rows
                    .map_or_else(|| Outcome::Error("guest panicked".into()), Outcome::Rows),
            })
            .collect();
        Report {
            commit: format!("{jolt_rev}-commit"),
            jolt_rev: jolt_rev.into(),
            jolt_cli: "jolt 0.1.0".into(),
            guest_elf_sha256: jolt_rev.into(),
            guest_elf_bytes: 1,
            block_set: "set".into(),
            total_rows: blocks.iter().map(BlockResult::rows).sum(),
            total_gas: 400,
            blocks,
        }
    }

    #[test]
    fn manifest_pins_ten_consecutive_blocks() -> Result<()> {
        let manifest: Manifest = serde_json::from_str(MANIFEST)?;
        let numbers: Vec<_> = manifest.blocks.iter().map(|pin| pin.number).collect();
        assert_eq!(numbers.len(), 10);
        assert!(numbers.windows(2).all(|pair| pair[1] == pair[0] + 1));
        Ok(())
    }

    #[test]
    fn comparison_reports_deltas_totals_and_a_jolt_pin_change() -> Result<()> {
        let base = report("aaaa", [Some(1_000), Some(3_000)]);
        let head = report("bbbb", [Some(1_100), Some(2_400)]);
        assert_eq!(
            comparison(&base, &head)?,
            "### Expanded cycles against base\n\n\
             | Block | Base | Head | Δ | Δ % |\n|---|---:|---:|---:|---:|\n\
             | 1 | 1,000 | 1,100 | +100 | +10.000% |\n\
             | 2 | 3,000 | 2,400 | -600 | -20.000% |\n\
             | **Total** | 4,000 | 3,500 | -500 | -12.500% |\n\n\
             Gas-weighted cycles/gas over 400 gas: base 10.0000, head 8.7500.\n\n\
             Base `aaaa-commit`, head `bbbb-commit`.\n\n\
             **Jolt differs between the sides:** base pins `aaaa` (CLI `jolt 0.1.0`), \
             head pins `bbbb` (CLI `jolt 0.1.0`).\n"
        );
        Ok(())
    }

    #[test]
    fn a_failed_block_is_reported_without_a_total() -> Result<()> {
        let failed = report("aaaa", [Some(1_000), None]);
        assert_eq!(failed.total_rows, None);
        assert_eq!(
            serde_json::to_string(&failed.blocks[1])?,
            r#"{"number":2,"gas_used":300,"error":"guest panicked"}"#
        );
        let decoded: Report = serde_json::from_str(&serde_json::to_string(&failed)?)?;
        let table = comparison(&decoded, &report("aaaa", [Some(1_000), Some(3_000)]))?;
        assert!(table.contains("| 2 | failed | 3,000 | – | – |"));
        assert!(table.contains("| **Total** | failed | 4,000 | – | – |"));
        Ok(())
    }
}
