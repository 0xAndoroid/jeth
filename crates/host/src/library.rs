use alloy_primitives::{keccak256, Bytes, B256};
use anyhow::{Context, Result};
use jeth_core::{
    code_library::{
        LibraryView, CODE_LEN_OFFSET, CODE_OFFSET_OFFSET, HASH_OFFSET, INDEX_HEADER_SIZE,
        INDEX_MAGIC, INDEX_RECORD_SIZE, INDEX_VERSION, JT_BIT_LEN_OFFSET, JT_LEN_OFFSET,
        JT_OFFSET_OFFSET, KIND_EIP7702, KIND_LEGACY, KIND_OFFSET, ORIGINAL_LEN_OFFSET,
    },
    ExecutionWitness,
};
use revm_bytecode::{Bytecode, BytecodeKind};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const DEFAULT_MANIFEST: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../library/dev/manifest.json"
);

#[derive(Clone)]
struct Candidate {
    code: Bytes,
    block_frequency: usize,
    witness_occurrences: usize,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Coverage {
    pub codes_total: usize,
    pub codes_covered: usize,
    pub code_bytes_total: usize,
    pub code_bytes_covered: usize,
    pub keccak_perms_total: u64,
    pub keccak_perms_covered: u64,
}

impl Coverage {
    pub fn code_percent(self) -> f64 {
        percent(self.codes_covered as u64, self.codes_total as u64)
    }

    pub fn perm_percent(self) -> f64 {
        percent(self.keccak_perms_covered, self.keccak_perms_total)
    }
}

#[derive(Serialize)]
struct Manifest {
    format: u32,
    library_id: String,
    source_blocks: Vec<u64>,
    entry_count: usize,
    original_code_bytes: usize,
    analyzed_code_bytes: usize,
    jump_table_bytes: usize,
    index_bytes: usize,
    top_n: Option<usize>,
}

pub struct LoadedLibrary {
    pub id: [u8; 32],
    hashes: BTreeSet<B256>,
}

impl LoadedLibrary {
    pub fn load(manifest_path: &str) -> Result<Self> {
        let manifest_path = Path::new(manifest_path);
        let dir = if manifest_path.is_dir() {
            manifest_path
        } else {
            manifest_path
                .parent()
                .context("code-library manifest has no parent")?
        };
        let manifest_path = if manifest_path.is_dir() {
            dir.join("manifest.json")
        } else {
            manifest_path.to_path_buf()
        };
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&manifest_path)
                .with_context(|| format!("reading {}", manifest_path.display()))?,
        )?;
        let expected_id = parse_id(
            manifest["library_id"]
                .as_str()
                .context("manifest library_id")?,
        )?;
        let index = std::fs::read(dir.join("index.bin"))?;
        let codes = std::fs::read(dir.join("codes.bin"))?;
        let jump_tables = std::fs::read(dir.join("jt.bin"))?;
        let actual_id = artifact_id(&index, &codes, &jump_tables);
        anyhow::ensure!(actual_id == expected_id, "code-library id mismatch");
        let view = LibraryView::new(&index, &codes, &jump_tables)
            .map_err(|error| anyhow::anyhow!("invalid code library: {error:?}"))?;
        view.validate()
            .map_err(|error| anyhow::anyhow!("invalid code library: {error:?}"))?;
        let hashes = (0..view.len())
            .map(|index| {
                view.entry(index)
                    .map(|entry| B256::from(*entry.hash))
                    .map_err(|error| anyhow::anyhow!("invalid code-library entry: {error:?}"))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            id: expected_id,
            hashes,
        })
    }

    pub fn filter(&self, codes: &mut Vec<Bytes>) -> Coverage {
        let mut coverage = Coverage {
            codes_total: codes.len(),
            codes_covered: 0,
            code_bytes_total: 0,
            code_bytes_covered: 0,
            keccak_perms_total: 0,
            keccak_perms_covered: 0,
        };
        codes.retain(|code| {
            let bytes = code.len();
            let perms = code_keccak_perms(bytes);
            coverage.code_bytes_total += bytes;
            coverage.keccak_perms_total += perms;
            if self.hashes.contains(&keccak256(code)) {
                coverage.codes_covered += 1;
                coverage.code_bytes_covered += bytes;
                coverage.keccak_perms_covered += perms;
                false
            } else {
                true
            }
        });
        coverage
    }
}

pub fn build(block_dirs: &[String], top_n: Option<usize>, out: &str) -> Result<()> {
    anyhow::ensure!(
        !block_dirs.is_empty(),
        "--blocks requires at least one directory"
    );
    let mut candidates = BTreeMap::<B256, Candidate>::new();
    let mut source_blocks = Vec::with_capacity(block_dirs.len());
    for block_dir in block_dirs {
        let dir = Path::new(block_dir);
        let witness: ExecutionWitness = serde_json::from_slice(
            &std::fs::read(dir.join("witness.json"))
                .with_context(|| format!("reading {}/witness.json", dir.display()))?,
        )?;
        let block: reth_ethereum_primitives::Block =
            alloy_rlp::decode_exact(&std::fs::read(dir.join("block.rlp"))?).map_err(|error| {
                anyhow::anyhow!("decoding {}/block.rlp: {error}", dir.display())
            })?;
        source_blocks.push(block.header.number);
        let mut seen = BTreeSet::new();
        for code in witness.codes {
            let hash = keccak256(&code);
            let entry = candidates.entry(hash).or_insert_with(|| Candidate {
                code: code.clone(),
                block_frequency: 0,
                witness_occurrences: 0,
            });
            anyhow::ensure!(entry.code == code, "code hash collision for {hash}");
            entry.witness_occurrences += 1;
            if seen.insert(hash) {
                entry.block_frequency += 1;
            }
        }
    }

    let mut selected: Vec<_> = candidates.into_iter().collect();
    selected.sort_by(|(hash_a, a), (hash_b, b)| {
        b.block_frequency
            .cmp(&a.block_frequency)
            .then_with(|| b.witness_occurrences.cmp(&a.witness_occurrences))
            .then_with(|| hash_a.cmp(hash_b))
    });
    if let Some(limit) = top_n {
        selected.truncate(limit);
    }
    selected.sort_by_key(|(hash, _)| *hash);

    let mut index = vec![0; INDEX_HEADER_SIZE];
    index[0..4].copy_from_slice(&INDEX_MAGIC.to_le_bytes());
    index[4..6].copy_from_slice(&INDEX_VERSION.to_le_bytes());
    index[6..8].copy_from_slice(&(INDEX_RECORD_SIZE as u16).to_le_bytes());
    put_u32(&mut index, 8, selected.len())?;
    let mut codes = Vec::new();
    let mut jump_tables = Vec::new();
    let mut original_code_bytes = 0usize;

    for (hash, candidate) in &selected {
        align(&mut codes);
        align(&mut jump_tables);
        let analyzed = Bytecode::new_raw(candidate.code.clone());
        let code_offset = codes.len();
        codes.extend_from_slice(analyzed.bytes_slice());
        let jump_table_offset = jump_tables.len();
        let (jump_table_len, jump_table_bit_len, kind) = match analyzed.kind() {
            BytecodeKind::LegacyAnalyzed => {
                let jump_table = analyzed.legacy_jump_table().unwrap();
                jump_tables.extend_from_slice(jump_table.as_slice());
                (jump_table.as_slice().len(), jump_table.len(), KIND_LEGACY)
            }
            BytecodeKind::Eip7702 => (0, 0, KIND_EIP7702),
        };
        original_code_bytes += candidate.code.len();

        let mut record = vec![0; INDEX_RECORD_SIZE];
        record[HASH_OFFSET..HASH_OFFSET + 32].copy_from_slice(hash.as_slice());
        put_u32(&mut record, CODE_OFFSET_OFFSET, code_offset)?;
        put_u32(&mut record, CODE_LEN_OFFSET, analyzed.bytes_slice().len())?;
        put_u32(&mut record, ORIGINAL_LEN_OFFSET, analyzed.len())?;
        put_u32(&mut record, JT_OFFSET_OFFSET, jump_table_offset)?;
        put_u32(&mut record, JT_LEN_OFFSET, jump_table_len)?;
        put_u32(&mut record, JT_BIT_LEN_OFFSET, jump_table_bit_len)?;
        put_u32(&mut record, KIND_OFFSET, kind as usize)?;
        index.extend_from_slice(&record);
    }

    let id = artifact_id(&index, &codes, &jump_tables);
    let manifest = Manifest {
        format: 1,
        library_id: format!("0x{}", alloy_primitives::hex::encode(id)),
        source_blocks,
        entry_count: selected.len(),
        original_code_bytes,
        analyzed_code_bytes: codes.len(),
        jump_table_bytes: jump_tables.len(),
        index_bytes: index.len(),
        top_n,
    };
    let out = PathBuf::from(out);
    std::fs::create_dir_all(&out)?;
    std::fs::write(out.join("index.bin"), &index)?;
    std::fs::write(out.join("codes.bin"), &codes)?;
    std::fs::write(out.join("jt.bin"), &jump_tables)?;
    std::fs::write(
        out.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;
    println!(
        "library: {} entries, {:.1} MB code, {:.1} MB jump tables, id {}",
        selected.len(),
        codes.len() as f64 / 1e6,
        jump_tables.len() as f64 / 1e6,
        manifest.library_id
    );
    println!("wrote {}", out.display());
    Ok(())
}

pub fn filter_witness(
    witness: &mut ExecutionWitness,
    manifest_path: &str,
) -> Result<([u8; 32], Coverage)> {
    let library = LoadedLibrary::load(manifest_path)?;
    let coverage = library.filter(&mut witness.codes);
    println!(
        "code library: {}/{} codes ({:.1}%), {}/{} keccak perms ({:.1}%), {} misses",
        coverage.codes_covered,
        coverage.codes_total,
        coverage.code_percent(),
        coverage.keccak_perms_covered,
        coverage.keccak_perms_total,
        coverage.perm_percent(),
        witness.codes.len(),
    );
    Ok((library.id, coverage))
}

fn artifact_id(index: &[u8], codes: &[u8], jump_tables: &[u8]) -> [u8; 32] {
    let mut artifact = Vec::with_capacity(index.len() + codes.len() + jump_tables.len());
    artifact.extend_from_slice(index);
    artifact.extend_from_slice(codes);
    artifact.extend_from_slice(jump_tables);
    keccak256(artifact).into()
}

fn parse_id(value: &str) -> Result<[u8; 32]> {
    let value = value.strip_prefix("0x").context("library id prefix")?;
    anyhow::ensure!(value.len() == 64, "library id length");
    let mut id = [0; 32];
    alloy_primitives::hex::decode_to_slice(value, &mut id).context("library id hex")?;
    Ok(id)
}

fn align(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.len().next_multiple_of(8), 0);
}

fn put_u32(bytes: &mut [u8], offset: usize, value: usize) -> Result<()> {
    let value = u32::try_from(value).context("code-library artifact exceeds u32")?;
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn code_keccak_perms(len: usize) -> u64 {
    len as u64 / 136 + 1
}

fn percent(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 * 100.0 / denominator as f64
    }
}
