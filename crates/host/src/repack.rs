use anyhow::{Context, Result};
use jeth_core::ExecutionWitness;
use reth_ethereum_primitives::Block;

pub fn run(dir: &str, library_manifest: &str) -> Result<()> {
    let dir = std::path::Path::new(dir);
    let mut witness: ExecutionWitness = serde_json::from_slice(
        &std::fs::read(dir.join("witness.json")).context("reading witness.json")?,
    )
    .context("decoding witness.json")?;

    let block_rlp = std::fs::read(dir.join("block.rlp")).context("reading block.rlp")?;
    let block: Block = alloy_rlp::decode_exact(&block_rlp)
        .map_err(|error| anyhow::anyhow!("decoding block.rlp: {error}"))?;
    let signers = crate::fetch::recover_signers(&block.body.transactions)?;
    let (library_id, coverage) = crate::library::filter_witness(&mut witness, library_manifest)?;
    let input = jeth_core::container::ContainerWriter::write(
        &block_rlp,
        &signers,
        &witness,
        crate::trace::stream_start(crate::trace::Variant::Input),
        u64::from_le_bytes(library_id[..8].try_into().unwrap()),
    )
    .map_err(anyhow::Error::msg)?;

    std::fs::write(dir.join("input.bin"), &input)?;
    update_meta(dir, input.len(), library_manifest, &library_id, coverage)?;
    println!(
        "repacked block {}: {} state, {} codes, {} headers → {} bytes",
        block.header.number,
        witness.state.len(),
        witness.codes.len(),
        witness.headers.len(),
        input.len()
    );
    Ok(())
}

fn update_meta(
    dir: &std::path::Path,
    input_len: usize,
    library_manifest: &str,
    library_id: &[u8; 32],
    coverage: crate::library::Coverage,
) -> Result<()> {
    let path = dir.join("meta.json");
    let mut meta: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    meta["format"] = 2.into();
    meta["input_bin_bytes"] = input_len.into();
    meta["code_library"] = serde_json::json!({
        "manifest": library_manifest,
        "library_id": format!("0x{}", alloy_primitives::hex::encode(library_id)),
        "coverage": coverage,
    });
    std::fs::write(path, serde_json::to_string_pretty(&meta)?)?;
    Ok(())
}
