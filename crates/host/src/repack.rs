use anyhow::{Context, Result};
use jeth_core::ExecutionWitness;
use reth_ethereum_primitives::Block;

pub fn run(dir: &str) -> Result<()> {
    let dir = std::path::Path::new(dir);
    let witness: ExecutionWitness = serde_json::from_slice(
        &std::fs::read(dir.join("witness.json")).context("reading witness.json")?,
    )
    .context("decoding witness.json")?;

    let block_rlp = std::fs::read(dir.join("block.rlp")).context("reading block.rlp")?;
    let block: Block = alloy_rlp::decode_exact(&block_rlp)
        .map_err(|error| anyhow::anyhow!("decoding block.rlp: {error}"))?;
    let signers = crate::fetch::recover_signers(&block.body.transactions)?;
    let input = jeth_core::container::ContainerWriter::write(
        &block_rlp,
        &signers,
        &witness,
        crate::trace::stream_start(crate::trace::Variant::Input),
        0,
    )
    .map_err(anyhow::Error::msg)?;

    std::fs::write(dir.join("block.rlp"), &block_rlp)?;
    std::fs::write(dir.join("input.bin"), &input)?;
    update_meta(dir, input.len())?;
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

fn update_meta(dir: &std::path::Path, input_len: usize) -> Result<()> {
    let path = dir.join("meta.json");
    let mut meta: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
    meta["format"] = 2.into();
    meta["input_bin_bytes"] = input_len.into();
    std::fs::write(path, serde_json::to_string_pretty(&meta)?)?;
    Ok(())
}
