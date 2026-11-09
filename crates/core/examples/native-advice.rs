//! Generate a FIFO advice tape for the ordinary, code-library-enabled guest.
//!
//! Run one block per process. Match the guest's source revision, dependency
//! versions, and features; a tape is not portable across arbitrary guest builds.
//! The proven guest still checks every hint. This example does not support the
//! trusted-digest guest or optional guest features such as lazy analysis.

use std::{env, error::Error, fmt::Write, fs, time::Instant};

#[expect(
    clippy::print_stdout,
    reason = "CLI reports the generated tape and block"
)]
fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args_os().skip(1);
    let usage = "usage: native-advice INPUT_JEF OUTPUT_TAPE";
    let input_path = args.next().ok_or(usage)?;
    let output_path = args.next().ok_or(usage)?;
    if args.next().is_some() {
        return Err(usage.into());
    }

    // JEF alignment includes the postcard slice-length prefix, just as in the
    // guest input region. This one-shot command retains the allocation until exit.
    let raw = fs::read(input_path)?;
    let stream: &'static [u8] = Box::leak(postcard::to_stdvec(&raw)?.into_boxed_slice());
    let bytes: &'static [u8] = postcard::from_bytes(stream)?;
    let start = Instant::now();
    let (result, tape) = jeth_core::advice::native::record(|| {
        jeth_core::advice::advice_smoke();
        if !jeth_core::install_jolt_crypto() {
            return Err("crypto provider installation failed".into());
        }
        let input = jeth_core::decode_container(bytes).map_err(|error| format!("{error:?}"))?;
        let recovered = jeth_core::recover_block(input.block, input.signers)
            .map_err(|error| format!("{error:?}"))?;
        jeth_core::validate_recovered(recovered, input.witness)
            .map_err(|error| format!("{error:?}"))
    })?;
    let result = result?;
    let elapsed = start.elapsed();
    fs::write(output_path, &tape)?;
    let mut hash = String::with_capacity(64);
    for byte in result.block_hash {
        write!(hash, "{byte:02x}")?;
    }
    println!(
        "{} advice bytes in {elapsed:?}; block 0x{hash}, gas {}",
        tape.len(),
        result.gas_used
    );
    Ok(())
}
