use sha3::{Digest, Keccak256};
use std::{
    env,
    error::Error,
    fs,
    io::{self, Write},
    path::PathBuf,
};

fn main() -> Result<(), Box<dyn Error>> {
    let mut output = io::stdout().lock();
    writeln!(output, "cargo:rerun-if-env-changed=JETH_CODE_LIBRARY")?;
    if env::var_os("CARGO_FEATURE_CODE_LIBRARY").is_none() {
        return Ok(());
    }

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("missing CARGO_MANIFEST_DIR")?);
    let library_dir = env::var_os("JETH_CODE_LIBRARY").map_or_else(
        || manifest_dir.join("../../library/production"),
        PathBuf::from,
    );
    let library_dir = library_dir.canonicalize().map_err(|error| {
        format!(
            "code library {} is unavailable: {error}; run `jeth library build`",
            library_dir.display()
        )
    })?;
    let manifest_path = library_dir.join("manifest.json");
    let index_path = library_dir.join("index.bin");
    let codes_path = library_dir.join("codes.bin");
    let jump_tables_path = library_dir.join("jt.bin");
    for path in [&manifest_path, &index_path, &codes_path, &jump_tables_path] {
        writeln!(output, "cargo:rerun-if-changed={}", path.display())?;
        assert!(
            path.is_file(),
            "missing code-library artifact {}",
            path.display()
        );
    }

    let manifest = fs::read_to_string(&manifest_path)?;
    let library_id = manifest
        .lines()
        .find_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            (key.trim_matches('"') == "library_id")
                .then(|| value.trim().trim_end_matches(',').trim_matches('"'))
        })
        .ok_or("manifest library_id missing")?;
    let library_id = library_id
        .strip_prefix("0x")
        .ok_or("manifest library_id must start with 0x")?;
    assert_eq!(library_id.len(), 64, "manifest library_id length");
    let mut id = [0u8; 32];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&library_id[2 * i..2 * i + 2], 16)?;
    }
    // The id is keccak(index ‖ codes ‖ jump tables), as `jeth library build`
    // writes it; a stale manifest must not bake edited artifacts under its id.
    let mut artifact = Vec::new();
    for path in [&index_path, &codes_path, &jump_tables_path] {
        artifact.extend(fs::read(path)?);
    }
    let mut computed = [0u8; 32];
    computed.copy_from_slice(&Keccak256::digest(&artifact));
    assert_eq!(
        computed, id,
        "manifest library_id does not match index.bin/codes.bin/jt.bin; run `jeth library build`"
    );

    let generated = format!(
        "#[repr(align(8))]\n\
         struct Aligned<const N: usize>([u8; N]);\n\
         static INDEX: Aligned<{{ include_bytes!({index:?}).len() }}> = Aligned(*include_bytes!({index:?}));\n\
         static CODES: Aligned<{{ include_bytes!({codes:?}).len() }}> = Aligned(*include_bytes!({codes:?}));\n\
         static JUMP_TABLES: Aligned<{{ include_bytes!({jump_tables:?}).len() }}> = Aligned(*include_bytes!({jump_tables:?}));\n\
         pub static LIBRARY_INDEX: &[u8] = &INDEX.0;\n\
         pub static LIBRARY_CODES: &[u8] = &CODES.0;\n\
         pub static LIBRARY_JUMP_TABLES: &[u8] = &JUMP_TABLES.0;\n\
         pub const LIBRARY_ID: [u8; 32] = {id:?};\n",
        index = index_path.to_string_lossy(),
        codes = codes_path.to_string_lossy(),
        jump_tables = jump_tables_path.to_string_lossy(),
    );
    let out =
        PathBuf::from(env::var_os("OUT_DIR").ok_or("missing OUT_DIR")?).join("code_library.rs");
    fs::write(out, generated)?;
    Ok(())
}
