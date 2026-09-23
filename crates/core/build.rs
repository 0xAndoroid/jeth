use sha3::{Digest, Keccak256};
use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=JETH_CODE_LIBRARY");
    if env::var_os("CARGO_FEATURE_CODE_LIBRARY").is_none() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let library_dir = env::var_os("JETH_CODE_LIBRARY")
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.join("../../library/production"));
    let library_dir = library_dir.canonicalize().unwrap_or_else(|error| {
        panic!(
            "code library {} is unavailable: {error}; run `jeth library build`",
            library_dir.display()
        )
    });
    let manifest_path = library_dir.join("manifest.json");
    let index_path = library_dir.join("index.bin");
    let codes_path = library_dir.join("codes.bin");
    let jump_tables_path = library_dir.join("jt.bin");
    for path in [&manifest_path, &index_path, &codes_path, &jump_tables_path] {
        println!("cargo:rerun-if-changed={}", path.display());
        assert!(
            path.is_file(),
            "missing code-library artifact {}",
            path.display()
        );
    }

    let manifest = fs::read_to_string(&manifest_path).expect("reading code-library manifest");
    let library_id = manifest
        .lines()
        .find_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            (key.trim_matches('"') == "library_id")
                .then(|| value.trim().trim_end_matches(',').trim_matches('"'))
        })
        .expect("manifest library_id");
    let library_id = library_id
        .strip_prefix("0x")
        .expect("manifest library_id must start with 0x");
    assert_eq!(library_id.len(), 64, "manifest library_id length");
    let mut id = [0u8; 32];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&library_id[2 * i..2 * i + 2], 16).expect("manifest library_id hex");
    }
    // The id is keccak(index ‖ codes ‖ jump tables), as `jeth library build`
    // writes it; a stale manifest must not bake edited artifacts under its id.
    let mut artifact = Vec::new();
    for path in [&index_path, &codes_path, &jump_tables_path] {
        artifact.extend(fs::read(path).expect("reading code-library artifact"));
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
         static INDEX: Aligned<{index_len}> = Aligned(*include_bytes!({index:?}));\n\
         static CODES: Aligned<{codes_len}> = Aligned(*include_bytes!({codes:?}));\n\
         static JUMP_TABLES: Aligned<{jump_tables_len}> = Aligned(*include_bytes!({jump_tables:?}));\n\
         pub static LIBRARY_INDEX: &[u8] = &INDEX.0;\n\
         pub static LIBRARY_CODES: &[u8] = &CODES.0;\n\
         pub static LIBRARY_JUMP_TABLES: &[u8] = &JUMP_TABLES.0;\n\
         pub const LIBRARY_ID: [u8; 32] = {id:?};\n",
        index = index_path.to_string_lossy(),
        codes = codes_path.to_string_lossy(),
        jump_tables = jump_tables_path.to_string_lossy(),
        index_len = fs::metadata(&index_path).unwrap().len(),
        codes_len = fs::metadata(&codes_path).unwrap().len(),
        jump_tables_len = fs::metadata(&jump_tables_path).unwrap().len(),
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("code_library.rs");
    fs::write(out, generated).expect("writing code-library constants");
}
