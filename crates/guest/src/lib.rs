//! jeth guest: statelessly validate one Ethereum mainnet block inside Jolt.
//!
//! Sizing rationale (PLAN.md D6): input ~10–15 MB observed; decoded witness +
//! sparse trie + revm state for a ~29M-gas block needs high-hundreds-MB heap.
//! All guest addresses stay < 4 GiB (cycle-marker pointers truncate to u32).
//! KEEP IN SYNC with `GUEST_MEMORY` in `crates/host/src/trace.rs`.

#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

// Guest-only shims. Their native differential tests live in the standalone
// `native-tests` crate (`cargo test --manifest-path
// crates/guest/native-tests/Cargo.toml`), which includes these files by path.
#[cfg(feature = "guest")]
mod keccak;
#[cfg(feature = "guest")]
mod mem;

use jeth_core::{BlockInput, ValidationResult};

/// Print keccak counters with a phase label (census builds only).
#[cfg(all(feature = "guest", feature = "keccak-census"))]
fn keccak_stats(label: &str) {
    unsafe {
        jolt::println!(
            "keccak[{}]: calls={} bytes={} perms={} unaligned={}",
            label,
            KECCAK_CALLS,
            KECCAK_BYTES,
            KECCAK_PERMS,
            KECCAK_UNALIGNED
        );
    }
}
#[cfg(not(all(feature = "guest", feature = "keccak-census")))]
fn keccak_stats(_label: &str) {}

/// Shared body: read JEF (measured), verify signatures, validate statelessly.
fn run_validation(bytes: &[u8]) -> ValidationResult {
    // Advice-tape alignment sentinel: panics immediately on a missing tape or
    // mismatched compute/proven ELF pair (~6 rows).
    jeth_core::advice::advice_smoke();

    // Route the EVM ecrecover precompile through the secp256k1 inline.
    jeth_core::install_jolt_crypto();

    jolt::start_cycle_tracking("deserialize");
    // The input region is immutable and remains mapped for the whole program.
    let bytes: &'static [u8] = unsafe { core::mem::transmute(bytes) };
    let input: BlockInput = jeth_core::decode_container(bytes).expect("JEF input");
    jolt::end_cycle_tracking("deserialize");

    let BlockInput {
        block,
        signers,
        witness,
    } = input;

    // Phase 1: verify tx signatures against host-supplied pubkeys, derive senders.
    keccak_stats("pre_sig");
    jolt::start_cycle_tracking("sig_verify");
    let recovered = jeth_core::recover_block(block, signers).expect("signature verification");
    jolt::end_cycle_tracking("sig_verify");
    keccak_stats("post_sig");

    // Phase 2: ancestor-chain checks, witness reveal vs parent state root, full tx
    // execution, post-execution consensus checks, post-state root == header root.
    jolt::start_cycle_tracking("validation");
    let result = jeth_core::validate_recovered(recovered, witness).expect("stateless validation");
    jolt::end_cycle_tracking("validation");
    keccak_stats("post_validation");

    result
}

/// Standard path: JEF arrives as committed input, borrowed from the input region.
#[jolt::provable(
    max_input_size = 33554432,   // 32 MiB
    max_output_size = 4096,      // 4 KiB
    heap_size = 1610612736,      // 1.5 GiB (bump allocator never frees: peak = total allocated; keeps addr space < 4 GiB)
    stack_size = 33554432        // 32 MiB
)]
fn validate_block(input: &[u8]) -> ValidationResult {
    run_validation(input)
}

/// Advice path: the same bytes arrive as TRUSTED ADVICE instead of committed
/// input. Prover-side this skips input commitment costs; soundness is unaffected
/// for the witness because the guest verifies it against the parent state root
/// (and the block/pubkeys against the header hash + signatures) regardless of
/// which stream carried the bytes.
#[jolt::provable(
    max_input_size = 4096,
    max_output_size = 4096,
    max_trusted_advice_size = 33554432, // 32 MiB
    heap_size = 1610612736,
    stack_size = 33554432
)]
fn validate_block_advice(input: jolt::TrustedAdvice<&[u8]>) -> ValidationResult {
    run_validation(*input)
}

/// Trusted-digest path: pre-computed witness-node keccaks + code hashes arrive
/// as TRUSTED ADVICE, so the reveal phase skips hashing the witness entirely.
///
/// SOUNDNESS CAVEAT: the digest map is verifier-trusted, per Jolt's trusted
/// advice semantics. The proof statement weakens to "this block is valid GIVEN
/// this node-digest map" — use when the verifier independently has the witness.
///
/// Blob layout: u32 LE state-digest count, then that many 32-byte digests,
/// then 32-byte code hashes for every witness code entry.
#[jolt::provable(
    max_input_size = 33554432,          // 32 MiB
    max_output_size = 4096,
    max_trusted_advice_size = 4194304,  // 4 MiB (52k digests ≈ 1.7 MB observed)
    heap_size = 1610612736,
    stack_size = 33554432
)]
fn validate_block_trusted(input: &[u8], digests: jolt::TrustedAdvice<&[u8]>) -> ValidationResult {
    let blob: &[u8] = *digests;
    let pad_len = *blob.first().expect("digest alignment prefix") as usize;
    assert!(pad_len <= 7, "digest alignment prefix");
    let content = &blob[1 + pad_len..];
    assert!(
        content.len() >= 4 && (content.len() - 4) % 32 == 0,
        "digest blob shape"
    );
    assert_eq!(content.as_ptr() as usize % 4, 0, "digest count alignment");
    assert_eq!(content[4..].as_ptr() as usize % 8, 0, "digest alignment");
    let state_count = u32::from_le_bytes(content[..4].try_into().unwrap()) as usize;
    let entries = (content.len() - 4) / 32;
    assert!(state_count <= entries, "digest blob count");
    let all: &[[u8; 32]] =
        unsafe { core::slice::from_raw_parts(content[4..].as_ptr().cast(), entries) };
    let (state_digests, code_hashes) = all.split_at(state_count);
    // The advice region lives for the whole program run.
    let (state_digests, code_hashes): (&'static [[u8; 32]], &'static [[u8; 32]]) = unsafe {
        (
            core::mem::transmute(state_digests),
            core::mem::transmute(code_hashes),
        )
    };
    jeth_core::set_trusted_digests(state_digests, code_hashes);

    run_validation(input)
}

/// Keccak accounting (census builds only): calls, input bytes, Keccak-f
/// permutations (rate 136), and calls whose input pointer is not 8-aligned
/// (they take the shift/or gather path in `keccak.rs`).
#[cfg(all(feature = "guest", feature = "keccak-census"))]
pub static mut KECCAK_CALLS: u64 = 0;
#[cfg(all(feature = "guest", feature = "keccak-census"))]
pub static mut KECCAK_BYTES: u64 = 0;
#[cfg(all(feature = "guest", feature = "keccak-census"))]
pub static mut KECCAK_PERMS: u64 = 0;
#[cfg(all(feature = "guest", feature = "keccak-census"))]
pub static mut KECCAK_UNALIGNED: u64 = 0;

/// alloy-primitives (feature "native-keccak") declares this extern and calls it
/// for every keccak256. Routes to the Jolt Keccak-f[1600] inlines (opcode 0x0B);
/// the word-wise sponge driver lives in `keccak.rs`.
///
/// `#[inline(never)]`: keeps the shim one out-of-line body. Its misaligned
/// digest store is a five-word read-modify-write of the caller's `[u8; 32]`
/// neighbourhood; inlined into a caller whose surrounding stores LTO can see,
/// that RMW would become a fusion candidate instead of the volatile sequence
/// the containing-word argument in `keccak.rs` is made for.
#[cfg(feature = "guest")]
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8) {
    #[cfg(feature = "keccak-census")]
    {
        KECCAK_CALLS += 1;
        KECCAK_BYTES += len as u64;
        KECCAK_PERMS += (len / 136) as u64 + 1;
        KECCAK_UNALIGNED += (bytes as usize & 7 != 0) as u64;
    }
    keccak::keccak256_into(bytes, len, output);
}

/// Phase hooks for jeth-core's instrumented trie: forward to jolt cycle markers
/// and checkpoint the keccak counters. Label pointers are 'static (marker keys).
///
/// `#[inline(never)]`: the profiler's `--split-markers` mode tracks the active
/// marker by watching these functions' entry PCs — LTO must not inline them.
#[cfg(feature = "guest")]
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn jeth_phase_start(ptr: *const u8, len: usize) {
    let label = core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len));
    keccak_stats(label);
    jolt::start_cycle_tracking(label);
}

#[cfg(feature = "guest")]
#[no_mangle]
#[inline(never)]
pub unsafe extern "C" fn jeth_phase_end(ptr: *const u8, len: usize) {
    let label = core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len));
    jolt::end_cycle_tracking(label);
    keccak_stats(label);
}

/// Hook for the vendored alloy-eip7702: EIP-7702 authority recovery through the
/// Jolt secp256k1 inline (same routine as the ecrecover precompile override).
/// Returns 1 and writes keccak(pubkey) to `out` (32 bytes) on success, 0 on
/// recovery failure.
#[cfg(feature = "guest")]
#[no_mangle]
pub unsafe extern "C" fn jeth_ecrecover_prehash(
    sig: *const u8,
    recid: u8,
    msg: *const u8,
    out: *mut u8,
) -> u8 {
    let sig: &[u8; 64] = &*(sig as *const [u8; 64]);
    let msg: &[u8; 32] = &*(msg as *const [u8; 32]);
    match jeth_core::inline_ecrecover(sig, recid, msg) {
        Some(hash) => {
            core::ptr::copy_nonoverlapping(hash.as_ptr(), out, 32);
            1
        }
        None => 0,
    }
}

/// Hook for the vendored revm-interpreter's MULMOD: `(a * b) % m` through the
/// Jolt BIGINT256_MUL inline, remainder written over `m` (the top-of-stack
/// word). Zero when `m` is zero. Unconditional because Cargo.toml enables the
/// interpreter's `bigint-inline` feature (which emits the extern declaration)
/// in every configuration of this crate.
#[no_mangle]
pub unsafe extern "C" fn jeth_mul_mod(a: *const u64, b: *const u64, m: *mut u64) {
    use alloy_primitives::U256;
    jeth_core::bigint::mul_mod(
        &*(a as *const U256),
        &*(b as *const U256),
        &mut *(m as *mut U256),
    );
}

/// `once_cell`'s critical-section backend (via reth-primitives-traits) needs a
/// [`critical_section::Impl`]. The Jolt guest is a single hart with no interrupts,
/// so acquire/release are no-ops.
#[cfg(feature = "guest")]
mod cs {
    struct SingleHartCriticalSection;
    critical_section::set_impl!(SingleHartCriticalSection);

    unsafe impl critical_section::Impl for SingleHartCriticalSection {
        unsafe fn acquire() -> critical_section::RawRestoreState {}
        unsafe fn release(_: critical_section::RawRestoreState) {}
    }
}
