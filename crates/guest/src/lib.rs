//! jeth guest: statelessly validate one Ethereum mainnet block inside Jolt.
//!
//! Sizing rationale (PLAN.md D6): input ~10–15 MB observed; decoded witness +
//! sparse trie + revm state for a ~29M-gas block needs high-hundreds-MB heap.
//! All guest addresses stay < 4 GiB (cycle-marker pointers truncate to u32).
//! KEEP IN SYNC with `GUEST_MEMORY` in `crates/host/src/trace.rs`.

#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use jeth_core::{BlockInput, ValidationResult};

/// Shared body: deserialize (measured), verify signatures, validate statelessly.
fn run_validation(bytes: &[u8]) -> ValidationResult {
    jolt::start_cycle_tracking("deserialize");
    let input: BlockInput = jolt::postcard::from_bytes(bytes).expect("input deserialization");
    jolt::end_cycle_tracking("deserialize");

    let BlockInput {
        block,
        signers,
        witness,
    } = input;

    // Phase 1: verify tx signatures against host-supplied pubkeys, derive senders.
    jolt::start_cycle_tracking("sig_verify");
    let recovered = jeth_core::recover_block(block, signers).expect("signature verification");
    jolt::end_cycle_tracking("sig_verify");

    // Phase 2: ancestor-chain checks, witness reveal vs parent state root, full tx
    // execution, post-execution consensus checks, post-state root == header root.
    jolt::start_cycle_tracking("validation");
    let result = jeth_core::validate_recovered(recovered, witness).expect("stateless validation");
    jolt::end_cycle_tracking("validation");

    result
}

/// Standard path: the postcard-encoded [`BlockInput`] arrives as committed input
/// (borrowed zero-copy from the input region; deserialize measured in-guest).
#[jolt::provable(
    max_input_size = 33554432,   // 32 MiB
    max_output_size = 4096,      // 4 KiB
    heap_size = 1610612736,      // 1.5 GiB (pow2-class allocator needs headroom; keeps addr space < 4 GiB)
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

/// alloy-primitives (feature "native-keccak") declares this extern and calls it for
/// every keccak256. Routes to the Jolt Keccak-f[1600] inline (opcode 0x0B).
#[cfg(feature = "guest")]
#[no_mangle]
pub unsafe extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8) {
    let data = core::slice::from_raw_parts(bytes, len);
    let digest = jolt_inlines_keccak256::Keccak256::digest(data);
    core::ptr::copy_nonoverlapping(digest.as_ptr(), output, 32);
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
