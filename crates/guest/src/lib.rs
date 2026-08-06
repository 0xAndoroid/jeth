//! jeth guest: statelessly validate one Ethereum mainnet block inside Jolt.
//!
//! Sizing rationale (PLAN.md D6): input ~10–15 MB observed; decoded witness +
//! sparse trie + revm state for a ~29M-gas block needs high-hundreds-MB heap.
//! All guest addresses stay < 4 GiB (cycle-marker pointers truncate to u32).
//! KEEP IN SYNC with `GUEST_MEMORY` in `crates/host/src/trace.rs`.

#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use jeth_core::{BlockInput, ValidationResult};

#[jolt::provable(
    max_input_size = 33554432,   // 32 MiB
    max_output_size = 4096,      // 4 KiB
    heap_size = 1073741824,      // 1 GiB
    stack_size = 33554432        // 32 MiB
)]
fn validate_block(input: BlockInput) -> ValidationResult {
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
