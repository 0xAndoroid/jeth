//! Compiles the guest shims natively so their differential tests run.
//! See `Cargo.toml` for the command.
#![allow(dead_code)]

extern crate alloc;

#[cfg(feature = "keccak-prefix-cache")]
#[path = "../../../core/src/keccak_prefix_params.rs"]
mod keccak_prefix_params;
#[cfg(feature = "keccak-prefix-cache")]
#[path = "../../../core/src/prefix_plan.rs"]
mod prefix_plan;

#[path = "../../src/keccak.rs"]
mod keccak;
#[path = "../../src/mem.rs"]
mod mem;
