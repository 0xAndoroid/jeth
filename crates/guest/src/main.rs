//! Guest entry point stub — the `#[jolt::provable]` macro in lib.rs generates
//! the actual `main` for the guest build.

#![cfg_attr(feature = "guest", no_std)]
#![no_main]

#[allow(unused_imports)]
use jeth_guest::*;
