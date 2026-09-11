//! Crate-local advice plumbing for the arena encoder.
//!
//! Same two-pass contract as jeth-core's `advice.rs` (the `compute_advice`
//! cfg must resolve in the DEFINING crate, so zeth-mpt carries its own copy):
//! pass 1 runs the body and writes the value to the byte-FIFO tape; the
//! proven ELF reads it back; native builds run the body directly. Every
//! consumed value is sealed locally at its consumption site.
//!
//! The tape intrinsics are not linked from here: on riscv64 the macros call
//! the `jeth_advice_*` hooks that jeth-core exports over the jolt SDK
//! (`crates/core/src/advice.rs`), so this crate has no dependency on a jolt
//! checkout and builds standalone.

#[cfg(target_arch = "riscv64")]
extern "C" {
    pub(super) fn jeth_advice_write_u64(value: u64);
    pub(super) fn jeth_advice_read_u64() -> u64;
    pub(super) fn jeth_advice_assert_eq_u64(left: u64, right: u64);
}

/// One u64 of untrusted advice; `$body` is compiled out of the proven ELF.
macro_rules! advice_u64 {
    ($body:expr) => {{
        #[cfg(all(target_arch = "riscv64", feature = "compute_advice"))]
        {
            let v: u64 = $body;
            // SAFETY: single-hart guest; the hook only appends to the tape.
            unsafe { $crate::mpt::advice::jeth_advice_write_u64(v) };
            v
        }
        #[cfg(all(target_arch = "riscv64", not(feature = "compute_advice")))]
        {
            // SAFETY: single-hart guest; the hook only reads the tape.
            unsafe { $crate::mpt::advice::jeth_advice_read_u64() }
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            $body
        }
    }};
}

/// 1-row `VirtualAssertEQ` on riscv64, `assert_eq!` natively.
macro_rules! advice_assert_eq {
    ($a:expr, $b:expr) => {{
        #[cfg(target_arch = "riscv64")]
        {
            // SAFETY: the hook is a pure assertion on two register values.
            unsafe { $crate::mpt::advice::jeth_advice_assert_eq_u64($a, $b) }
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            assert_eq!($a, $b)
        }
    }};
}

pub(super) use {advice_assert_eq, advice_u64};
