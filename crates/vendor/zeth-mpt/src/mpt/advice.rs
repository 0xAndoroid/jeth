//! Crate-local advice plumbing for the arena encoder (advice-trie Phase 3a).
//!
//! Same two-pass contract as jeth-core's `advice.rs` (the `compute_advice`
//! cfg must resolve in the DEFINING crate, so zeth-mpt carries its own copy):
//! pass 1 runs the body and writes the value to the byte-FIFO tape; the
//! proven ELF reads it back (1-row `ADVICE_LD`); native builds run the body
//! directly. Every consumed value is sealed locally (L2).

/// One u64 of untrusted advice; `$body` is compiled out of the proven ELF.
macro_rules! advice_u64 {
    ($body:expr) => {{
        #[cfg(all(target_arch = "riscv64", feature = "compute_advice"))]
        {
            let v: u64 = $body;
            jolt::AdviceWriter::get().write_u64(v);
            v
        }
        #[cfg(all(target_arch = "riscv64", not(feature = "compute_advice")))]
        {
            jolt::AdviceReader::get().read_u64()
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
            jolt::check_advice_eq!($a, $b)
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            assert_eq!($a, $b)
        }
    }};
}

pub(super) use {advice_assert_eq, advice_u64};
