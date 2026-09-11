//! Hand-rolled untrusted-advice plumbing.
//!
//! Deliberately NOT `#[jolt::advice]`: the macro's proven-pass read goes
//! through the Pod `AdviceTapeIO` machinery (`new_from_advice_tape` →
//! `read_slice` alignment arithmetic); the resolver hot path wants the bare
//! `ADVICE_LD`. Semantics are identical — pass 1 (`compute_advice` feature)
//! runs the body and appends the value to the byte FIFO tape; the proven pass
//! skips the body and reads the tape in call order.
//!
//! Build matrix:
//! - riscv64 + `compute_advice` (pass-1 ELF): body runs, value written to tape.
//! - riscv64, no `compute_advice` (proven ELF): 1-row `ADVICE_LD` read.
//! - native (host / run-native gate): body runs directly, tape-free — the
//!   native gate exercises identical logic.
//!
//! Every consumed advice value MUST be locally verified at its consumption
//! site: the header state root is prover-chosen, so the final root comparison
//! verifies nothing about advice.

/// One u64 of untrusted advice. `$body` must be an expression evaluating to
/// `u64`; it is compiled OUT of the proven ELF entirely (so it may reference
/// pass-1-only state, e.g. a digest index map behind
/// `#[cfg(feature = "compute_advice")]`).
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

/// `check_advice_eq!` on riscv64 (1-row `VirtualAssertEQ`; failure panics the
/// tracer — honest-prover bug ⇒ crash, never an invalid proof), `assert_eq!`
/// natively. Both operands must fit in registers.
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

pub(crate) use {advice_assert_eq, advice_u64};

/// Tape hooks for the vendored zeth-mpt (`crates/vendor/zeth-mpt/src/mpt/advice.rs`),
/// which carries no jolt dependency of its own: the intrinsics the macros above
/// use, exported as C symbols and marked for inlining so LTO can fold them into
/// the zeth-mpt call sites. Gated like the macros, so a compute/proven feature
/// mismatch between the two crates fails to link instead of misreading the tape.
#[cfg(target_arch = "riscv64")]
mod hooks {
    #[cfg(feature = "compute_advice")]
    #[no_mangle]
    #[inline(always)]
    pub extern "C" fn jeth_advice_write_u64(value: u64) {
        jolt::AdviceWriter::get().write_u64(value);
    }

    #[cfg(not(feature = "compute_advice"))]
    #[no_mangle]
    #[inline(always)]
    pub extern "C" fn jeth_advice_read_u64() -> u64 {
        jolt::AdviceReader::get().read_u64()
    }

    #[no_mangle]
    #[inline(always)]
    pub extern "C" fn jeth_advice_assert_eq_u64(left: u64, right: u64) {
        jolt::check_advice_eq!(left, right)
    }
}

/// Tape-alignment sentinel — the first advice value of every run (~6 proven
/// rows). Turns "forgot to thread the tape / mismatched ELF pair" into an
/// instant, unambiguous panic instead of a misaligned-tape heisenbug later.
pub fn advice_smoke() {
    const SENTINEL: u64 = 0x6a65_7468_6164_7631; // "jethadv1"
    let v = advice_u64!(SENTINEL);
    advice_assert_eq!(v, SENTINEL);
}
