//! Hand-rolled untrusted-advice plumbing (advice-trie campaign, Phase 0).
//!
//! Deliberately NOT `#[jolt::advice]`: the macro's proven-pass read goes
//! through the Pod `AdviceTapeIO` machinery (`new_from_advice_tape` →
//! `read_slice` alignment arithmetic, ~5–15 rows/call); the resolver hot path
//! wants the bare 1-row `ADVICE_LD`. Semantics are identical — pass 1
//! (`compute_advice` feature) runs the body and appends the value to the byte
//! FIFO tape; the proven pass skips the body and reads the tape in call order.
//!
//! Build matrix:
//! - riscv64 + `compute_advice` (pass-1 ELF): body runs, value written to tape.
//! - riscv64, no `compute_advice` (proven ELF): 1-row `ADVICE_LD` read.
//! - native (host / run-native gate): body runs directly, tape-free — the
//!   native gate exercises identical logic (spec §3 native split).
//!
//! Every consumed advice value MUST be locally verified at its consumption
//! site (design law L2): the header state root is prover-chosen, so the final
//! root comparison verifies nothing about advice.

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

/// `check_advice!` on riscv64 (~2–4 rows), `assert!` natively.
#[allow(unused_macros)] // consumed from Phase 1a (resolver bounds checks)
macro_rules! advice_assert {
    ($cond:expr) => {{
        #[cfg(target_arch = "riscv64")]
        {
            jolt::check_advice!($cond)
        }
        #[cfg(not(target_arch = "riscv64"))]
        {
            assert!($cond)
        }
    }};
}

#[allow(unused_imports)] // advice_assert consumed from Phase 1a
pub(crate) use {advice_assert, advice_assert_eq, advice_u64};

/// Tape-alignment sentinel — the first advice value of every run (~6 proven
/// rows). Turns "forgot to thread the tape / mismatched ELF pair" into an
/// instant, unambiguous panic instead of a misaligned-tape heisenbug later.
pub fn advice_smoke() {
    const SENTINEL: u64 = 0x6a65_7468_6164_7631; // "jethadv1"
    let v = advice_u64!(SENTINEL);
    advice_assert_eq!(v, SENTINEL);
}
