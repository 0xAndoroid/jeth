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
//! - native: body runs directly. With `native-advice`, an explicit recording
//!   scope also collects the words; otherwise execution remains tape-free.
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
            let value: u64 = $body;
            #[cfg(feature = "native-advice")]
            $crate::advice::native::write_word(value);
            value
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

#[cfg(all(feature = "native-advice", not(target_arch = "riscv64")))]
pub mod native {
    //! Collect the native execution's untrusted advice in guest FIFO order.
    //! Outside a recording scope, native execution remains tape-free.
    extern crate std;
    use alloc::vec::Vec;
    use core::cell::RefCell;

    std::thread_local! {
        static TAPE: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
    }

    struct Reset;

    impl Drop for Reset {
        fn drop(&mut self) {
            TAPE.with_borrow_mut(|slot| *slot = None);
        }
    }

    /// Record one execution on this thread. Reject nesting and discard partial
    /// advice if the closure unwinds. The proven guest must check every word.
    pub fn record<T>(run: impl FnOnce() -> T) -> Result<(T, Vec<u8>), &'static str> {
        TAPE.with_borrow_mut(|slot| {
            if slot.is_some() {
                return Err("native advice recording cannot be nested");
            }
            *slot = Some(Vec::new());
            Ok(())
        })?;
        let _reset = Reset;
        let result = run();
        let tape = TAPE
            .with_borrow_mut(Option::take)
            .ok_or("native advice recording scope was lost")?;
        Ok((result, tape))
    }

    pub(crate) fn write_word(value: u64) {
        TAPE.with_borrow_mut(|slot| {
            if let Some(tape) = slot {
                tape.extend_from_slice(&value.to_le_bytes());
            }
        });
    }

    #[no_mangle]
    pub extern "C" fn jeth_advice_write_u64(value: u64) {
        write_word(value);
    }

    #[cfg(test)]
    #[expect(
        clippy::expect_used,
        reason = "test failures should identify the recording operation"
    )]
    mod tests {
        use super::{record, std, write_word};

        #[test]
        fn records_fifo_words_and_leaves_unselected_execution_alone() {
            write_word(99);
            let (value, tape) = record(|| {
                write_word(0x0102_0304_0506_0708);
                super::jeth_advice_write_u64(17);
                42
            })
            .expect("record");
            assert_eq!(value, 42);
            let expected: alloc::vec::Vec<_> = [0x0102_0304_0506_0708u64, 17]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect();
            assert_eq!(tape, expected);
            assert!(record(|| ()).expect("next recording").1.is_empty());
        }

        #[test]
        fn nesting_does_not_replace_the_outer_tape() {
            let ((), tape) = record(|| {
                write_word(1);
                assert!(record(|| write_word(99)).is_err());
                write_word(2);
            })
            .expect("outer recording");
            assert_eq!(tape.len(), 16);
            assert_eq!(&tape[8..], &2u64.to_le_bytes());
        }

        #[test]
        fn concurrent_recordings_keep_separate_tapes() {
            let ((), outer) = record(|| {
                write_word(1);
                let other = std::thread::spawn(|| record(|| write_word(2)).expect("worker record"))
                    .join()
                    .expect("worker joins");
                assert_eq!(other.1, 2u64.to_le_bytes());
                write_word(3);
            })
            .expect("outer record");
            assert_eq!(outer.len(), 16);
            assert_eq!(&outer[..8], &1u64.to_le_bytes());
            assert_eq!(&outer[8..], &3u64.to_le_bytes());
        }

        #[test]
        #[expect(
            clippy::panic,
            reason = "exercise cleanup when the recorded closure unwinds"
        )]
        fn unwinding_discards_partial_advice() {
            let result = std::panic::catch_unwind(|| {
                let _ = record(|| {
                    write_word(123);
                    panic!("test unwind");
                });
            });
            assert!(result.is_err());
            let ((), tape) = record(|| write_word(7)).expect("record after unwind");
            assert_eq!(tape, 7u64.to_le_bytes());
        }
    }
}

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
