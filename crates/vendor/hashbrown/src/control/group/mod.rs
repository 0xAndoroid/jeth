// TESTING NOTE:
//
// Because this module uses `cfg(..)` to select an implementation, it will not
// be linted without being run on targets that actually load each of these
// modules. Be sure to edit `ci/tools.sh` to add in the necessary cfgs if you
// change these, so that your implementation gets properly linted.

cfg_if! {
    // Use the SSE2 implementation if possible: it allows us to scan 16 buckets
    // at once instead of 8. We don't bother with AVX since it would require
    // runtime dispatch and wouldn't gain us much anyways: the probability of
    // finding a match drops off drastically after the first few buckets.
    //
    // I attempted an implementation on ARM using NEON instructions, but it
    // turns out that most NEON instructions have multi-cycle latency, which in
    // the end outweighs any gains over the generic implementation.
    if #[cfg(all(
        target_feature = "sse2",
        any(target_arch = "x86", target_arch = "x86_64"),
        not(miri),
    ))] {
        mod sse2;
        use sse2 as imp;
    } else if #[cfg(all(
        target_arch = "aarch64",
        target_feature = "neon",
        // NEON intrinsics are currently broken on big-endian targets.
        // See https://github.com/rust-lang/stdarch/issues/1484.
        target_endian = "little",
        not(miri),
    ))] {
        mod neon;
        use neon as imp;
    } else if #[cfg(all(
        feature = "nightly",
        target_arch = "loongarch64",
        target_feature = "lsx",
        not(miri),
    ))] {
        mod lsx;
        use lsx as imp;
    } else {
        mod generic;
        use generic as imp;
    }
}
pub(crate) use self::imp::Group;
pub(super) use self::imp::{BITMASK_ITER_MASK, BITMASK_STRIDE, BitMaskWord, NonZeroBitMaskWord};

/// jeth patch: containing-word load of an unaligned 8-byte ctrl group for the
/// riscv64 Jolt guest (used by `generic::Group::load`; same helper as the vendored
/// foldhash / alloy-primitives `gather`). Lives here, outside the `cfg_if!`
/// implementation switch, so the host unit test below compiles on every target.
///
/// `read_unaligned::<u64>` lowers to 8 `lbu` + 14 shift/or on riscv64imac (no
/// unaligned loads), and Jolt expands every `lbu` into a multi-row virtual
/// sequence: about 46 trace rows per probe. Gathering the word from the one or
/// two aligned words that contain it costs 1-2 `ld` + 3 ALU ops and yields
/// exactly the bytes the unaligned read would (little endian on the guest).
///
/// Soundness of the over-read: see the module comment of jeth's
/// `crates/guest/src/mem.rs`. Jolt guest RAM is one flat, word-granular address
/// space whose regions all start 8-aligned, so the aligned word holding a live
/// byte is always inside mapped memory, and only words containing at least one
/// live byte of `p..p + 8` are loaded (the ctrl array always carries
/// `Group::WIDTH` trailing mirror bytes, so those 8 bytes are live). The loads
/// are volatile so LLVM never reasons about the bytes outside the range.
/// Compiled for the guest target and for the host unit test only; native
/// builds keep the upstream read.
#[cfg(any(target_arch = "riscv64", test))]
#[inline(always)]
pub(crate) unsafe fn load_gathered(p: *const u8) -> u64 {
    let addr = p as usize;
    let k = addr & 7;
    let a = (addr & !7) as *const u64;
    // SAFETY: `a` is the aligned word containing byte `p`, a live byte of the
    // caller's range (precondition), hence mapped.
    let w0 = unsafe { core::ptr::read_volatile(a) };
    if k == 0 {
        return w0;
    }
    let s = (k * 8) as u32;
    // SAFETY: k > 0, so `p..p + 8` spills into the next aligned word, which
    // therefore holds live bytes of the range and is mapped.
    let w1 = unsafe { core::ptr::read_volatile(a.add(1)) };
    (w0 >> s) | (w1 << (64 - s))
}

#[cfg(test)]
mod gather_tests {
    /// The gather must reproduce the unaligned read at all 8 offsets inside an
    /// aligned 32-byte window.
    #[test]
    fn gathered_load_matches_unaligned_read() {
        #[repr(align(8))]
        struct Aligned([u8; 32]);
        let mut buf = Aligned([0; 32]);
        for (i, b) in buf.0.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x9d) ^ 0x5a;
        }
        for base in [0usize, 8, 16] {
            for off in 0..8 {
                let p = unsafe { buf.0.as_ptr().add(base + off) };
                let want = unsafe { p.cast::<u64>().read_unaligned() };
                assert_eq!(unsafe { super::load_gathered(p) }, want, "at {}", base + off);
            }
        }
    }
}
