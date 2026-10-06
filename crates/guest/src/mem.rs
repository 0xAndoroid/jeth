//! Word-RMW `memcpy`/`memset`/`memcmp` overrides for the Jolt guest.
//!
//! Jolt expands every sub-word (byte/half) memory access into a multi-row
//! virtual sequence: `sb` ≈ 12 rows, `lbu` ≈ 7 rows (see jolt-program's
//! `expand_narrow_store`/`expand_byte_load`), so byte-loop heads and tails
//! dominate the typical short call (memcpy traffic averages under 100 bytes).
//!
//! These overrides never issue a sub-word memory access. Boundary bytes are
//! handled by read-modify-write of the containing aligned word (`ld` + mask
//! merge + `sd` ≈ 8 rows for the whole boundary, not per byte). Source bytes
//! are gathered from the aligned word(s) that contain them with shift/or.
//!
//! Safety of the containing-word loads: Jolt guest RAM is a flat, contiguous,
//! word-granular address space — the aligned word containing any valid byte is
//! itself fully addressable. We only ever load/store words that contain at
//! least one live byte of the source/destination ranges.
//!
//! Layout dependency, not a language guarantee: those containing-word loads
//! and the boundary read-modify-writes touch up to 7 bytes outside the
//! caller's byte range, which no Rust memory access may do. They are
//! well-defined on the guest only because of the Jolt memory model, so
//! `keccak.rs`, the vendored `revm-interpreter` (`interpreter/words.rs`),
//! `zeth-mpt` (`mpt/decode.rs` `load_word`) and the key-hashing /
//! ctrl-group gathers in the vendored `foldhash` (`lib.rs` `gather`),
//! `alloy-primitives` (`map/fixed.rs` `gather`) and `hashbrown`
//! (`control/group/mod.rs` `load_gathered`) — which all cite this argument —
//! depend on the following staying true:
//!
//! * Guest RAM is one flat, contiguous, word-granular array from
//!   `RAM_START_ADDRESS`; every region `MemoryLayout` and the linker script
//!   carve out (program, input, advice, stack, heap) starts 8-aligned, so the
//!   word holding a live byte of any region lies inside the traced range.
//! * The stack and heap edges inherit the alignment of the ELF's `program_end`
//!   (`stack_end = RAM_START + program_size`, `heap_end = stack_end + stack +
//!   heap`); only `heap_end` borders unmapped memory, so a live byte in the
//!   heap's final partial word is the one way a containing-word access could
//!   leave the traced range. That takes the 1.5 GiB heap full to within 7
//!   bytes (peak use on the benchmark set is ~58 MiB); pin it upstream
//!   (`align_up(program_size, 8)` or a boot assert) before relying on more.
//! * Containing-word accesses use inline-asm `ld`/`sd` on riscv64: neither
//!   volatile operations nor the C ABI permit out-of-allocation Rust access.
//!   The single-hart guest has no concurrent writer of the preserved edge
//!   bytes. Native tests own and initialize the entire containing words.
//!
//! Re-validate this paragraph whenever the guest linker script, jolt's
//! `MemoryLayout`, or its region alignment changes. The native tests
//! (`crates/guest/native-tests`) run the same code inside buffers with a word
//! of slack on both sides so it stays in bounds there.
//!
//! Volatile word ops keep LLVM's loop-idiom recognizer from lowering the loops
//! back into memcpy/memset calls (infinite recursion); they cost the same one
//! row per ld/sd here.

use core::ptr::{read_volatile, write_volatile};

/// Loads the 8-aligned word `I` words past `p` (the offset is an `ld`
/// immediate), which may hold bytes outside the caller's range
/// (containing-word read, see the module docs). On other targets the
/// native-test caller must own and initialize the whole word.
#[inline(always)]
pub(super) unsafe fn load_word<const I: usize>(p: *const u64) -> u64 {
    #[cfg(target_arch = "riscv64")]
    {
        let w: u64;
        core::arch::asm!(
            "ld {w}, {off}({p})",
            p = in(reg) p,
            off = const I * 8,
            w = lateout(reg) w,
            options(pure, readonly, nostack, preserves_flags)
        );
        w
    }
    #[cfg(not(target_arch = "riscv64"))]
    read_volatile(p.add(I))
}

/// Stores `v` to the 8-aligned word `I` words past `p`, which may hold bytes
/// outside the caller's range (edge word of a read-modify-write, see the
/// module docs). The caller must exclusively own the whole word, or run
/// on the single-hart guest with no concurrent access to its edge bytes.
#[inline(always)]
pub(super) unsafe fn store_word<const I: usize>(p: *mut u64, v: u64) {
    #[cfg(target_arch = "riscv64")]
    core::arch::asm!(
        "sd {v}, {off}({p})",
        p = in(reg) p,
        off = const I * 8,
        v = in(reg) v,
        options(nostack, preserves_flags)
    );
    #[cfg(not(target_arch = "riscv64"))]
    write_volatile(p.add(I), v);
}

/// Gather the 8 source bytes for destination word position `i` when the
/// source is relatively misaligned by `shift` bits: combines the aligned
/// window words `w[i]` and `w[i+1]`.
#[inline(always)]
unsafe fn gather(cur: u64, next: u64, shift: u32) -> u64 {
    // LE: byte k of the result comes from bit offset shift + 8k.
    (cur >> shift) | (next << (64 - shift))
}

#[inline(always)]
unsafe fn word_at(p: *const u8) -> u64 {
    load_word::<0>(((p as usize) & !7) as *const u64)
}

/// Read `n` (1..=8) bytes starting at `s` (arbitrary alignment) into the low
/// bytes of a u64, using only aligned word loads of words that contain live
/// source bytes.
#[inline(always)]
unsafe fn load_le_partial(s: *const u8, n: usize) -> u64 {
    debug_assert!(n >= 1 && n <= 8);
    let off = (s as usize) & 7;
    let lo = word_at(s) >> (off * 8);
    let have = 8 - off;
    let v = if n > have {
        // needed span crosses into the next aligned word (which then contains
        // live bytes) — combine.
        let hi = word_at(s.add(have));
        lo | (hi << (have * 8))
    } else {
        lo
    };
    if n == 8 {
        v
    } else {
        v & ((1u64 << (n * 8)) - 1)
    }
}

/// Write the low `n` (1..=8) bytes of `v` to `d` (arbitrary alignment) with
/// read-modify-write of the containing aligned word(s).
#[inline(always)]
unsafe fn store_le_partial(d: *mut u8, v: u64, n: usize) {
    debug_assert!(n >= 1 && n <= 8);
    let off = (d as usize) & 7;
    let base = ((d as usize) & !7) as *mut u64;
    let fit = 8 - off;
    let n0 = n.min(fit);
    {
        let mask = if n0 == 8 {
            u64::MAX
        } else {
            ((1u64 << (n0 * 8)) - 1) << (off * 8)
        };
        let old = load_word::<0>(base);
        store_word::<0>(base, (old & !mask) | ((v << (off * 8)) & mask));
    }
    if n > n0 {
        let rem = n - n0; // 1..=7 bytes into the next word
        let mask = (1u64 << (rem * 8)) - 1;
        let old = load_word::<1>(base);
        store_word::<1>(base, (old & !mask) | ((v >> (n0 * 8)) & mask));
    }
}

/// Core implementation (also compiled natively for the fuzz tests).
pub(crate) unsafe fn memcpy_impl(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if n == 0 {
        return dst;
    }
    if n <= 8 {
        let v = load_le_partial(src, n);
        store_le_partial(dst, v, n);
        return dst;
    }
    if n <= 16 {
        // two (possibly overlapping) 8-byte transfers cover 9..=16 bytes
        let lo = load_le_partial(src, 8);
        let hi = load_le_partial(src.add(n - 8), 8);
        store_le_partial(dst, lo, 8);
        store_le_partial(dst.add(n - 8), hi, 8);
        return dst;
    }

    let mut d = dst;
    let mut s = src;
    let mut rem = n;
    let head = (8 - ((d as usize) & 7)) & 7;
    if head > 0 {
        let v = load_le_partial(s, head);
        store_le_partial(d, v, head);
        d = d.add(head);
        s = s.add(head);
        rem -= head;
    }

    let src_misalign = (s as usize) & 7;
    let mut dw = d as *mut u64;
    if src_misalign == 0 {
        let mut sw = s as *const u64;
        while rem >= 32 {
            let a = read_volatile(sw);
            let b = read_volatile(sw.add(1));
            let c = read_volatile(sw.add(2));
            let e = read_volatile(sw.add(3));
            write_volatile(dw, a);
            write_volatile(dw.add(1), b);
            write_volatile(dw.add(2), c);
            write_volatile(dw.add(3), e);
            dw = dw.add(4);
            sw = sw.add(4);
            rem -= 32;
        }
        while rem >= 8 {
            write_volatile(dw, read_volatile(sw));
            dw = dw.add(1);
            sw = sw.add(1);
            rem -= 8;
        }
        s = sw as *const u8;
    } else {
        // Relatively misaligned: aligned window loads + shift-combine (LE).
        // The window word containing `s` holds live bytes; `rem >= 32`
        // guarantees the next four window words hold live bytes (the live
        // range reaches past `sw + 32`), `rem >= 8` the next one. Unrolled 4×
        // with the carried word rotating through registers: ~25 rows per 32 B
        // instead of ~10 per 8 B.
        let shift = (src_misalign * 8) as u32;
        let mut sw = ((s as usize) & !7) as *const u64;
        let mut cur = load_word::<0>(sw);
        while rem >= 32 {
            let w1 = load_word::<1>(sw);
            let w2 = load_word::<2>(sw);
            let w3 = load_word::<3>(sw);
            let w4 = load_word::<4>(sw);
            write_volatile(dw, gather(cur, w1, shift));
            write_volatile(dw.add(1), gather(w1, w2, shift));
            write_volatile(dw.add(2), gather(w2, w3, shift));
            write_volatile(dw.add(3), gather(w3, w4, shift));
            cur = w4;
            sw = sw.wrapping_add(4);
            dw = dw.add(4);
            rem -= 32;
        }
        while rem >= 8 {
            let next = load_word::<1>(sw);
            write_volatile(dw, gather(cur, next, shift));
            cur = next;
            sw = sw.wrapping_add(1);
            dw = dw.add(1);
            rem -= 8;
        }
        s = (sw as *const u8).wrapping_add(src_misalign);
    }
    d = dw as *mut u8;

    if rem > 0 {
        // tail < 8: destination is 8-aligned here, so this is a single RMW.
        let v = load_le_partial(s, rem);
        store_le_partial(d, v, rem);
    }
    dst
}

pub(crate) unsafe fn memset_impl(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    if n == 0 {
        return dst;
    }
    let byte = val as u8;
    let word = u64::from_ne_bytes([byte; 8]);
    if n <= 8 {
        store_le_partial(dst, word, n);
        return dst;
    }

    let mut d = dst;
    let mut rem = n;
    let head = (8 - ((d as usize) & 7)) & 7;
    if head > 0 {
        store_le_partial(d, word, head);
        d = d.add(head);
        rem -= head;
    }
    let mut dw = d as *mut u64;
    while rem >= 32 {
        write_volatile(dw, word);
        write_volatile(dw.add(1), word);
        write_volatile(dw.add(2), word);
        write_volatile(dw.add(3), word);
        dw = dw.add(4);
        rem -= 32;
    }
    while rem >= 8 {
        write_volatile(dw, word);
        dw = dw.add(1);
        rem -= 8;
    }
    if rem > 0 {
        store_le_partial(dw as *mut u8, word, rem);
    }
    dst
}

/// `memcmp` sign from the first differing words, both loaded little-endian so
/// the lowest differing byte is the first one in memory order. Bytes below it
/// are equal, so the words masked up to and including that byte order like
/// the byte itself (no byte swap: RV64IMAC has no `rev8`).
#[inline(always)]
fn first_diff_sign(x: u64, y: u64) -> i32 {
    let d = x ^ y;
    let low_bit = d & d.wrapping_neg();
    let ones = (low_bit | (low_bit - 1)) & 0x0101_0101_0101_0101;
    let mask = ones * 0xFF;
    if (x & mask) > (y & mask) {
        1
    } else {
        -1
    }
}

pub(crate) unsafe fn memcmp_impl(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0usize;
    // Co-aligned fast path (the common case: 32-byte hash equality between
    // 8-aligned heap objects): one aligned load per side per word after a
    // single partial head compare.
    if n >= 8 && ((a as usize) & 7) == ((b as usize) & 7) {
        let head = (8 - ((a as usize) & 7)) & 7;
        if head > 0 {
            let x = load_le_partial(a, head);
            let y = load_le_partial(b, head);
            if x != y {
                return first_diff_sign(x, y);
            }
            i = head;
        }
        while n - i >= 8 {
            let x = read_volatile(a.add(i) as *const u64);
            let y = read_volatile(b.add(i) as *const u64);
            if x != y {
                return first_diff_sign(x, y);
            }
            i += 8;
        }
    }
    while n - i >= 8 {
        let x = load_le_partial(a.add(i), 8);
        let y = load_le_partial(b.add(i), 8);
        if x != y {
            return first_diff_sign(x, y);
        }
        i += 8;
    }
    if i < n {
        let rem = n - i;
        let x = load_le_partial(a.add(i), rem);
        let y = load_le_partial(b.add(i), rem);
        if x != y {
            return first_diff_sign(x, y);
        }
    }
    0
}

/// The actual C-ABI symbols, guest builds only (native test builds must not
/// shadow libc).
#[cfg(feature = "guest")]
mod exports {
    #[no_mangle]
    pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
        super::memcpy_impl(dst, src, n)
    }
    #[no_mangle]
    pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
        super::memset_impl(dst, val, n)
    }
    #[no_mangle]
    pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
        super::memcmp_impl(a, b, n)
    }
}

/// Native tests (`cargo test --manifest-path crates/guest/native-tests/Cargo.toml`,
/// no `guest` feature): the implementations are pure LE 64-bit word logic,
/// identical on aarch64, so we fuzz them against the std implementations.
#[cfg(all(test, not(feature = "guest")))]
mod tests {
    use super::{memcmp_impl as jmemcmp, memcpy_impl as jmemcpy, memset_impl as jmemset};

    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn fuzz_memcpy_memset_memcmp() {
        let mut rng = 0x1234_5678_9abc_def0u64;
        for _ in 0..200_000 {
            let n = (xorshift(&mut rng) % 100) as usize;
            let soff = (xorshift(&mut rng) % 16) as usize;
            let doff = (xorshift(&mut rng) % 16) as usize;

            let mut src = [0u8; 144];
            for b in src.iter_mut() {
                *b = xorshift(&mut rng) as u8;
            }
            let mut dst = [0u8; 144];
            for b in dst.iter_mut() {
                *b = xorshift(&mut rng) as u8;
            }
            let mut expect = dst;

            unsafe {
                jmemcpy(dst.as_mut_ptr().add(doff), src.as_ptr().add(soff), n);
            }
            expect[doff..doff + n].copy_from_slice(&src[soff..soff + n]);
            assert_eq!(dst, expect, "memcpy n={n} soff={soff} doff={doff}");

            let val = (xorshift(&mut rng) & 0xff) as i32;
            unsafe {
                jmemset(dst.as_mut_ptr().add(doff), val, n);
            }
            expect[doff..doff + n].fill(val as u8);
            assert_eq!(dst, expect, "memset n={n} doff={doff} val={val}");

            let r = unsafe { jmemcmp(dst.as_ptr().add(doff), expect.as_ptr().add(doff), n) };
            assert_eq!(r, 0);
            if n > 0 {
                let flip = (xorshift(&mut rng) as usize) % n;
                let mut other = expect;
                other[doff + flip] =
                    other[doff + flip].wrapping_add(1 + (xorshift(&mut rng) % 254) as u8);
                for b in other[doff + flip + 1..doff + n].iter_mut() {
                    *b = xorshift(&mut rng) as u8;
                }
                let want = expect[doff..doff + n].cmp(&other[doff..doff + n]) as i32;
                let got = unsafe { jmemcmp(dst.as_ptr().add(doff), other.as_ptr().add(doff), n) };
                assert_eq!(got.signum(), want.signum(), "memcmp n={n} flip={flip}");
            }
        }
    }
}
