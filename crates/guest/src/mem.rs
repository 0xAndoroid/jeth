//! Word-wide `memcpy`/`memset`/`memcmp` overrides for the Jolt guest.
//!
//! Jolt expands every sub-word (byte/half) memory access into a multi-row
//! virtual sequence, so compiler_builtins' byte loops cost ~6–10 trace rows per
//! byte. Measured traffic on a real block (25698189): 1.41M memcpy calls,
//! 121 MB, 41% relatively-misaligned, dominated by 32–255 B copies — 255M rows
//! (14.6%) under the builtin. These overrides copy 8 bytes per aligned ld/sd
//! (shift-combining when src/dst are relatively misaligned) and fall back to
//! byte ops only for <8-byte heads/tails.
//!
//! Volatile word ops keep LLVM's loop-idiom recognizer from lowering the loops
//! back into memcpy/memset calls (infinite recursion); they cost the same one
//! row per ld/sd here.

use core::ptr::{read_volatile, write_volatile};

#[inline(always)]
unsafe fn copy_bytes(mut dst: *mut u8, mut src: *const u8, mut n: usize) {
    while n > 0 {
        write_volatile(dst, read_volatile(src));
        dst = dst.add(1);
        src = src.add(1);
        n -= 1;
    }
}

#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if n < 8 {
        copy_bytes(dst, src, n);
        return dst;
    }

    // Align the destination to 8 bytes (≤7 byte ops).
    let mut d = dst;
    let mut s = src;
    let mut rem = n;
    let head = d.align_offset(8);
    if head > 0 {
        copy_bytes(d, s, head);
        d = d.add(head);
        s = s.add(head);
        rem -= head;
    }

    let src_misalign = (s as usize) & 7;
    if src_misalign == 0 {
        let mut dw = d as *mut u64;
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
        d = dw as *mut u8;
        s = sw as *const u8;
    } else if rem >= 16 {
        // Relatively misaligned: aligned window loads + shift-combine (LE).
        // The initial window may start up to 7 bytes before `s`; heap objects
        // are ≥8-aligned so the read stays inside the source object (same
        // trick as musl). `rem >= 16` keeps `sw.add(1)` in bounds.
        let shift = (src_misalign * 8) as u32;
        let inv_shift = 64 - shift;
        let mut sw = ((s as usize) & !7) as *const u64;
        let mut cur = read_volatile(sw);
        let mut dw = d as *mut u64;
        while rem >= 16 {
            let next = read_volatile(sw.add(1));
            write_volatile(dw, (cur >> shift) | (next << inv_shift));
            cur = next;
            sw = sw.add(1);
            dw = dw.add(1);
            rem -= 8;
        }
        d = dw as *mut u8;
        s = src.add(n - rem);
    }

    copy_bytes(d, s, rem);
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    let byte = val as u8;
    let mut d = dst;
    let mut rem = n;
    if n >= 8 {
        let head = d.align_offset(8);
        let mut h = head;
        while h > 0 {
            write_volatile(d, byte);
            d = d.add(1);
            h -= 1;
        }
        rem -= head;

        let word = u64::from_ne_bytes([byte; 8]);
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
        d = dw as *mut u8;
    }
    while rem > 0 {
        write_volatile(d, byte);
        d = d.add(1);
        rem -= 1;
    }
    dst
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    // Word-compare only when both sides are co-aligned (the common case:
    // 32-byte hash equality between 8-aligned heap objects). Byte-lexicographic
    // order == big-endian integer order of the mismatching word.
    let mut i = 0usize;
    if n >= 8 && (a as usize) % 8 == (b as usize) % 8 {
        let head = a.add(i).align_offset(8).min(n);
        while i < head {
            let (x, y) = (read_volatile(a.add(i)), read_volatile(b.add(i)));
            if x != y {
                return x as i32 - y as i32;
            }
            i += 1;
        }
        while n - i >= 8 {
            let x = read_volatile(a.add(i) as *const u64);
            let y = read_volatile(b.add(i) as *const u64);
            if x != y {
                let xb = x.to_be();
                let yb = y.to_be();
                return if xb > yb { 1 } else { -1 };
            }
            i += 8;
        }
    }
    while i < n {
        let (x, y) = (read_volatile(a.add(i)), read_volatile(b.add(i)));
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}
