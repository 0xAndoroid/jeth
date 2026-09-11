//! Word-wise big-endian 32-byte transfers on byte buffers.
//!
//! On the Jolt RV64IMAC target every byte load expands to a 3-row virtual
//! sequence and every byte store to a 6-row one, while naturally aligned
//! `LD`/`SD` are single rows. `U256::try_from_be_slice` / `to_be_bytes` on
//! unaligned EVM memory therefore degrade to per-byte loops (~150+ rows per
//! 32-byte word). These helpers move whole doublewords instead: aligned
//! pointers use four `LD`/`SD` + [`bswap64`], unaligned ones the five aligned
//! doublewords covering the 32 bytes, shift-combined, the two edge words
//! read-modify-written on store so their outside bytes keep their values.
//!
//! The five-word window can leave the slice by up to seven bytes on either
//! side. Native builds check for that and take a byte path (the Rust-AM
//! in-bounds version; it is what the tests exercise at the slice edges). The
//! Jolt guest skips the check: every word touched holds at least one byte of
//! the 32-byte range, so the containing-word rule of the guest's `mem.rs`
//! (flat, word-granular RAM) makes it addressable, and the edge RMW writes
//! the outside bytes back unchanged. In Rust's abstract machine those accesses
//! are undefined behaviour; they are volatile so LLVM emits them as written
//! and infers nothing from them.

use core::ptr::{read_volatile, write_volatile};
use primitives::U256;

/// Whether the five-word window is checked against the slice (see the module
/// docs); `false` on the Jolt guest.
const CHECK_WINDOW: bool = !cfg!(target_os = "none");

/// Reads the 32-byte big-endian word at `data[offset..offset + 32]` (MLOAD,
/// CALLDATALOAD) with aligned `u64` loads.
///
/// # Panics
///
/// Debug-asserts `offset + 32 <= data.len()`.
#[inline(always)]
pub(crate) fn read_u256_be(data: &[u8], offset: usize) -> U256 {
    debug_assert!(offset + 32 <= data.len());
    // SAFETY: `offset + 32 <= data.len()` (callers resize / bounds-check first).
    let p = unsafe { data.as_ptr().add(offset) };
    let s = p as usize & 7;
    if s == 0 {
        // SAFETY: `p` is 8-aligned and bytes [offset, offset + 32) are in bounds.
        return unsafe {
            let w = p.cast::<u64>();
            U256::from_limbs([
                bswap64(*w.add(3)),
                bswap64(*w.add(2)),
                bswap64(*w.add(1)),
                bswap64(*w),
            ])
        };
    }
    if CHECK_WINDOW && (offset < s || offset + 40 - s > data.len()) {
        return read_u256_be_bytes(&data[offset..offset + 32]);
    }
    let sh = (s * 8) as u32;
    let inv = 64 - sh;
    // SAFETY: `a` is the 8-aligned word containing `p`; each of the five words
    // read holds at least one byte of [offset, offset + 32) — containing-word
    // rule (module docs); natively the window was checked to lie in `data`.
    unsafe {
        let a = (p as usize & !7) as *const u64;
        let w0 = read_volatile(a);
        let w1 = read_volatile(a.add(1));
        let w2 = read_volatile(a.add(2));
        let w3 = read_volatile(a.add(3));
        let w4 = read_volatile(a.add(4));
        // Little-endian target: `l0` is the LE u64 of bytes [p, p + 8), i.e.
        // the most significant 8 big-endian bytes.
        let l0 = (w0 >> sh) | (w1 << inv);
        let l1 = (w1 >> sh) | (w2 << inv);
        let l2 = (w2 >> sh) | (w3 << inv);
        let l3 = (w3 >> sh) | (w4 << inv);
        U256::from_limbs([bswap64(l3), bswap64(l2), bswap64(l1), bswap64(l0)])
    }
}

/// Byte path for a window that leaves the slice (native builds only).
#[cold]
#[inline(never)]
fn read_u256_be_bytes(bytes: &[u8]) -> U256 {
    U256::try_from_be_slice(bytes).unwrap()
}

/// Writes `value` as the 32-byte big-endian word at `data[offset..offset + 32]`
/// (MSTORE) with aligned `u64` stores.
///
/// # Panics
///
/// Debug-asserts `offset + 32 <= data.len()`.
#[inline(always)]
pub(crate) fn write_u256_be(data: &mut [u8], offset: usize, value: &U256) {
    debug_assert!(offset + 32 <= data.len());
    // SAFETY: `offset + 32 <= data.len()` (callers resize first).
    let p = unsafe { data.as_mut_ptr().add(offset) };
    let s = p as usize & 7;
    let limbs = value.as_limbs();
    // `v0` holds the most significant 8 big-endian bytes as the LE u64 to be
    // stored at the lowest address.
    let v0 = bswap64(limbs[3]);
    let v1 = bswap64(limbs[2]);
    let v2 = bswap64(limbs[1]);
    let v3 = bswap64(limbs[0]);
    if s == 0 {
        // SAFETY: `p` is 8-aligned and bytes [offset, offset + 32) are in bounds.
        unsafe {
            let w = p.cast::<u64>();
            *w = v0;
            *w.add(1) = v1;
            *w.add(2) = v2;
            *w.add(3) = v3;
        }
        return;
    }
    if CHECK_WINDOW && (offset < s || offset + 40 - s > data.len()) {
        return write_u256_be_bytes(&mut data[offset..offset + 32], value);
    }
    let sh = (s * 8) as u32;
    let inv = 64 - sh;
    let keep = (1u64 << sh) - 1; // bytes of the first word before `p`
                                 // SAFETY: as in `read_u256_be`; the first and last words are
                                 // read-modify-written so the bytes outside [offset, offset + 32) keep
                                 // their values.
    unsafe {
        let a = (p as usize & !7) as *mut u64;
        write_volatile(a, (read_volatile(a) & keep) | (v0 << sh));
        write_volatile(a.add(1), (v0 >> inv) | (v1 << sh));
        write_volatile(a.add(2), (v1 >> inv) | (v2 << sh));
        write_volatile(a.add(3), (v2 >> inv) | (v3 << sh));
        write_volatile(a.add(4), (read_volatile(a.add(4)) & !keep) | (v3 >> inv));
    }
}

/// Byte path for a window that leaves the slice (native builds only).
#[cold]
#[inline(never)]
fn write_u256_be_bytes(bytes: &mut [u8], value: &U256) {
    bytes.copy_from_slice(&value.to_be_bytes::<32>());
}

/// Byte-swaps `x`. Without Zbb's `rev8`, LLVM lowers `u64::swap_bytes` on
/// riscv64 to ~25 mask/shift/or instructions per call (and re-derives that
/// lowering from any hand-written swap it recognises); this pins the
/// 13-instruction butterfly — rotate by 32, swap the 16-bit halves, swap the
/// bytes — with the two lane masks materialised by the compiler once per
/// function.
#[inline(always)]
pub(crate) fn bswap64(x: u64) -> u64 {
    #[cfg(target_arch = "riscv64")]
    {
        let out: u64;
        // SAFETY: register-only arithmetic on the named operands; no memory
        // access, no stack use.
        unsafe {
            core::arch::asm!(
                "srli {t}, {x}, 32",
                "slli {o}, {x}, 32",
                "or   {o}, {o}, {t}",
                "srli {t}, {o}, 16",
                "and  {t}, {t}, {m16}",
                "and  {o}, {o}, {m16}",
                "slli {o}, {o}, 16",
                "or   {o}, {o}, {t}",
                "srli {t}, {o}, 8",
                "and  {t}, {t}, {m8}",
                "and  {o}, {o}, {m8}",
                "slli {o}, {o}, 8",
                "or   {o}, {o}, {t}",
                x = in(reg) x,
                m16 = in(reg) 0x0000_ffff_0000_ffffu64,
                m8 = in(reg) 0x00ff_00ff_00ff_00ffu64,
                o = out(reg) out,
                t = out(reg) _,
                options(pure, nomem, nostack),
            );
        }
        out
    }
    #[cfg(not(target_arch = "riscv64"))]
    x.swap_bytes()
}

/// The `N`-byte (1..=32) big-endian PUSH immediate at `p` as a `U256`, read
/// with aligned `LD`s only.
///
/// `N <= 4`: byte loads shifted in (cheaper than a word gather plus swap).
/// `N >= 5`: loads the 8-aligned words containing bytes `[p, p + N)`, funnels
/// them into the immediate's byte stream eight bytes at a time, byte-swaps
/// each chunk and right-aligns the value with a constant shift, so the up to
/// seven bytes past the immediate riding along in the last word fall off.
///
/// # Safety
///
/// `p` must point at `N` readable bytes. The loads touch only the 8-aligned
/// words holding at least one of those bytes; on the Jolt guest (flat,
/// word-granular RAM) such words are addressable — the containing-word rule of
/// the guest's `mem.rs`/`keccak.rs`. In Rust's abstract machine the other
/// bytes inside those words lie outside the caller's slice; the loads are
/// volatile, so nothing is inferred from them, and the bits they contribute
/// are shifted out. The native tests give every buffer a word of slack on
/// both sides.
#[inline(always)]
pub(crate) unsafe fn read_be_immediate<const N: usize>(p: *const u8) -> U256 {
    const { assert!(1 <= N && N <= 32) };
    if N <= 4 {
        let mut v = 0u64;
        for i in 0..N {
            v = (v << 8) | *p.add(i) as u64;
        }
        return U256::from_limbs([v, 0, 0, 0]);
    }
    let s = p as usize & 7;
    let base = (p as usize & !7) as *const u64;
    // `c` 8-byte chunks make up the immediate's byte stream. Words 0..c each
    // hold immediate bytes for every `s`; word c holds one exactly when the
    // stream spills into it (`s + N > 8c`) and is read only then — its bytes
    // past the immediate are shifted out below.
    let c = N.div_ceil(8);
    let mut w = [0u64; 5];
    for (i, word) in w.iter_mut().enumerate().take(c) {
        *word = read_volatile(base.add(i));
    }
    if s + N > 8 * c {
        w[c] = read_volatile(base.add(c));
    }
    let sh = (s * 8) as u32;
    // Chunk m = stream bytes [8m, 8m + 8), little-endian; `<< (63 - sh) << 1`
    // is `<< (64 - sh)` that is also defined for sh == 0. Swapped, chunk 0 is
    // the most significant limb of the left-aligned value.
    let mut y = [0u64; 4];
    for m in 0..c {
        y[3 - m] = bswap64((w[m] >> sh) | ((w[m + 1] << (63 - sh)) << 1));
    }
    // Right-align by the 32 - N missing bytes: `d` whole limbs and `r` bits.
    let d = (32 - N) / 8;
    let r = ((32 - N) % 8) * 8;
    let mut x = [0u64; 4];
    for i in 0..4 - d {
        x[i] = y[i + d] >> r;
        if r != 0 && i + d + 1 < 4 {
            x[i] |= y[i + d + 1] << (64 - r);
        }
    }
    U256::from_limbs(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every alignment of the 32-byte word inside a buffer with slack on both
    /// sides (the window path), plus every alignment at the very start and
    /// end of the buffer (the window leaves the slice: native byte path).
    #[test]
    fn read_write_all_alignments() {
        let value = U256::from_be_bytes::<32>(core::array::from_fn(|i| (i as u8) * 7 + 1));
        for pad in 0..8usize {
            for (len, off) in [(64usize, pad + 8), (32 + pad, pad), (40, 8 - pad)] {
                let mut buf = vec![0xAAu8; len];
                write_u256_be(&mut buf, off, &value);
                assert_eq!(&buf[off..off + 32], &value.to_be_bytes::<32>());
                // Neighbours untouched.
                assert!(buf[..off].iter().all(|&b| b == 0xAA), "pad {pad} len {len}");
                assert!(
                    buf[off + 32..].iter().all(|&b| b == 0xAA),
                    "pad {pad} len {len}"
                );
                buf.fill(0xAA);
                buf[off..off + 32].copy_from_slice(&value.to_be_bytes::<32>());
                assert_eq!(read_u256_be(&buf, off), value, "pad {pad} len {len}");
            }
        }
    }

    #[test]
    fn bswap64_matches_swap_bytes() {
        let mut v = 0x0123_4567_89ab_cdefu64;
        for _ in 0..64 {
            assert_eq!(bswap64(v), v.swap_bytes());
            v = v.rotate_left(7) ^ 0x9e37_79b9_7f4a_7c15;
        }
    }

    /// `read_be_immediate::<N>` against `U256::try_from_be_slice` for every
    /// N and every alignment of the immediate; the buffer carries a word of
    /// slack on both sides (the containing-word contract) and the bytes after
    /// the immediate are non-zero so a leak would show.
    fn check_immediate<const N: usize>(rng: &mut u64) {
        for off in 0..8usize {
            let mut buf = vec![0u8; 8 + off + N + 8];
            for b in buf.iter_mut() {
                *rng ^= *rng << 13;
                *rng ^= *rng >> 7;
                *rng ^= *rng << 17;
                *b = (*rng as u8) | 1;
            }
            // Immediates with zero bytes (and a zero leading byte) too.
            if off % 3 == 0 {
                buf[8 + off] = 0;
                buf[8 + off + N / 2] = 0;
            }
            let imm = &buf[8 + off..8 + off + N];
            let want = U256::try_from_be_slice(imm).unwrap();
            let got = unsafe { read_be_immediate::<N>(imm.as_ptr()) };
            assert_eq!(got, want, "N {N} off {off}");
        }
    }

    #[test]
    fn immediate_all_sizes_all_alignments() {
        let mut rng = 0xfeed_face_cafe_beefu64;
        macro_rules! check {
            ($($n:literal)*) => { $( check_immediate::<$n>(&mut rng); )* };
        }
        check!(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32);
    }

    #[test]
    fn read_write_slice_edges() {
        let value = U256::from_be_bytes::<32>(core::array::from_fn(|i| 255 - i as u8));
        let mut buf = vec![0u8; 32];
        write_u256_be(&mut buf, 0, &value);
        assert_eq!(&buf[..], &value.to_be_bytes::<32>());
        buf.copy_from_slice(&value.to_be_bytes::<32>());
        assert_eq!(read_u256_be(&buf, 0), value);
    }
}
