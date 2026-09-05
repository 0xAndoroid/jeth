//! `native_keccak256` core for the Jolt guest: alloy's `native-keccak` hook,
//! lowered onto the two Keccak-f[1600] inlines of `jolt-inlines-keccak256`
//! (opcode 0x0B, funct7 1): funct3 0 permutes the 25 lanes at `rs1`
//! (`Keccak256Permutation`); funct3 1 first XORs the 17 rate lanes at `rs2`
//! into them (`Keccak256AbsorbPermutation`, `sdk.rs:179`
//! `keccak256_absorb_permute`). The absorb variant costs 34 more trace rows
//! (17 `LD` + 17 `XOR`), so it is used only where it is cheapest: whole,
//! 8-aligned middle blocks read straight from the caller's memory. The first
//! block of every message is written into the still-zero rate lanes, and the
//! padded final block is XORed lane-wise into the state by the shim itself;
//! both then run the plain permutation.
//!
//! Row discipline (one Jolt row per RV64 instruction, sub-word accesses expand
//! to 3–9 rows, misaligned `LD`/`SD` trap): every memory access below is an
//! 8-aligned `LD`/`SD`. Partial words are assembled from the aligned word(s)
//! that contain them — the containing-word pattern `mem.rs` uses for memcpy
//! boundaries — and the final block is padded word-wise, so no memset/memcpy
//! call and no byte store is ever issued.
//!
//! Volatile word ops keep LLVM from re-forming memset/memcpy calls out of the
//! copy/zero loops (the guest overrides those symbols) and from merging the
//! zero stores; they cost the same one row per `LD`/`SD`.
//!
//! Containing-word reads: for a byte range `[p, p + n)` with `n >= 1` the
//! aligned words touched are exactly those holding at least one live byte, so
//! on the guest (flat, word-granular RAM — see `mem.rs`) they are addressable.
//! In Rust terms the extra bytes lie outside the caller's slice; the native
//! tests place every buffer inside an allocation with word-sized slack on
//! both ends so the same code stays in bounds there.

use core::mem::MaybeUninit;
use core::ptr::{read_volatile, write_volatile};

const RATE_BYTES: usize = 136;
const RATE_WORDS: usize = RATE_BYTES / 8;
const STATE_WORDS: usize = 25;
const DIGEST_WORDS: usize = 4;

/// Keccak-f[1600] on the 25 lanes at `state` (8-aligned).
#[inline(always)]
unsafe fn permute(state: *mut u64) {
    #[cfg(feature = "guest")]
    {
        use jolt_inlines_keccak256::{INLINE_OPCODE, KECCAK256_FUNCT3, KECCAK256_FUNCT7};
        // `Keccak256Permutation` (sequence_builder.rs): rs1 = state, rs2 unused.
        core::arch::asm!(
            ".insn r {opcode}, {funct3}, {funct7}, x0, {rs1}, x0",
            opcode = const INLINE_OPCODE,
            funct3 = const KECCAK256_FUNCT3,
            funct7 = const KECCAK256_FUNCT7,
            rs1 = in(reg) state,
            options(nostack)
        );
    }
    #[cfg(not(feature = "guest"))]
    f1600(state);
}

/// Native reference permutation for the differential tests.
#[cfg(not(feature = "guest"))]
unsafe fn f1600(state: *mut u64) {
    keccak::Keccak::new().with_f1600(|f| f(&mut *state.cast::<[u64; STATE_WORDS]>()));
}

/// `state[i] ^= block[i]` over the 17 rate lanes, then Keccak-f[1600].
/// Both pointers 8-aligned and non-overlapping.
#[inline(always)]
unsafe fn absorb_permute(state: *mut u64, block: *const u64) {
    #[cfg(feature = "guest")]
    jolt_inlines_keccak256::keccak256_absorb_permute(state, block.cast());
    #[cfg(not(feature = "guest"))]
    {
        for i in 0..RATE_WORDS {
            *state.add(i) ^= *block.add(i);
        }
        f1600(state);
    }
}

/// Stores `v` at the 8-aligned `p`, or XORs it into the lane there when `XOR`.
#[inline(always)]
unsafe fn put<const XOR: bool>(p: *mut u64, v: u64) {
    if XOR {
        write_volatile(p, read_volatile(p) ^ v);
    } else {
        write_volatile(p, v);
    }
}

/// Merges `n` whole words from the 8-aligned `src` into the 8-aligned `dst`
/// (see [`put`]). Unrolled by four so loop control stays under one row per
/// word; a constant `n` folds to straight-line code.
#[inline(always)]
unsafe fn copy_words<const XOR: bool>(mut dst: *mut u64, mut src: *const u64, n: usize) {
    let end4 = src.add(n & !3);
    let end = src.add(n);
    while src != end4 {
        let a = read_volatile(src);
        let b = read_volatile(src.add(1));
        let c = read_volatile(src.add(2));
        let d = read_volatile(src.add(3));
        put::<XOR>(dst, a);
        put::<XOR>(dst.add(1), b);
        put::<XOR>(dst.add(2), c);
        put::<XOR>(dst.add(3), d);
        src = src.add(4);
        dst = dst.add(4);
    }
    while src != end {
        put::<XOR>(dst, read_volatile(src));
        src = src.add(1);
        dst = dst.add(1);
    }
}

/// Merges the first `n` whole little-endian words of the byte stream at `src`
/// (`src % 8 != 0`, stream length >= max(8n, 1)) into the 8-aligned `dst`,
/// combining consecutive aligned words `W[i] = *((src & !7) + 8i)`. Only
/// `W[0..=n]` are read; each holds at least one stream byte. Returns `W[n]`
/// so a trailing partial word can be finished without reloading it.
#[inline(always)]
unsafe fn gather_words<const XOR: bool>(dst: *mut u64, src: *const u8, n: usize) -> u64 {
    let s = ((src as usize & 7) * 8) as u32;
    let base = ((src as usize) & !7) as *const u64;
    let mut cur = read_volatile(base);
    for i in 0..n {
        let next = read_volatile(base.add(i + 1));
        put::<XOR>(dst.add(i), (cur >> s) | (next << (64 - s)));
        cur = next;
    }
    cur
}

/// Merges the padded final block — the `rem < 136` stream bytes at `src`,
/// then `0x01`, zeros, `0x80` (Keccak pad10*1) — into the 17 rate lanes at
/// `dst`: written when `!XOR` (a single-block message: the lanes hold nothing
/// yet), XORed lane-wise when `XOR` (the state already carries earlier blocks).
#[inline(always)]
unsafe fn merge_final_block<const XOR: bool>(dst: *mut u64, src: *const u8, rem: usize) {
    if !XOR {
        // Zero fill first (17 unconditional SDs beat a variable-length loop);
        // the data words overwrite below. Lane 16 carries the trailing 0x80.
        for i in 0..RATE_WORDS - 1 {
            write_volatile(dst.add(i), 0);
        }
        write_volatile(dst.add(RATE_WORDS - 1), 1 << 63);
    }

    let t = rem >> 3; // whole stream words
    let r = rem & 7; // stream bytes in word t
    let off = src as usize & 7;
    let data = if off == 0 {
        copy_words::<XOR>(dst, src.cast(), t);
        // The word at src + 8t holds stream bytes only when r > 0.
        if r != 0 {
            read_volatile(src.cast::<u64>().add(t))
        } else {
            0
        }
    } else if rem != 0 {
        let s = (off * 8) as u32;
        let base = ((src as usize) & !7) as *const u64;
        let lo = gather_words::<XOR>(dst, src, t) >> s;
        // W[t + 1] holds stream bytes only when the partial word spills into it.
        if off + r > 8 {
            lo | (read_volatile(base.add(t + 1)) << (64 - s))
        } else {
            lo
        }
    } else {
        0
    };
    // Lane t: its r stream bytes, 0x01 at byte r, and — when t == 16, i.e.
    // rem >= 128 — the 0x80 of lane 16 as well (rem == 135 yields 0x81).
    let pad = 1u64 << (8 * r);
    let top = ((rem >> 7) as u64) << 63;
    put::<XOR>(dst.add(t), (data & (pad - 1)) | pad | top);
    if XOR && rem < 128 {
        put::<true>(dst.add(RATE_WORDS - 1), 1 << 63);
    }
}

/// Writes the four digest lanes to the 32 bytes at `out` (any alignment).
#[inline(always)]
unsafe fn store_digest(state: *const u64, out: *mut u8) {
    let mut d = [0u64; DIGEST_WORDS];
    for (i, lane) in d.iter_mut().enumerate() {
        *lane = read_volatile(state.add(i));
    }
    let off = out as usize & 7;
    if off == 0 {
        let out = out.cast::<u64>();
        for (i, lane) in d.iter().enumerate() {
            write_volatile(out.add(i), *lane);
        }
        return;
    }
    // Misaligned: read-modify-write the five aligned words the digest spans,
    // preserving the bytes outside it (each of the five holds digest bytes).
    let base = ((out as usize) & !7) as *mut u64;
    let s = (off * 8) as u32;
    let below = (1u64 << s) - 1; // bytes of base[0] before the digest
    write_volatile(base, (read_volatile(base) & below) | (d[0] << s));
    for i in 1..DIGEST_WORDS {
        write_volatile(base.add(i), (d[i - 1] >> (64 - s)) | (d[i] << s));
    }
    write_volatile(
        base.add(DIGEST_WORDS),
        (read_volatile(base.add(DIGEST_WORDS)) & !below) | (d[DIGEST_WORDS - 1] >> (64 - s)),
    );
}

/// Keccak-256 of the `len` bytes at `bytes`, written to the 32 bytes at `out`.
/// Either pointer may have any alignment; `out` is written only after the
/// whole input has been read.
#[inline(always)]
pub(crate) unsafe fn keccak256_into(bytes: *const u8, len: usize, out: *mut u8) {
    let mut state = MaybeUninit::<[u64; STATE_WORDS]>::uninit();
    let state = state.as_mut_ptr().cast::<u64>();
    // Capacity lanes of the initial all-zero sponge state.
    for i in RATE_WORDS..STATE_WORDS {
        write_volatile(state.add(i), 0);
    }

    let mut src = bytes;
    let mut rem = len;
    if rem < RATE_BYTES {
        // The padded message is the entire first block, i.e. the rate part of
        // the state after absorption: write it there and permute.
        merge_final_block::<false>(state, src, rem);
        permute(state);
    } else {
        // First block: absorbing into the zero state is a copy.
        if src as usize & 7 == 0 {
            copy_words::<false>(state, src.cast(), RATE_WORDS);
            permute(state);
            src = src.add(RATE_BYTES);
            rem -= RATE_BYTES;
            while rem >= RATE_BYTES {
                absorb_permute(state, src.cast());
                src = src.add(RATE_BYTES);
                rem -= RATE_BYTES;
            }
        } else {
            gather_words::<false>(state, src, RATE_WORDS);
            permute(state);
            src = src.add(RATE_BYTES);
            rem -= RATE_BYTES;
            while rem >= RATE_BYTES {
                gather_words::<true>(state, src, RATE_WORDS);
                permute(state);
                src = src.add(RATE_BYTES);
                rem -= RATE_BYTES;
            }
        }
        merge_final_block::<true>(state, src, rem);
        permute(state);
    }
    store_digest(state, out);
}

// Native differential tests (`cargo test`, no `guest` feature): `permute` and
// `absorb_permute` fall back to `keccak::f1600`, so the alignment dispatch,
// containing-word loads, gather, padding, first-block write, XOR merge and
// digest store under test are the production code. Reference: `sha3` — alloy's
// own `keccak256` cannot serve, since under `native-keccak` it calls the very
// extern being tested.
#[cfg(all(test, not(feature = "guest")))]
mod tests {
    use super::keccak256_into;
    use sha3::{Digest, Keccak256};

    fn reference(msg: &[u8]) -> [u8; 32] {
        let mut want = [0u8; 32];
        want.copy_from_slice(&Keccak256::digest(msg));
        want
    }

    /// Runs the shim with the message at byte offset `in_off` and the digest
    /// slot at byte offset `out_off` of 8-aligned buffers. Both carry a word
    /// of slack on each side, so the containing-word loads and the misaligned
    /// digest RMW stay inside the allocation; the guard bytes around the
    /// digest slot must come back untouched.
    fn shim(msg: &[u8], in_off: usize, out_off: usize) -> [u8; 32] {
        let words = (msg.len() + in_off + 8) / 8 + 2;
        let mut inbuf = vec![0x5A5A_5A5A_5A5A_5A5Au64; words];
        let inb =
            unsafe { std::slice::from_raw_parts_mut(inbuf.as_mut_ptr().cast::<u8>(), words * 8) };
        inb[8 + in_off..8 + in_off + msg.len()].copy_from_slice(msg);

        let mut outbuf = [0xA5A5_A5A5_A5A5_A5A5u64; 7];
        let outb = unsafe { std::slice::from_raw_parts_mut(outbuf.as_mut_ptr().cast::<u8>(), 56) };
        unsafe {
            keccak256_into(
                inb.as_ptr().add(8 + in_off),
                msg.len(),
                outb.as_mut_ptr().add(8 + out_off),
            )
        };

        let slot = 8 + out_off..8 + out_off + 32;
        for (i, &b) in outb.iter().enumerate() {
            if !slot.contains(&i) {
                assert_eq!(
                    b,
                    0xA5,
                    "guard byte {i} clobbered (len {}, in_off {in_off}, out_off {out_off})",
                    msg.len()
                );
            }
        }
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&outb[slot]);
        digest
    }

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    fn random_bytes(rng: &mut u64, len: usize) -> Vec<u8> {
        (0..len).map(|_| xorshift(rng) as u8).collect()
    }

    #[test]
    fn empty_message() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let want: [u8; 32] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(reference(&[]), want);
        for in_off in 0..8 {
            for out_off in 0..8 {
                assert_eq!(shim(&[], in_off, out_off), want);
            }
        }
    }

    /// Every length through four full blocks (covers rem == 0, rem == 135,
    /// t == 16, partial words spilling into the next aligned word) at every
    /// input and output alignment.
    #[test]
    fn matches_sha3_for_lengths_0_to_600_at_every_alignment() {
        let mut rng = 0x1234_5678_9abc_def0u64;
        for len in 0..=600usize {
            let msg = random_bytes(&mut rng, len);
            let want = reference(&msg);
            for in_off in 0..8 {
                for out_off in 0..8 {
                    assert_eq!(
                        shim(&msg, in_off, out_off),
                        want,
                        "len {len} in_off {in_off} out_off {out_off}"
                    );
                }
            }
        }
    }

    #[test]
    fn matches_sha3_for_random_lengths_up_to_20k() {
        let mut rng = 0xdead_beef_cafe_f00du64;
        for _ in 0..96 {
            let len = (xorshift(&mut rng) % 20_001) as usize;
            let msg = random_bytes(&mut rng, len);
            let want = reference(&msg);
            for in_off in 0..8 {
                let out_off = (xorshift(&mut rng) % 8) as usize;
                assert_eq!(
                    shim(&msg, in_off, out_off),
                    want,
                    "len {len} in_off {in_off} out_off {out_off}"
                );
            }
        }
    }
}
