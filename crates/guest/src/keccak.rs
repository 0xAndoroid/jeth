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
//! to 4–9 rows, misaligned `LD`/`SD` trap): every memory access below is an
//! 8-aligned `LD`/`SD`. Partial words are assembled from the aligned word(s)
//! that contain them — the containing-word pattern `mem.rs` uses for memcpy
//! boundaries — and the final block is padded word-wise, so no memset/memcpy
//! call and no byte store is ever issued.
//!
//! Volatile word ops keep LLVM from re-forming memset/memcpy calls out of the
//! copy/zero loops (the guest overrides those symbols) and from merging the
//! zero stores; they cost the same one row per `LD`/`SD`.
//!
//! Containing-word accesses: for a byte range `[p, p + n)` with `n >= 1` the
//! aligned words touched are exactly those holding at least one live byte, so
//! on the guest (flat, word-granular RAM — see `mem.rs`) they are addressable.
//! Those words also hold bytes outside the caller's slice (and the five-word
//! RMW of a misaligned digest slot writes them back unchanged), which no Rust
//! memory access may touch, so on riscv64 they are inline-asm `ld`/`sd`
//! ([`load_word`], [`store_word`]) that neither the abstract machine nor LLVM
//! sees as accesses to the caller's objects. Other targets build only the
//! native tests (`crates/guest/native-tests`), whose buffers carry word-sized
//! slack on both ends so the same accesses stay inside the allocation.

use super::mem::{load_word, store_word};
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
    let mut cur = load_word::<0>(base);
    for i in 0..n {
        let next = load_word::<1>(base.wrapping_add(i));
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

    let t = rem >> 3;
    let r = rem & 7;
    let off = src as usize & 7;
    let data = if off == 0 {
        copy_words::<XOR>(dst, src.cast(), t);
        // The word at src + 8t holds stream bytes only when r > 0.
        if r != 0 {
            load_word::<0>(src.cast::<u64>().add(t))
        } else {
            0
        }
    } else if rem != 0 {
        let s = (off * 8) as u32;
        let base = ((src as usize) & !7) as *const u64;
        let lo = gather_words::<XOR>(dst, src, t) >> s;
        // W[t + 1] holds stream bytes only when the partial word spills into it.
        if off + r > 8 {
            lo | (load_word::<1>(base.wrapping_add(t)) << (64 - s))
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

/// Write each rate lane once for a fixed short message, including both
/// padding bytes. Partial containing words obey the generic path's bounds.
#[inline(always)]
unsafe fn merge_short_block<const LEN: usize>(state: *mut u64, bytes: *const u8) {
    const {
        assert!(LEN < RATE_BYTES);
    }
    let words = LEN / 8;
    let tail = LEN & 7;
    let off = bytes as usize & 7;
    let data = if off == 0 {
        copy_words::<false>(state, bytes.cast(), words);
        if tail == 0 {
            0
        } else {
            load_word::<0>(bytes.cast::<u64>().add(words))
        }
    } else if LEN != 0 {
        let last = gather_words::<false>(state, bytes, words);
        if tail == 0 {
            0
        } else {
            let shift = (off * 8) as u32;
            let low = last >> shift;
            if off + tail > 8 {
                let base = (bytes as usize & !7) as *const u64;
                low | (load_word::<1>(base.wrapping_add(words)) << (64 - shift))
            } else {
                low
            }
        }
    } else {
        0
    };
    let pad = 1u64 << (8 * tail);
    let top = ((LEN >> 7) as u64) << 63;
    write_volatile(state.add(words), (data & (pad - 1)) | pad | top);
    for i in words + 1..RATE_WORDS - 1 {
        write_volatile(state.add(i), 0);
    }
    if words < RATE_WORDS - 1 {
        write_volatile(state.add(RATE_WORDS - 1), 1 << 63);
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
    let below = (1u64 << s) - 1;
    store_word::<0>(base, (load_word::<0>(base) & below) | (d[0] << s));
    for i in 1..DIGEST_WORDS {
        write_volatile(base.wrapping_add(i), (d[i - 1] >> (64 - s)) | (d[i] << s));
    }
    store_word::<DIGEST_WORDS>(
        base,
        (load_word::<DIGEST_WORDS>(base) & !below) | (d[DIGEST_WORDS - 1] >> (64 - s)),
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
        // Every possible short length selects the same padding grammar with
        // constant lane counts. The range guard above makes the fallback dead.
        match rem {
            0 => merge_short_block::<0>(state, src),
            1 => merge_short_block::<1>(state, src),
            2 => merge_short_block::<2>(state, src),
            3 => merge_short_block::<3>(state, src),
            4 => merge_short_block::<4>(state, src),
            5 => merge_short_block::<5>(state, src),
            6 => merge_short_block::<6>(state, src),
            7 => merge_short_block::<7>(state, src),
            8 => merge_short_block::<8>(state, src),
            9 => merge_short_block::<9>(state, src),
            10 => merge_short_block::<10>(state, src),
            11 => merge_short_block::<11>(state, src),
            12 => merge_short_block::<12>(state, src),
            13 => merge_short_block::<13>(state, src),
            14 => merge_short_block::<14>(state, src),
            15 => merge_short_block::<15>(state, src),
            16 => merge_short_block::<16>(state, src),
            17 => merge_short_block::<17>(state, src),
            18 => merge_short_block::<18>(state, src),
            19 => merge_short_block::<19>(state, src),
            20 => merge_short_block::<20>(state, src),
            21 => merge_short_block::<21>(state, src),
            22 => merge_short_block::<22>(state, src),
            23 => merge_short_block::<23>(state, src),
            24 => merge_short_block::<24>(state, src),
            25 => merge_short_block::<25>(state, src),
            26 => merge_short_block::<26>(state, src),
            27 => merge_short_block::<27>(state, src),
            28 => merge_short_block::<28>(state, src),
            29 => merge_short_block::<29>(state, src),
            30 => merge_short_block::<30>(state, src),
            31 => merge_short_block::<31>(state, src),
            32 => merge_short_block::<32>(state, src),
            33 => merge_short_block::<33>(state, src),
            34 => merge_short_block::<34>(state, src),
            35 => merge_short_block::<35>(state, src),
            36 => merge_short_block::<36>(state, src),
            37 => merge_short_block::<37>(state, src),
            38 => merge_short_block::<38>(state, src),
            39 => merge_short_block::<39>(state, src),
            40 => merge_short_block::<40>(state, src),
            41 => merge_short_block::<41>(state, src),
            42 => merge_short_block::<42>(state, src),
            43 => merge_short_block::<43>(state, src),
            44 => merge_short_block::<44>(state, src),
            45 => merge_short_block::<45>(state, src),
            46 => merge_short_block::<46>(state, src),
            47 => merge_short_block::<47>(state, src),
            48 => merge_short_block::<48>(state, src),
            49 => merge_short_block::<49>(state, src),
            50 => merge_short_block::<50>(state, src),
            51 => merge_short_block::<51>(state, src),
            52 => merge_short_block::<52>(state, src),
            53 => merge_short_block::<53>(state, src),
            54 => merge_short_block::<54>(state, src),
            55 => merge_short_block::<55>(state, src),
            56 => merge_short_block::<56>(state, src),
            57 => merge_short_block::<57>(state, src),
            58 => merge_short_block::<58>(state, src),
            59 => merge_short_block::<59>(state, src),
            60 => merge_short_block::<60>(state, src),
            61 => merge_short_block::<61>(state, src),
            62 => merge_short_block::<62>(state, src),
            63 => merge_short_block::<63>(state, src),
            64 => merge_short_block::<64>(state, src),
            65 => merge_short_block::<65>(state, src),
            66 => merge_short_block::<66>(state, src),
            67 => merge_short_block::<67>(state, src),
            68 => merge_short_block::<68>(state, src),
            69 => merge_short_block::<69>(state, src),
            70 => merge_short_block::<70>(state, src),
            71 => merge_short_block::<71>(state, src),
            72 => merge_short_block::<72>(state, src),
            73 => merge_short_block::<73>(state, src),
            74 => merge_short_block::<74>(state, src),
            75 => merge_short_block::<75>(state, src),
            76 => merge_short_block::<76>(state, src),
            77 => merge_short_block::<77>(state, src),
            78 => merge_short_block::<78>(state, src),
            79 => merge_short_block::<79>(state, src),
            80 => merge_short_block::<80>(state, src),
            81 => merge_short_block::<81>(state, src),
            82 => merge_short_block::<82>(state, src),
            83 => merge_short_block::<83>(state, src),
            84 => merge_short_block::<84>(state, src),
            85 => merge_short_block::<85>(state, src),
            86 => merge_short_block::<86>(state, src),
            87 => merge_short_block::<87>(state, src),
            88 => merge_short_block::<88>(state, src),
            89 => merge_short_block::<89>(state, src),
            90 => merge_short_block::<90>(state, src),
            91 => merge_short_block::<91>(state, src),
            92 => merge_short_block::<92>(state, src),
            93 => merge_short_block::<93>(state, src),
            94 => merge_short_block::<94>(state, src),
            95 => merge_short_block::<95>(state, src),
            96 => merge_short_block::<96>(state, src),
            97 => merge_short_block::<97>(state, src),
            98 => merge_short_block::<98>(state, src),
            99 => merge_short_block::<99>(state, src),
            100 => merge_short_block::<100>(state, src),
            101 => merge_short_block::<101>(state, src),
            102 => merge_short_block::<102>(state, src),
            103 => merge_short_block::<103>(state, src),
            104 => merge_short_block::<104>(state, src),
            105 => merge_short_block::<105>(state, src),
            106 => merge_short_block::<106>(state, src),
            107 => merge_short_block::<107>(state, src),
            108 => merge_short_block::<108>(state, src),
            109 => merge_short_block::<109>(state, src),
            110 => merge_short_block::<110>(state, src),
            111 => merge_short_block::<111>(state, src),
            112 => merge_short_block::<112>(state, src),
            113 => merge_short_block::<113>(state, src),
            114 => merge_short_block::<114>(state, src),
            115 => merge_short_block::<115>(state, src),
            116 => merge_short_block::<116>(state, src),
            117 => merge_short_block::<117>(state, src),
            118 => merge_short_block::<118>(state, src),
            119 => merge_short_block::<119>(state, src),
            120 => merge_short_block::<120>(state, src),
            121 => merge_short_block::<121>(state, src),
            122 => merge_short_block::<122>(state, src),
            123 => merge_short_block::<123>(state, src),
            124 => merge_short_block::<124>(state, src),
            125 => merge_short_block::<125>(state, src),
            126 => merge_short_block::<126>(state, src),
            127 => merge_short_block::<127>(state, src),
            128 => merge_short_block::<128>(state, src),
            129 => merge_short_block::<129>(state, src),
            130 => merge_short_block::<130>(state, src),
            131 => merge_short_block::<131>(state, src),
            132 => merge_short_block::<132>(state, src),
            133 => merge_short_block::<133>(state, src),
            134 => merge_short_block::<134>(state, src),
            135 => merge_short_block::<135>(state, src),
            _ => unreachable!(),
        }
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

// Native differential tests (`cargo test --manifest-path
// crates/guest/native-tests/Cargo.toml`, no `guest` feature): `permute` and
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
    fn overlapping_input_output_matches_reference() {
        let mut rng = 0xa4b3_c2d1_e0f9_8765u64;
        // Includes the address, storage-key, pair and bloom input sizes.
        for len in (0..=300).chain([308, 340, 372, 404, 436, 468, 500, 512, 532, 1024, 2048]) {
            let msg = random_bytes(&mut rng, len);
            let want = reference(&msg);
            for input_offset in 0..8 {
                for output_offset in 0..8 {
                    let mut storage = vec![0u64; (len + 96) / 8 + 1];
                    let base = storage.as_mut_ptr().cast::<u8>();
                    unsafe {
                        let input = base.add(8 + input_offset);
                        let output = base.add(8 + output_offset);
                        core::ptr::copy_nonoverlapping(msg.as_ptr(), input, len);
                        keccak256_into(input, len, output);
                        assert_eq!(core::slice::from_raw_parts(output, 32), &want);
                    }
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
