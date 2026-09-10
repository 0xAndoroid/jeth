//! BLAKE2b round inlines: `k` compression rounds over a 16-word working state kept in memory.
//!
//! One op per round count `k ∈ 1..=10`, all starting at sigma row 0. Because the BLAKE2b message
//! schedule cycles with period 10, `rounds = 10·q + r` is `q` applications of the 10-round op
//! followed by the `r`-round op (`r > 0`), each picking up where the previous one left off.
//! Encoding (opcode 0x2B): `k = 10` and `k = 1..=7` use funct7 [`FUNCT7_LOW`] with funct3
//! `k % 10`; `k = 8, 9` use funct7 [`FUNCT7_HIGH`] with funct3 `k − 8`.
#![cfg_attr(not(feature = "host"), no_std)]

pub const INLINE_OPCODE: u32 = 0x2B;
/// funct7 of the block holding the 10-round op (funct3 0) and the 1..=7-round ops (funct3 = k).
pub const FUNCT7_LOW: u32 = 0x02;
/// funct7 of the block holding the 8- and 9-round ops (funct3 0 and 1).
pub const FUNCT7_HIGH: u32 = 0x03;

/// Working-state and message-block length in 64-bit words.
pub const STATE_LEN: usize = 16;
/// Every round count with an op, in registration order.
pub const ROUND_COUNTS: [usize; 10] = [10, 1, 2, 3, 4, 5, 6, 7, 8, 9];

pub const fn funct3(rounds: usize) -> u32 {
    ((rounds % 10) % 8) as u32
}

pub const fn funct7(rounds: usize) -> u32 {
    FUNCT7_LOW + ((rounds % 10) / 8) as u32
}

pub const fn name(rounds: usize) -> &'static str {
    match rounds {
        1 => "BLAKE2B_ROUNDS_1",
        2 => "BLAKE2B_ROUNDS_2",
        3 => "BLAKE2B_ROUNDS_3",
        4 => "BLAKE2B_ROUNDS_4",
        5 => "BLAKE2B_ROUNDS_5",
        6 => "BLAKE2B_ROUNDS_6",
        7 => "BLAKE2B_ROUNDS_7",
        8 => "BLAKE2B_ROUNDS_8",
        9 => "BLAKE2B_ROUNDS_9",
        10 => "BLAKE2B_ROUNDS_10",
        _ => panic!("round count without an inline"),
    }
}

/// BLAKE2b initialization vector (RFC 7693 §2.6).
pub const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

/// BLAKE2b message schedule (RFC 7693 §2.7); round `i` uses row `i % 10`.
pub const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// `rounds` BLAKE2b rounds over `v` with message `m`, sigma rows `0, 1, …` (RFC 7693 §3.2 round
/// loop) — the semantics every round op is checked against.
pub fn rounds_reference(v: &mut [u64; STATE_LEN], m: &[u64; STATE_LEN], rounds: usize) {
    for round in 0..rounds {
        let s = &SIGMA[round % 10];
        g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
}

fn g(v: &mut [u64; STATE_LEN], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

pub mod sdk;
pub use sdk::*;

#[cfg(feature = "host")]
pub mod sequence_builder;

#[cfg(feature = "host")]
mod host;
#[cfg(feature = "host")]
pub use host::*;

#[cfg(all(test, feature = "host"))]
mod spec;
