//! bn254 base-field Montgomery multiplication inlines for the Jolt guest.
//!
//! Three deterministic (advice-free) inlines over the ark-ff limb layout, dispatched from the
//! vendored ark-ff `MontBackend`/`QuadExtField` arithmetic in guest builds:
//! `BN254_MULQ` (one product), `BN254_SOPQ2` (two-term sum of products) and `BN254_FP2MULQ`
//! (a full Fq2 multiplication). Each computes the Montgomery reduction (Σ aᵢ·bᵢ + m·q) / 2^256
//! and returns it in [0, 2q); the caller performs the final conditional subtraction.

#![cfg_attr(not(feature = "host"), no_std)]

/// custom-1 opcode: user-defined inlines.
pub const INLINE_OPCODE: u32 = 0x2B;
pub const BN254_FUNCT7: u32 = 0x00;

pub const BN254_MULQ_FUNCT3: u32 = 0x00;
pub const BN254_MULQ_NAME: &str = "BN254_MULQ";

pub const BN254_SOPQ2_FUNCT3: u32 = 0x02;
pub const BN254_SOPQ2_NAME: &str = "BN254_SOPQ2";

pub const BN254_FP2MULQ_FUNCT3: u32 = 0x03;
pub const BN254_FP2MULQ_NAME: &str = "BN254_FP2MULQ";

/// bn254 base field modulus q (little-endian u64 limbs).
pub const BN254_MODULUS: [u64; 4] = [
    0x3c20_8c16_d87c_fd47,
    0x9781_6a91_6871_ca8d,
    0xb850_45b6_8181_585d,
    0x3064_4e72_e131_a029,
];

/// −q⁻¹ mod 2^64.
pub const BN254_INV: u64 = 0x87d2_0782_e486_6389;

/// −1 in Montgomery form (q − 2^256 mod q): the Fq2 nonresidue the fused product implements.
pub const BN254_MINUS_ONE: [u64; 4] = [
    0x68c3_4889_12ed_efaa,
    0x8d08_7f68_72aa_bf4f,
    0x51e1_a247_0908_1231,
    0x2259_d6b1_4729_c0fa,
];

pub mod sdk;
pub use sdk::*;

#[cfg(feature = "host")]
pub mod exec;
#[cfg(feature = "host")]
pub mod sequence_builder;

#[cfg(feature = "host")]
mod host;
#[cfg(feature = "host")]
pub use host::*;

#[cfg(all(test, feature = "host"))]
mod spec;
#[cfg(all(test, feature = "host"))]
mod tests;
