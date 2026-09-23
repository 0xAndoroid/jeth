//! BLS12-381 base-field (Fq, 6 × 64-bit limbs, Montgomery form) inlines for the Jolt guest.
//!
//! Every operand is a little-endian `[u64; 6]` Montgomery-form field element `< p` at an
//! 8-byte-aligned address; every result is canonical (`< p`). Operands are loaded before any
//! store, so the output may alias either input.
//!
//! - `0x0` MULP:   out = a · b · R⁻¹ mod p                      (rs1 → a, rs2 → b, rd → out)
//! - `0x1` SOPP2:  out = (a₀·b₀ + a₁·b₁) · R⁻¹ mod p             (rs1 → [a₀, a₁], rs2 → [b₀, b₁], rd → out)
//! - `0x2` FP2MUL: (out₀, out₁) = (a₀ + a₁u)(b₀ + b₁u), u² = −1  (rs1 → [a₀, a₁], rs2 → [b₀, b₁], rd → [out₀, out₁])
//!
//! The sequences are deterministic product-scanning Montgomery multiplications (no advice rows).

#![cfg_attr(not(feature = "host"), no_std)]

pub const INLINE_OPCODE: u32 = 0x2B;
pub const FUNCT7: u32 = 0x01;

pub const MULP_FUNCT3: u32 = 0x0;
pub const MULP_NAME: &str = "BLS12_381_MULP";
pub const SOPP2_FUNCT3: u32 = 0x1;
pub const SOPP2_NAME: &str = "BLS12_381_SOPP2";
pub const FP2MUL_FUNCT3: u32 = 0x2;
pub const FP2MUL_NAME: &str = "BLS12_381_FP2MUL";

/// Number of 64-bit limbs of a field element.
pub const LIMBS: usize = 6;

/// p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
/// (little-endian limbs).
pub const MODULUS: [u64; LIMBS] = [
    0xb9fe_ffff_ffff_aaab,
    0x1eab_fffe_b153_ffff,
    0x6730_d2a0_f6b0_f624,
    0x6477_4b84_f385_12bf,
    0x4b1b_a7b6_434b_acd7,
    0x1a01_11ea_397f_e69a,
];

/// −p⁻¹ mod 2⁶⁴.
pub const INV: u64 = 0x89f3_fffc_fffc_fffd;

/// −1 in Montgomery form, i.e. p − (R mod p): the Fp2 nonresidue the fused multiplication assumes.
pub const MINUS_ONE: [u64; LIMBS] = [
    0x43f5_ffff_fffc_aaae,
    0x32b7_fff2_ed47_fffd,
    0x07e8_3a49_a2e9_9d69,
    0xeca8_f331_8332_bb7a,
    0xef14_8d1e_a0f4_c069,
    0x040a_b326_3eff_0206,
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
