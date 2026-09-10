//! Guest entry points (riscv64 builds) and their software fallbacks (`host` feature).
//!
//! Memory contract, shared by every entry point: u64 limbs, little-endian, 8-byte aligned; the
//! sequence performs all loads before its first store, so `out` may alias `a` or `b`.
//!
//! | entry | reads | writes |
//! |---|---|---|
//! | `mulq` | `a[0..4]`, `b[0..4]` | `out[0..4]` = (a·b + m·q) / 2^256 |
//! | `sopq2` | `a[0..8]`, `b[0..8]` | `out[0..4]` = (a₀·b₀ + a₁·b₁ + m·q) / 2^256 |
//! | `fp2mulq` | `a[0..8]`, `b[0..8]` | `out[0..4]` = REDC(a₀·b₀ + a₁·(q − b₁)), `out[4..8]` = REDC(a₀·b₁ + a₁·b₀) |
//!
//! with m the unique value in [0, 2^256) making the numerator divisible by 2^256. For operands
//! below q every result is below 2q.

#[cfg(all(not(feature = "host"), target_arch = "riscv64"))]
macro_rules! insn {
    ($funct3:expr, $out:expr, $a:expr, $b:expr) => {
        core::arch::asm!(
            ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
            opcode = const crate::INLINE_OPCODE,
            funct3 = const $funct3,
            funct7 = const crate::BN254_FUNCT7,
            rd = in(reg) $out,
            rs1 = in(reg) $a,
            rs2 = in(reg) $b,
            options(nostack)
        )
    };
}

/// `out[0..4] = (a·b + m·q) / 2^256`.
///
/// # Safety
/// `a` and `b` must be readable for 32 bytes and `out` writable for 32 bytes, all 8-byte aligned.
#[cfg(all(not(feature = "host"), target_arch = "riscv64"))]
#[inline(always)]
pub unsafe fn mulq(out: *mut u64, a: *const u64, b: *const u64) {
    insn!(crate::BN254_MULQ_FUNCT3, out, a, b);
}

/// `out[0..4] = (a[0..4]·b[0..4] + a[4..8]·b[4..8] + m·q) / 2^256`.
///
/// # Safety
/// `a` and `b` must be readable for 64 bytes and `out` writable for 32 bytes, all 8-byte aligned.
#[cfg(all(not(feature = "host"), target_arch = "riscv64"))]
#[inline(always)]
pub unsafe fn sopq2(out: *mut u64, a: *const u64, b: *const u64) {
    insn!(crate::BN254_SOPQ2_FUNCT3, out, a, b);
}

/// Fq2 product for the nonresidue −1: `out[0..4] = REDC(a₀·b₀ + a₁·(q − b₁))`,
/// `out[4..8] = REDC(a₀·b₁ + a₁·b₀)`.
///
/// # Safety
/// `a` and `b` must be readable for 64 bytes and `out` writable for 64 bytes, all 8-byte aligned.
#[cfg(all(not(feature = "host"), target_arch = "riscv64"))]
#[inline(always)]
pub unsafe fn fp2mulq(out: *mut u64, a: *const u64, b: *const u64) {
    insn!(crate::BN254_FP2MULQ_FUNCT3, out, a, b);
}

/// # Safety
/// Never returns: the inline exists only on riscv64 guests or with the `host` model.
#[cfg(all(not(feature = "host"), not(target_arch = "riscv64")))]
pub unsafe fn mulq(_out: *mut u64, _a: *const u64, _b: *const u64) {
    panic!("bn254 mulq requires a riscv64 target or the host feature");
}

/// # Safety
/// Never returns: the inline exists only on riscv64 guests or with the `host` model.
#[cfg(all(not(feature = "host"), not(target_arch = "riscv64")))]
pub unsafe fn sopq2(_out: *mut u64, _a: *const u64, _b: *const u64) {
    panic!("bn254 sopq2 requires a riscv64 target or the host feature");
}

/// # Safety
/// Never returns: the inline exists only on riscv64 guests or with the `host` model.
#[cfg(all(not(feature = "host"), not(target_arch = "riscv64")))]
pub unsafe fn fp2mulq(_out: *mut u64, _a: *const u64, _b: *const u64) {
    panic!("bn254 fp2mulq requires a riscv64 target or the host feature");
}

/// Software model of `BN254_MULQ`.
///
/// # Safety
/// Same contract as the guest entry point.
#[cfg(feature = "host")]
pub unsafe fn mulq(out: *mut u64, a: *const u64, b: *const u64) {
    let result = crate::exec::mulq(&*(a as *const [u64; 4]), &*(b as *const [u64; 4]));
    core::ptr::copy_nonoverlapping(result.as_ptr(), out, 4);
}

/// Software model of `BN254_SOPQ2`.
///
/// # Safety
/// Same contract as the guest entry point.
#[cfg(feature = "host")]
pub unsafe fn sopq2(out: *mut u64, a: *const u64, b: *const u64) {
    let result = crate::exec::sopq2(&*(a as *const [u64; 8]), &*(b as *const [u64; 8]));
    core::ptr::copy_nonoverlapping(result.as_ptr(), out, 4);
}

/// Software model of `BN254_FP2MULQ`.
///
/// # Safety
/// Same contract as the guest entry point.
#[cfg(feature = "host")]
pub unsafe fn fp2mulq(out: *mut u64, a: *const u64, b: *const u64) {
    let result = crate::exec::fp2mulq(&*(a as *const [u64; 8]), &*(b as *const [u64; 8]));
    core::ptr::copy_nonoverlapping(result.as_ptr(), out, 8);
}
