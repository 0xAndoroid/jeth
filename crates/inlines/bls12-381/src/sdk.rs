//! Guest entry points. On riscv64 guest builds each function is the raw inline instruction; with the
//! `host` feature it is the software reference (`exec`), which is also what the tests compare against.

#[cfg(all(not(feature = "host"), target_arch = "riscv64"))]
macro_rules! inline_insn {
    ($funct3:expr, $out:expr, $a:expr, $b:expr) => {
        core::arch::asm!(
            ".insn r {opcode}, {funct3}, {funct7}, {rd}, {rs1}, {rs2}",
            opcode = const crate::INLINE_OPCODE,
            funct3 = const $funct3,
            funct7 = const crate::FUNCT7,
            rd = in(reg) $out,
            rs1 = in(reg) $a,
            rs2 = in(reg) $b,
            options(nostack)
        )
    };
}

#[cfg(feature = "host")]
macro_rules! inline_insn {
    ($funct3:expr, $out:expr, $a:expr, $b:expr) => {{
        let (out, a, b): (*mut u64, *const u64, *const u64) = ($out, $a, $b);
        match $funct3 {
            crate::MULP_FUNCT3 => {
                let r = crate::exec::mulp(&*(a as *const [u64; 6]), &*(b as *const [u64; 6]));
                core::ptr::copy_nonoverlapping(r.as_ptr(), out, 6);
            }
            crate::SOPP2_FUNCT3 => {
                let r = crate::exec::sopp2(
                    &*(a as *const [[u64; 6]; 2]),
                    &*(b as *const [[u64; 6]; 2]),
                );
                core::ptr::copy_nonoverlapping(r.as_ptr(), out, 6);
            }
            _ => {
                let r = crate::exec::fp2mul(
                    &*(a as *const [[u64; 6]; 2]),
                    &*(b as *const [[u64; 6]; 2]),
                );
                core::ptr::copy_nonoverlapping(r.as_ptr().cast::<u64>(), out, 12);
            }
        }
    }};
}

#[cfg(all(not(feature = "host"), not(target_arch = "riscv64")))]
macro_rules! inline_insn {
    ($funct3:expr, $out:expr, $a:expr, $b:expr) => {{
        let _ = ($funct3, $out, $a, $b);
        panic!("BLS12-381 inlines require a riscv64 guest or the host feature")
    }};
}

/// `out[0..6] = a[0..6] · b[0..6] · R⁻¹ mod p`.
///
/// # Safety
/// `a`, `b` and `out` must be 8-byte aligned and valid for 6 `u64` words holding field elements
/// `< p`; `out` may alias either input.
#[inline(always)]
pub unsafe fn mulp(out: *mut u64, a: *const u64, b: *const u64) {
    inline_insn!(crate::MULP_FUNCT3, out, a, b)
}

/// `out[0..6] = (a[0..6] · b[0..6] + a[6..12] · b[6..12]) · R⁻¹ mod p`.
///
/// # Safety
/// `a` and `b` must be 8-byte aligned and valid for 12 `u64` words holding field elements `< p`;
/// `out` must be 8-byte aligned and valid for 6 words and may alias either input.
#[inline(always)]
pub unsafe fn sopp2(out: *mut u64, a: *const u64, b: *const u64) {
    inline_insn!(crate::SOPP2_FUNCT3, out, a, b)
}

/// `out[0..12] = (a[0..6] + a[6..12]·u) · (b[0..6] + b[6..12]·u)` in Fp2 = Fp[u]/(u² + 1).
///
/// # Safety
/// `a`, `b` and `out` must be 8-byte aligned and valid for 12 `u64` words holding field elements
/// `< p`; `out` may alias either input.
#[inline(always)]
pub unsafe fn fp2mul(out: *mut u64, a: *const u64, b: *const u64) {
    inline_insn!(crate::FP2MUL_FUNCT3, out, a, b)
}
