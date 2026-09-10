//! Guest entry points: the round ops and the compression built around them.
use crate::{IV, STATE_LEN};

/// `R` rounds (sigma rows `0..R`, `R ∈ 1..=10`) of `v` with message `m`, in place.
///
/// Memory contract: `v` (rs1) is read then written, `m` (rs2) is read; both 16 words, 8-byte
/// aligned. Off the RISC-V target this is the software reference the inline is tested against.
#[inline(always)]
pub fn round_op<const R: usize>(v: &mut [u64; STATE_LEN], m: &[u64; STATE_LEN]) {
    #[cfg(target_arch = "riscv64")]
    // SAFETY: both arrays are 8-byte aligned and exactly the 128 bytes the inline reads; only
    // `v` is written.
    unsafe {
        core::arch::asm!(
            ".insn r {opcode}, {funct3}, {funct7}, x0, {rs1}, {rs2}",
            opcode = const crate::INLINE_OPCODE,
            funct3 = const crate::funct3(R),
            funct7 = const crate::funct7(R),
            rs1 = in(reg) v.as_mut_ptr(),
            rs2 = in(reg) m.as_ptr(),
            options(nostack)
        );
    }
    #[cfg(not(target_arch = "riscv64"))]
    crate::rounds_reference(v, m, R);
}

/// BLAKE2b compression `F(h, m, t, f)` with an arbitrary round count (EIP-152 / RFC 7693 §3.2):
/// software initialization and finalization around `rounds / 10` ten-round ops and one
/// `rounds % 10`-round op.
pub fn compress(rounds: u32, h: &mut [u64; 8], m: &[u64; STATE_LEN], t: &[u64; 2], f: bool) {
    let mut v = [0u64; STATE_LEN];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t[0];
    v[13] ^= t[1];
    if f {
        v[14] = !v[14];
    }
    for _ in 0..rounds / 10 {
        round_op::<10>(&mut v, m);
    }
    match rounds % 10 {
        0 => {}
        1 => round_op::<1>(&mut v, m),
        2 => round_op::<2>(&mut v, m),
        3 => round_op::<3>(&mut v, m),
        4 => round_op::<4>(&mut v, m),
        5 => round_op::<5>(&mut v, m),
        6 => round_op::<6>(&mut v, m),
        7 => round_op::<7>(&mut v, m),
        8 => round_op::<8>(&mut v, m),
        _ => round_op::<9>(&mut v, m),
    }
    for (h, (lo, hi)) in h.iter_mut().zip(v[..8].iter().zip(&v[8..])) {
        *h ^= lo ^ hi;
    }
}
