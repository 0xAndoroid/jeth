//! Expansion of one round op: load `v` and `m` into inline registers, emit the rounds' G
//! functions, store `v`.
//!
//! Rows: 32 loads + 80 per round (8 G × 10) + 16 stores + 32 register resets = `80·R + 80`.

use crate::{SIGMA, STATE_LEN};
use jolt_inlines_sdk::host::{
    ExpandedInstructionSequence, ExpansionError, InlineBuilderExt, InlineExpansionBuilder,
    InlineOp, InlineOperands, InlineRegister, NoAdvice,
};
use jolt_inlines_sdk::jolt_asm;

const NEEDED_REGISTERS: usize = 2 * STATE_LEN;
/// `vr[0..16]`: working state `v`; `vr[16..32]`: message block `m`.
const VR_MESSAGE: usize = STATE_LEN;

/// `ROUNDS` BLAKE2b rounds (sigma rows `0..ROUNDS`) over the 16 words at rs1 with the 16 message
/// words at rs2; rs1 is read then written, rs2 only read.
pub struct Blake2bRounds<const ROUNDS: usize>;

impl<const ROUNDS: usize> InlineOp for Blake2bRounds<ROUNDS> {
    type Advice = NoAdvice;

    const OPCODE: u32 = crate::INLINE_OPCODE;
    const FUNCT3: u32 = crate::funct3(ROUNDS);
    const FUNCT7: u32 = crate::funct7(ROUNDS);
    const NAME: &'static str = crate::name(ROUNDS);

    fn build_sequence(
        mut asm: InlineExpansionBuilder,
        operands: InlineOperands,
    ) -> Result<ExpandedInstructionSequence, ExpansionError> {
        let vr = asm.allocate_inline_array::<NEEDED_REGISTERS>()?;
        asm.load_u64_range(operands.rs1, 0, &vr[..STATE_LEN]);
        asm.load_u64_range(operands.rs2, 0, &vr[VR_MESSAGE..]);
        for round in 0..ROUNDS {
            let s = &SIGMA[round % 10];
            g(&mut asm, &vr, [0, 4, 8, 12], s[0], s[1]);
            g(&mut asm, &vr, [1, 5, 9, 13], s[2], s[3]);
            g(&mut asm, &vr, [2, 6, 10, 14], s[4], s[5]);
            g(&mut asm, &vr, [3, 7, 11, 15], s[6], s[7]);
            g(&mut asm, &vr, [0, 5, 10, 15], s[8], s[9]);
            g(&mut asm, &vr, [1, 6, 11, 12], s[10], s[11]);
            g(&mut asm, &vr, [2, 7, 8, 13], s[12], s[13]);
            g(&mut asm, &vr, [3, 4, 9, 14], s[14], s[15]);
        }
        asm.store_u64_range(operands.rs1, 0, &vr[..STATE_LEN]);
        asm.release_many(vr);
        asm.finalize()
    }
}

/// RFC 7693 §3.1 `G(v, a, b, c, d, x, y)` with the fused xor-rotate rows.
fn g(
    asm: &mut InlineExpansionBuilder,
    vr: &[InlineRegister; NEEDED_REGISTERS],
    [a, b, c, d]: [usize; 4],
    x: usize,
    y: usize,
) {
    let (va, vb, vc, vd) = (*vr[a], *vr[b], *vr[c], *vr[d]);
    let (mx, my) = (*vr[VR_MESSAGE + x], *vr[VR_MESSAGE + y]);
    jolt_asm!(asm, {
        add va, va, vb;
        add va, va, mx;
        xorrot32 vd, vd, va;
        add vc, vc, vd;
        xorrot24 vb, vb, vc;
        add va, va, vb;
        add va, va, my;
        xorrot16 vd, vd, va;
        add vc, vc, vd;
        xorrot63 vb, vb, vc;
    });
}
