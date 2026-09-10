use jolt_inlines_sdk::host::{
    ExpandedInstructionSequence, ExpansionError, InlineExpansionBuilder, InlineOp, InlineOperands,
    InlineRegister, Kind, NoAdvice,
};

use crate::{BN254_INV, BN254_MODULUS};

const LIMBS: usize = 4;
type Limbs = [InlineRegister; LIMBS];

/// Product-scanning Montgomery reduction over 64-bit limbs.
///
/// Column k of Σ aᵖ·bᵖ + m·q accumulates lo(x_i·y_j) for i + j = k and hi(x_i·y_j) for
/// i + j = k − 1 in `r[k % 2]`, with the carry count in `r[(k + 1) % 2]`. For k < 4 the column
/// value fixes m_k = r_k · (−q⁻¹) mod 2^64, and the term lo(m_k·q_0) is never computed:
/// r_k + lo(m_k·q_0) ≡ 0 (mod 2^64), so its only effect is a carry of one exactly when r_k ≠ 0.
/// Columns 4..8 are the result limbs. With every operand below q the result is below 2q < 2^255,
/// so column 7 cannot carry out and is accumulated without carry tracking.
struct Montgomery {
    asm: InlineExpansionBuilder,
    q: Limbs,
    m: Limbs,
    r: [InlineRegister; 2],
    aux: InlineRegister,
    operands: Vec<Limbs>,
}

struct Column {
    first: bool,
    last: bool,
}

impl Montgomery {
    fn new(mut asm: InlineExpansionBuilder) -> Result<Self, ExpansionError> {
        let q = asm.allocate_inline_array()?;
        let m = asm.allocate_inline_array()?;
        let r = asm.allocate_inline_array()?;
        let aux = asm.allocate_for_inline()?;
        Ok(Self {
            asm,
            q,
            m,
            r,
            aux,
            operands: Vec::new(),
        })
    }

    /// Loads four limbs from `base + offset`.
    fn load(&mut self, base: u8, offset: i64) -> Result<Limbs, ExpansionError> {
        let regs: Limbs = self.asm.allocate_inline_array()?;
        for (i, reg) in regs.iter().enumerate() {
            self.asm
                .emit_ld(Kind::LD, **reg, base, offset + 8 * i as i64);
        }
        self.operands.push(regs);
        Ok(regs)
    }

    fn load_modulus(&mut self) {
        for (reg, limb) in self.q.iter().zip(BN254_MODULUS) {
            self.asm.emit_u(Kind::LUI, **reg, limb);
        }
    }

    /// Adds one half-product to the column: `kind` ∈ {MUL, MULHU}.
    fn term(&mut self, kind: Kind, x: u8, y: u8, lo: u8, hi: u8, column: &mut Column) {
        let aux = *self.aux;
        self.asm.emit_r(kind, aux, x, y);
        self.asm.emit_r(Kind::ADD, lo, lo, aux);
        if column.last {
            return;
        }
        if column.first {
            self.asm.emit_r(Kind::SLTU, hi, lo, aux);
            column.first = false;
        } else {
            self.asm.emit_r(Kind::SLTU, aux, lo, aux);
            self.asm.emit_r(Kind::ADD, hi, hi, aux);
        }
    }

    /// Stores (Σ a·b + m·q) / 2^256 as four limbs at `base + offset`.
    fn redc_sum(&mut self, pairs: &[(Limbs, Limbs)], base: u8, offset: i64) {
        for k in 0..2 * LIMBS {
            let (lo, hi) = (*self.r[k % 2], *self.r[(k + 1) % 2]);
            let mut column = Column {
                first: true,
                last: k == 2 * LIMBS - 1,
            };
            if k == 0 {
                self.asm
                    .emit_r(Kind::MUL, lo, *pairs[0].0[0], *pairs[0].1[0]);
            }
            for (p, (a, b)) in pairs.iter().enumerate() {
                for i in 0..LIMBS {
                    if (p, k) != (0, 0) && k >= i && k - i < LIMBS {
                        self.term(Kind::MUL, *a[i], *b[k - i], lo, hi, &mut column);
                    }
                }
                for i in 0..LIMBS {
                    if k > i && k - 1 - i < LIMBS {
                        self.term(Kind::MULHU, *a[i], *b[k - 1 - i], lo, hi, &mut column);
                    }
                }
            }
            for i in 0..LIMBS.min(k) {
                if k - i < LIMBS {
                    self.term(Kind::MUL, *self.m[i], *self.q[k - i], lo, hi, &mut column);
                }
                if k - 1 - i < LIMBS {
                    self.term(
                        Kind::MULHU,
                        *self.m[i],
                        *self.q[k - 1 - i],
                        lo,
                        hi,
                        &mut column,
                    );
                }
            }
            if k < LIMBS {
                self.asm
                    .emit_i(Kind::VirtualMULI, *self.m[k], lo, BN254_INV);
                if column.first {
                    self.asm.emit_r(Kind::SLTU, hi, 0, lo);
                } else {
                    self.asm.emit_r(Kind::SLTU, *self.aux, 0, lo);
                    self.asm.emit_r(Kind::ADD, hi, hi, *self.aux);
                }
            } else {
                self.asm
                    .emit_s(Kind::SD, base, lo, offset + 8 * (k - LIMBS) as i64);
            }
        }
    }

    /// b ← q − b for b ≤ q (borrow chain through `aux`; `r` holds the per-limb borrows).
    fn negate(&mut self, b: &Limbs) {
        let (borrow, b1, b2) = (*self.aux, *self.r[0], *self.r[1]);
        let (q, asm) = (&self.q, &mut self.asm);
        asm.emit_r(Kind::SLTU, borrow, *q[0], *b[0]);
        asm.emit_r(Kind::SUB, *b[0], *q[0], *b[0]);
        for (bi, qi) in b.iter().zip(q.iter()).take(LIMBS - 1).skip(1) {
            asm.emit_r(Kind::SLTU, b1, **qi, **bi);
            asm.emit_r(Kind::SUB, **bi, **qi, **bi);
            asm.emit_r(Kind::SLTU, b2, **bi, borrow);
            asm.emit_r(Kind::SUB, **bi, **bi, borrow);
            asm.emit_r(Kind::OR, borrow, b1, b2);
        }
        let top = LIMBS - 1;
        asm.emit_r(Kind::SUB, *b[top], *q[top], *b[top]);
        asm.emit_r(Kind::SUB, *b[top], *b[top], borrow);
    }

    fn finish(mut self) -> Result<ExpandedInstructionSequence, ExpansionError> {
        for regs in core::mem::take(&mut self.operands) {
            self.asm.release_many(regs);
        }
        self.asm.release_many(self.q);
        self.asm.release_many(self.m);
        self.asm.release_many(self.r);
        self.asm.release(self.aux);
        self.asm.finalize()
    }
}

/// out = (a·b + m·q) / 2^256 for a = rs1[0..32), b = rs2[0..32), out = rd[0..32).
pub struct Bn254MulQ;

impl InlineOp for Bn254MulQ {
    type Advice = NoAdvice;

    const OPCODE: u32 = crate::INLINE_OPCODE;
    const FUNCT3: u32 = crate::BN254_MULQ_FUNCT3;
    const FUNCT7: u32 = crate::BN254_FUNCT7;
    const NAME: &'static str = crate::BN254_MULQ_NAME;

    fn build_sequence(
        asm: InlineExpansionBuilder,
        operands: InlineOperands,
    ) -> Result<ExpandedInstructionSequence, ExpansionError> {
        let mut mont = Montgomery::new(asm)?;
        let a = mont.load(operands.rs1, 0)?;
        let b = mont.load(operands.rs2, 0)?;
        mont.load_modulus();
        mont.redc_sum(&[(a, b)], operands.rs3, 0);
        mont.finish()
    }
}

/// out = (a₀·b₀ + a₁·b₁ + m·q) / 2^256 for a = rs1[0..64), b = rs2[0..64), out = rd[0..32).
pub struct Bn254SopQ2;

impl InlineOp for Bn254SopQ2 {
    type Advice = NoAdvice;

    const OPCODE: u32 = crate::INLINE_OPCODE;
    const FUNCT3: u32 = crate::BN254_SOPQ2_FUNCT3;
    const FUNCT7: u32 = crate::BN254_FUNCT7;
    const NAME: &'static str = crate::BN254_SOPQ2_NAME;

    fn build_sequence(
        asm: InlineExpansionBuilder,
        operands: InlineOperands,
    ) -> Result<ExpandedInstructionSequence, ExpansionError> {
        let mut mont = Montgomery::new(asm)?;
        let a0 = mont.load(operands.rs1, 0)?;
        let a1 = mont.load(operands.rs1, 32)?;
        let b0 = mont.load(operands.rs2, 0)?;
        let b1 = mont.load(operands.rs2, 32)?;
        mont.load_modulus();
        mont.redc_sum(&[(a0, b0), (a1, b1)], operands.rs3, 0);
        mont.finish()
    }
}

/// Fq2 product for the nonresidue −1: rd[32..64) = REDC(a₀·b₁ + a₁·b₀), rd[0..32) =
/// REDC(a₀·b₀ + a₁·(q − b₁)) for a = rs1[0..64), b = rs2[0..64).
pub struct Bn254Fp2MulQ;

impl InlineOp for Bn254Fp2MulQ {
    type Advice = NoAdvice;

    const OPCODE: u32 = crate::INLINE_OPCODE;
    const FUNCT3: u32 = crate::BN254_FP2MULQ_FUNCT3;
    const FUNCT7: u32 = crate::BN254_FUNCT7;
    const NAME: &'static str = crate::BN254_FP2MULQ_NAME;

    fn build_sequence(
        asm: InlineExpansionBuilder,
        operands: InlineOperands,
    ) -> Result<ExpandedInstructionSequence, ExpansionError> {
        let mut mont = Montgomery::new(asm)?;
        let a0 = mont.load(operands.rs1, 0)?;
        let a1 = mont.load(operands.rs1, 32)?;
        let b0 = mont.load(operands.rs2, 0)?;
        let b1 = mont.load(operands.rs2, 32)?;
        mont.load_modulus();
        mont.redc_sum(&[(a0, b1), (a1, b0)], operands.rs3, 32);
        mont.negate(&b1);
        mont.redc_sum(&[(a0, b0), (a1, b1)], operands.rs3, 0);
        mont.finish()
    }
}
