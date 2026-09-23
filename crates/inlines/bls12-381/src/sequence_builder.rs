//! Deterministic product-scanning Montgomery multiplication over the BLS12-381 base field.
//!
//! Column k collects lo(aᵢ·bⱼ) for i + j = k, hi(aᵢ·bⱼ) for i + j = k − 1 and the same halves of
//! the reduction products mᵢ·pⱼ into a (value, carry) register pair. For k < 6 the multiplier
//! mₖ = valueₖ · INV mod 2⁶⁴ makes the column vanish: valueₖ + lo(mₖ·p₀) ≡ 0 (mod 2⁶⁴) with carry
//! (valueₖ ≠ 0), so lo(mₖ·p₀) is never multiplied. Columns 6..12 are t = (Σ aᵢbᵢ + m·p) / 2³⁸⁴ < 2p
//! (inputs < p), which one branch-free conditional subtraction makes canonical. No advice rows.

use jolt_inlines_sdk::host::{
    ExpandedInstructionSequence, ExpansionError, InlineExpansionBuilder, InlineOp, InlineOperands,
    InlineRegister, Kind, NoAdvice, SourceKind,
};

use crate::{
    FP2MUL_FUNCT3, FP2MUL_NAME, FUNCT7, INLINE_OPCODE, INV, LIMBS as N, MODULUS, MULP_FUNCT3,
    MULP_NAME, SOPP2_FUNCT3, SOPP2_NAME,
};

type Limbs = [u8; N];

fn nums(r: &[InlineRegister; N]) -> Limbs {
    r.map(|x| *x)
}

fn load(asm: &mut InlineExpansionBuilder, r: &Limbs, base: u8, offset: i64) {
    for (i, reg) in r.iter().enumerate() {
        asm.emit_ld(Kind::LD, *reg, base, offset + 8 * i as i64);
    }
}

fn constants(asm: &mut InlineExpansionBuilder, p: &Limbs, inv: u8) {
    for (reg, limb) in p.iter().zip(MODULUS) {
        asm.emit_u(Kind::LUI, *reg, limb);
    }
    asm.emit_u(Kind::LUI, inv, INV);
}

/// Accumulates the 2N columns of (Σ a·b) · R⁻¹ for the (a, b) limb-register pairs in `prods`.
/// `x[k]` is column k's value register and afterwards holds mₖ; column k ≥ N ends in `t[k − N]`.
/// `t[0]` must be a fresh register; `t[j]` (j ≥ 1) is first written at column N + j − 1 and may
/// alias any register that is dead by then (`inv` after column N − 1, `x[i]` after column i + N).
fn columns(
    asm: &mut InlineExpansionBuilder,
    prods: &[(Limbs, Limbs)],
    p: &Limbs,
    inv: u8,
    x: &Limbs,
    t: &Limbs,
    aux: u8,
) {
    for k in 0..2 * N {
        let c1 = if k < N { x[k] } else { t[k - N] };
        let c2 = if k + 1 < N {
            x[k + 1]
        } else if k + 1 < 2 * N {
            t[k + 1 - N]
        } else {
            0
        };
        let last = k + 1 == 2 * N;
        let mut any = false;
        let mut carry = false;
        let mut term = |asm: &mut InlineExpansionBuilder, kind: Kind, ra: u8, rb: u8| {
            if last {
                asm.emit_r(kind, aux, ra, rb);
                asm.emit_r(Kind::ADD, c1, c1, aux);
            } else if k == 0 && !any {
                asm.emit_r(kind, c1, ra, rb);
            } else if !carry {
                asm.emit_r(kind, aux, ra, rb);
                asm.emit_r(Kind::ADD, c1, c1, aux);
                asm.emit_r(Kind::SLTU, c2, c1, aux);
                carry = true;
            } else {
                asm.emit_r(kind, aux, ra, rb);
                asm.emit_r(Kind::ADD, c1, c1, aux);
                asm.emit_r(Kind::SLTU, aux, c1, aux);
                asm.emit_r(Kind::ADD, c2, c2, aux);
            }
            any = true;
        };
        for (a, b) in prods {
            for i in 0..N {
                if k >= i && k - i < N {
                    term(asm, Kind::MUL, a[i], b[k - i]);
                }
            }
            for i in 0..N {
                if k > i && k - 1 - i < N {
                    term(asm, Kind::MULHU, a[i], b[k - 1 - i]);
                }
            }
        }
        for i in 0..k.min(N) {
            if (1..N).contains(&(k - i)) {
                term(asm, Kind::MUL, x[i], p[k - i]);
            }
        }
        for i in 0..k.min(N) {
            if k - 1 - i < N {
                term(asm, Kind::MULHU, x[i], p[k - 1 - i]);
            }
        }
        if k < N {
            if carry {
                asm.emit_r(Kind::SLTU, aux, 0, c1);
                asm.emit_r(Kind::ADD, c2, c2, aux);
            } else {
                asm.emit_r(Kind::SLTU, c2, 0, c1);
            }
            asm.emit_r(Kind::MUL, x[k], c1, inv);
        }
    }
}

/// Stores `t − p` if `t ≥ p`, else `t`, at `base + offset` (requires t < 2p, p < 2³⁸¹).
/// `d` receives t − p; `bw`, `s1`, `s2` are scratch.
#[allow(clippy::too_many_arguments)]
fn reduce_store(
    asm: &mut InlineExpansionBuilder,
    t: &Limbs,
    p: &Limbs,
    d: &Limbs,
    bw: u8,
    s1: u8,
    s2: u8,
    base: u8,
    offset: i64,
) {
    asm.emit_r(Kind::SUB, d[0], t[0], p[0]);
    asm.emit_r(Kind::SLTU, bw, t[0], p[0]);
    for i in 1..N - 1 {
        asm.emit_r(Kind::SUB, d[i], t[i], p[i]);
        asm.emit_r(Kind::SLTU, s1, t[i], p[i]);
        asm.emit_r(Kind::SLTU, s2, d[i], bw);
        asm.emit_r(Kind::SUB, d[i], d[i], bw);
        asm.emit_r(Kind::OR, bw, s1, s2);
    }
    asm.emit_r(Kind::SUB, d[N - 1], t[N - 1], p[N - 1]);
    asm.emit_r(Kind::SUB, d[N - 1], d[N - 1], bw);
    // t − p is negative exactly when t < p: keep t (mask = all ones) or take d (mask = 0).
    asm.emit_i(SourceKind::SRAI, s1, d[N - 1], 63);
    for i in 0..N {
        asm.emit_r(Kind::XOR, s2, t[i], d[i]);
        asm.emit_r(Kind::AND, s2, s2, s1);
        asm.emit_r(Kind::XOR, s2, d[i], s2);
        asm.emit_s(Kind::SD, base, s2, offset + 8 * i as i64);
    }
}

/// `r = p − r` in place (r < p; r = 0 yields p, which the multiplication tolerates).
fn negate(asm: &mut InlineExpansionBuilder, r: &Limbs, p: &Limbs, bw: u8, s1: u8, s2: u8) {
    asm.emit_r(Kind::SLTU, bw, p[0], r[0]);
    asm.emit_r(Kind::SUB, r[0], p[0], r[0]);
    for i in 1..N - 1 {
        asm.emit_r(Kind::SLTU, s1, p[i], r[i]);
        asm.emit_r(Kind::SUB, r[i], p[i], r[i]);
        asm.emit_r(Kind::SLTU, s2, r[i], bw);
        asm.emit_r(Kind::SUB, r[i], r[i], bw);
        asm.emit_r(Kind::OR, bw, s1, s2);
    }
    asm.emit_r(Kind::SUB, r[N - 1], p[N - 1], r[N - 1]);
    asm.emit_r(Kind::SUB, r[N - 1], r[N - 1], bw);
}

struct Common {
    p: [InlineRegister; N],
    inv: InlineRegister,
    x: [InlineRegister; N],
    t0: InlineRegister,
    aux: InlineRegister,
}

impl Common {
    fn allocate(asm: &mut InlineExpansionBuilder) -> Result<Self, ExpansionError> {
        Ok(Self {
            p: asm.allocate_inline_array::<N>()?,
            inv: asm.allocate_for_inline()?,
            x: asm.allocate_inline_array::<N>()?,
            t0: asm.allocate_for_inline()?,
            aux: asm.allocate_for_inline()?,
        })
    }

    /// Output registers for columns N..2N once `inv` is dead: t₀, inv, x₀..x₃.
    fn t(&self) -> Limbs {
        let x = nums(&self.x);
        [*self.t0, *self.inv, x[0], x[1], x[2], x[3]]
    }

    fn release(self, asm: &mut InlineExpansionBuilder) {
        asm.release_many(self.p);
        asm.release(self.inv);
        asm.release_many(self.x);
        asm.release(self.t0);
        asm.release(self.aux);
    }
}

fn build_sum_of_products(
    mut asm: InlineExpansionBuilder,
    ops: InlineOperands,
    terms: usize,
) -> Result<ExpandedInstructionSequence, ExpansionError> {
    let a: Vec<[InlineRegister; N]> = (0..terms)
        .map(|_| asm.allocate_inline_array::<N>())
        .collect::<Result<_, _>>()?;
    let b: Vec<[InlineRegister; N]> = (0..terms)
        .map(|_| asm.allocate_inline_array::<N>())
        .collect::<Result<_, _>>()?;
    let c = Common::allocate(&mut asm)?;
    for (i, r) in a.iter().enumerate() {
        load(&mut asm, &nums(r), ops.rs1, 48 * i as i64);
    }
    for (i, r) in b.iter().enumerate() {
        load(&mut asm, &nums(r), ops.rs2, 48 * i as i64);
    }
    let (p, x) = (nums(&c.p), nums(&c.x));
    constants(&mut asm, &p, *c.inv);
    let prods: Vec<(Limbs, Limbs)> = a.iter().zip(&b).map(|(a, b)| (nums(a), nums(b))).collect();
    let t = c.t();
    columns(&mut asm, &prods, &p, *c.inv, &x, &t, *c.aux);
    let (d, s) = (nums(&a[0]), nums(&b[0]));
    reduce_store(&mut asm, &t, &p, &d, s[0], s[1], s[2], ops.rs3, 0);
    for r in a.into_iter().chain(b) {
        asm.release_many(r);
    }
    c.release(&mut asm);
    asm.finalize()
}

fn build_fp2_mul(
    mut asm: InlineExpansionBuilder,
    ops: InlineOperands,
) -> Result<ExpandedInstructionSequence, ExpansionError> {
    let a0 = asm.allocate_inline_array::<N>()?;
    let a1 = asm.allocate_inline_array::<N>()?;
    let b0 = asm.allocate_inline_array::<N>()?;
    let b1 = asm.allocate_inline_array::<N>()?;
    let c = Common::allocate(&mut asm)?;
    let t1 = asm.allocate_for_inline()?;
    let d = asm.allocate_inline_array::<N>()?;
    let (ra0, ra1, rb0, rb1) = (nums(&a0), nums(&a1), nums(&b0), nums(&b1));
    load(&mut asm, &ra0, ops.rs1, 0);
    load(&mut asm, &ra1, ops.rs1, 48);
    load(&mut asm, &rb0, ops.rs2, 0);
    load(&mut asm, &rb1, ops.rs2, 48);
    let (p, x, rd) = (nums(&c.p), nums(&c.x), nums(&d));
    constants(&mut asm, &p, *c.inv);
    // c₁ = a₀b₁ + a₁b₀ (inv stays live for the second pass, so column 7 lands in `t1`).
    let t = [*c.t0, *t1, x[0], x[1], x[2], x[3]];
    columns(
        &mut asm,
        &[(ra0, rb1), (ra1, rb0)],
        &p,
        *c.inv,
        &x,
        &t,
        *c.aux,
    );
    reduce_store(&mut asm, &t, &p, &rd, x[4], x[5], *c.aux, ops.rs3, 48);
    // c₀ = a₀b₀ − a₁b₁ = a₀b₀ + a₁(p − b₁).
    negate(&mut asm, &rb1, &p, x[4], x[5], *c.aux);
    let t = c.t();
    columns(
        &mut asm,
        &[(ra0, rb0), (ra1, rb1)],
        &p,
        *c.inv,
        &x,
        &t,
        *c.aux,
    );
    reduce_store(&mut asm, &t, &p, &rd, x[4], x[5], *c.aux, ops.rs3, 0);
    for r in [a0, a1, b0, b1, d] {
        asm.release_many(r);
    }
    asm.release(t1);
    c.release(&mut asm);
    asm.finalize()
}

macro_rules! inline_op {
    ($name:ident, $funct3:expr, $op_name:expr, $build:expr) => {
        pub struct $name;

        impl InlineOp for $name {
            type Advice = NoAdvice;

            const OPCODE: u32 = INLINE_OPCODE;
            const FUNCT3: u32 = $funct3;
            const FUNCT7: u32 = FUNCT7;
            const NAME: &'static str = $op_name;

            fn build_sequence(
                asm: InlineExpansionBuilder,
                operands: InlineOperands,
            ) -> Result<ExpandedInstructionSequence, ExpansionError> {
                $build(asm, operands)
            }
        }
    };
}

inline_op!(Mulp, MULP_FUNCT3, MULP_NAME, |asm, ops| {
    build_sum_of_products(asm, ops, 1)
});
inline_op!(Sopp2, SOPP2_FUNCT3, SOPP2_NAME, |asm, ops| {
    build_sum_of_products(asm, ops, 2)
});
inline_op!(Fp2Mul, FP2MUL_FUNCT3, FP2MUL_NAME, build_fp2_mul);
