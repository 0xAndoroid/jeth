use super::i256::{i256_div, i256_mod};
use crate::Ip;
use crate::{
    interpreter_types::{InterpreterTypes, StackTr},
    InstructionContext,
};
use context_interface::Host;
use primitives::U256;

// Offset arithmetic commonly fits in one limb. Keep the full-width path for
// every other value, including carry and borrow propagation across all limbs.
#[inline(always)]
pub(super) fn add_word(a: U256, b: U256) -> U256 {
    let x = a.as_limbs();
    let y = b.as_limbs();
    if (x[1] | x[2] | x[3] | y[1] | y[2] | y[3]) == 0 {
        let (low, carry) = x[0].overflowing_add(y[0]);
        U256::from_limbs([low, carry as u64, 0, 0])
    } else {
        a.wrapping_add(b)
    }
}

#[inline(always)]
pub(super) fn sub_word(a: U256, b: U256) -> U256 {
    let x = a.as_limbs();
    let y = b.as_limbs();
    if (x[1] | x[2] | x[3] | y[1] | y[2] | y[3]) == 0 {
        let (low, borrow) = x[0].overflowing_sub(y[0]);
        let high = 0u64.wrapping_sub(borrow as u64);
        U256::from_limbs([low, high, high, high])
    } else {
        a.wrapping_sub(b)
    }
}

/// Implements the ADD instruction - adds two values from stack.
pub fn add<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::add::<false, _, _>(ip, context, &mut 0)
}

/// Implements the MUL instruction - multiplies two values from stack.
#[inline(always)]
pub fn mul<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::mul::<false, _, _>(ip, context, &mut 0)
}

/// Implements the SUB instruction - subtracts two values from stack.
pub fn sub<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::sub::<false, _, _>(ip, context, &mut 0)
}

/// Implements the DIV instruction - divides two values from stack.
#[inline(always)]
pub fn div<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::div::<false, _, _>(ip, context, &mut 0)
}

/// Implements the SDIV instruction.
///
/// Performs signed division of two values from stack.
pub fn sdiv<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, SDIV);
    popn_top!([op1], op2, context.interpreter);
    *op2 = i256_div(op1, *op2);
    ip
}

/// Implements the MOD instruction.
///
/// Pops two values from stack and pushes the remainder of their division.
pub fn rem<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, MOD);
    popn_top!([op1], op2, context.interpreter);
    if !op2.is_zero() {
        *op2 = op1.wrapping_rem(*op2);
    }
    ip
}

/// Implements the SMOD instruction.
///
/// Performs signed modulo of two values from stack.
pub fn smod<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, SMOD);
    popn_top!([op1], op2, context.interpreter);
    *op2 = i256_mod(op1, *op2);
    ip
}

/// Implements the ADDMOD instruction.
///
/// Pops three values from stack and pushes (a + b) % n.
pub fn addmod<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, ADDMOD);
    popn_top!([op1, op2], op3, context.interpreter);
    *op3 = op1.add_mod(op2, *op3);
    ip
}

/// Implements the MULMOD instruction.
///
/// Pops three values from stack and pushes (a * b) % n.
pub fn mulmod<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, MULMOD);
    popn_top!([op1, op2], op3, context.interpreter);
    mul_mod(&op1, &op2, op3);
    ip
}

#[cfg(feature = "bigint-inline")]
unsafe extern "C" {
    /// jeth guest hook: `(a * b) % m` via the Jolt BIGINT256_MUL inline, the
    /// remainder written over `m` (zero when `m` is zero).
    fn jeth_mul_mod(a: *const u64, b: *const u64, m: *mut u64);
}

#[cfg(feature = "bigint-inline")]
#[inline(always)]
fn mul_mod(a: &U256, b: &U256, m: &mut U256) {
    // SAFETY: `U256` is `repr(transparent)` over `[u64; 4]`; the hook reads
    // 32 bytes from `a` and `b` and rewrites `m` in place.
    unsafe {
        jeth_mul_mod(
            a.as_limbs().as_ptr(),
            b.as_limbs().as_ptr(),
            m.as_limbs_mut().as_mut_ptr(),
        )
    }
}

#[cfg(not(feature = "bigint-inline"))]
#[inline(always)]
fn mul_mod(a: &U256, b: &U256, m: &mut U256) {
    *m = a.mul_mod(*b, *m);
}

/// Implements the EXP instruction - exponentiates two values from stack.
pub fn exp<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, EXP);
    popn_top!([op1], op2, context.interpreter);
    gas!(
        context.interpreter,
        context.host.gas_params().exp_cost(*op2)
    );
    *op2 = op1.pow(*op2);
    ip
}

/// Implements the `SIGNEXTEND` opcode as defined in the Ethereum Yellow Paper.
///
/// In the yellow paper `SIGNEXTEND` is defined to take two inputs, we will call them
/// `x` and `y`, and produce one output.
///
/// The first `t` bits of the output (numbering from the left, starting from 0) are
/// equal to the `t`-th bit of `y`, where `t` is equal to `256 - 8(x + 1)`.
///
/// The remaining bits of the output are equal to the corresponding bits of `y`.
///
/// **Note**: If `x >= 32` then the output is equal to `y` since `t <= 0`.
///
/// To efficiently implement this algorithm in the case `x < 32` we do the following.
///
/// Let `b` be equal to the `t`-th bit of `y` and let `s = 255 - t = 8x + 7`
/// (this is effectively the same index as `t`, but numbering the bits from the
/// right instead of the left).
///
/// We can create a bit mask which is all zeros up to and including the `t`-th bit,
/// and all ones afterwards by computing the quantity `2^s - 1`.
///
/// We can use this mask to compute the output depending on the value of `b`.
///
/// If `b == 1` then the yellow paper says the output should be all ones up to
/// and including the `t`-th bit, followed by the remaining bits of `y`; this is equal to
/// `y | !mask` where `|` is the bitwise `OR` and `!` is bitwise negation.
///
/// Similarly, if `b == 0` then the yellow paper says the output should start with all zeros,
/// then end with bits from `b`; this is equal to `y & mask` where `&` is bitwise `AND`.
#[inline(always)]
pub fn signextend<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, SIGNEXTEND);
    popn_top!([ext], x, context.interpreter);
    // For 31 we also don't need to do anything.
    if ext < U256::from(31) {
        let ext = ext.as_limbs()[0];
        let bit_index = (8 * ext + 7) as usize;
        let bit = x.bit(bit_index);
        let mask = (U256::from(1) << bit_index) - U256::from(1);
        *x = if bit { *x | !mask } else { *x & mask };
    }
    ip
}

#[cfg(test)]
mod small_word_tests {
    use super::{add_word, sub_word};
    use primitives::U256;

    #[test]
    fn small_arithmetic_matches_full_width() {
        let mut values = vec![U256::ZERO, U256::from(1), U256::from(u64::MAX), U256::MAX];
        for limb in 0..4 {
            for x in [1, u64::MAX] {
                let mut words = [0; 4];
                words[limb] = x;
                values.push(U256::from_limbs(words));
            }
        }
        for &a in &values {
            for &b in &values {
                assert_eq!(add_word(a, b), a.wrapping_add(b));
                assert_eq!(sub_word(a, b), a.wrapping_sub(b));
            }
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..128 {
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let a = U256::from_limbs(core::array::from_fn(|_| next()));
            let b = U256::from_limbs(core::array::from_fn(|_| next()));
            for (a, b) in [
                (a, b),
                (U256::from(a.as_limbs()[0]), U256::from(b.as_limbs()[0])),
            ] {
                assert_eq!(add_word(a, b), a.wrapping_add(b));
                assert_eq!(sub_word(a, b), a.wrapping_sub(b));
            }
        }
    }
}
