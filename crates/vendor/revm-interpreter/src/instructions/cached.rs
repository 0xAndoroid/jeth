//! Private canonical kernels for the run loop's local remaining-gas value.
//!
//! These kernels never call the host or yield. Every failure synchronizes gas
//! before the ordinary halt helper builds its action. All other instructions
//! execute with canonical gas and reload the local value on return.

use crate::{
    interpreter_types::{InterpreterTypes, RuntimeFlag, StackTr},
    InstructionContext, InstructionResult, Interpreter, Ip,
};
use primitives::{hardfork::SpecId, U256};

macro_rules! charge {
    ($context:ident, $remaining:ident, $opcode:ident) => {
        const OPCODE: u8 = crate::bytecode::opcode::$opcode;
        const COST: u64 = super::static_gas(OPCODE, SpecId::FRONTIER);
        const { assert!(super::static_gas_is_spec_independent(OPCODE)) };
        let old = *$remaining;
        let new = crate::gas::sub_const::<COST>(old);
        if new > old {
            $context.interpreter.gas.set_remaining(old);
            return $context.interpreter.halt_oog();
        }
        *$remaining = new;
    };
}

#[inline(always)]
fn fail<W: InterpreterTypes>(
    interpreter: &mut Interpreter<W>,
    remaining: u64,
    result: InstructionResult,
) -> Ip {
    interpreter.gas.set_remaining(remaining);
    interpreter.halt(result)
}

macro_rules! binary {
    ($name:ident, $opcode:ident, $operation:expr $(, $spec:ident)?) => {
        #[inline(always)]
        pub(crate) fn $name<W: InterpreterTypes, H: ?Sized>(
            ip: Ip,
            context: InstructionContext<'_, H, W>,
            remaining: &mut u64,
        ) -> Ip {
            charge!(context, remaining, $opcode);
            $(if !context.interpreter.runtime_flag.spec_id().is_enabled_in(SpecId::$spec) {
                return fail(context.interpreter, *remaining, InstructionResult::NotActivated);
            })?
            let Some(([a], top)) = context.interpreter.stack.popn_top::<1>() else {
                return fail(context.interpreter, *remaining, InstructionResult::StackUnderflow);
            };
            *top = ($operation)(a, *top);
            ip
        }
    };
}

binary!(add, ADD, |a: U256, b: U256| a.wrapping_add(b));
binary!(sub, SUB, |a: U256, b: U256| a.wrapping_sub(b));
binary!(mul, MUL, |a: U256, b: U256| a.wrapping_mul(b));
binary!(div, DIV, |a: U256, b: U256| if b.is_zero() {
    b
} else {
    a.wrapping_div(b)
});
binary!(lt, LT, |a: U256, b: U256| U256::from(
    super::bitwise::less_word(&a, &b)
));
binary!(gt, GT, |a: U256, b: U256| U256::from(
    super::bitwise::less_word(&b, &a)
));
binary!(eq, EQ, |a: U256, b: U256| U256::from(a == b));
binary!(bitand, AND, |a: U256, b: U256| a & b);
binary!(bitor, OR, |a: U256, b: U256| a | b);
binary!(
    shl,
    SHL,
    |a: U256, b: U256| super::bitwise::shift_word::<true>(b, as_usize_saturated!(a)),
    CONSTANTINOPLE
);
binary!(
    shr,
    SHR,
    |a: U256, b: U256| super::bitwise::shift_word::<false>(b, as_usize_saturated!(a)),
    CONSTANTINOPLE
);

macro_rules! unary {
    ($name:ident, $opcode:ident, $operation:expr) => {
        #[inline(always)]
        pub(crate) fn $name<W: InterpreterTypes, H: ?Sized>(
            ip: Ip,
            context: InstructionContext<'_, H, W>,
            remaining: &mut u64,
        ) -> Ip {
            charge!(context, remaining, $opcode);
            let Some(([], top)) = context.interpreter.stack.popn_top::<0>() else {
                return fail(
                    context.interpreter,
                    *remaining,
                    InstructionResult::StackUnderflow,
                );
            };
            *top = ($operation)(*top);
            ip
        }
    };
}

unary!(iszero, ISZERO, |a: U256| U256::from(a.is_zero()));
unary!(not, NOT, |a: U256| !a);

#[inline(always)]
pub(crate) fn pop<W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
) -> Ip {
    charge!(context, remaining, POP);
    if context.interpreter.stack.popn::<1>().is_none() {
        return fail(
            context.interpreter,
            *remaining,
            InstructionResult::StackUnderflow,
        );
    }
    ip
}

#[inline(always)]
pub(crate) fn push0<W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
) -> Ip {
    charge!(context, remaining, PUSH0);
    if !context
        .interpreter
        .runtime_flag
        .spec_id()
        .is_enabled_in(SpecId::SHANGHAI)
    {
        return fail(
            context.interpreter,
            *remaining,
            InstructionResult::NotActivated,
        );
    }
    if !context.interpreter.stack.push(U256::ZERO) {
        return fail(
            context.interpreter,
            *remaining,
            InstructionResult::StackOverflow,
        );
    }
    ip
}

#[inline(always)]
pub(crate) fn push<const N: usize, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
) -> Ip {
    charge!(context, remaining, PUSH1);
    // SAFETY: identical analysed-bytecode padding contract to stack::push.
    let value = unsafe { crate::interpreter::words::read_be_immediate::<N>(ip) };
    if !context.interpreter.stack.push(value) {
        return fail(
            context.interpreter,
            *remaining,
            InstructionResult::StackOverflow,
        );
    }
    // SAFETY: the immediate lies in the same padded bytecode allocation.
    unsafe { ip.add(N) }
}

#[inline(always)]
pub(crate) fn dup<const N: usize, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
) -> Ip {
    charge!(context, remaining, DUP1);
    if !context.interpreter.stack.dup(N) {
        // Preserve the original DUP handler's result for both bounds failures.
        return fail(
            context.interpreter,
            *remaining,
            InstructionResult::StackOverflow,
        );
    }
    ip
}

#[inline(always)]
pub(crate) fn swap<const N: usize, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
) -> Ip {
    charge!(context, remaining, SWAP1);
    assert!(N != 0);
    if !context.interpreter.stack.exchange(0, N) {
        return fail(
            context.interpreter,
            *remaining,
            InstructionResult::StackUnderflow,
        );
    }
    ip
}

#[inline(always)]
pub(crate) fn jumpdest<W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
) -> Ip {
    charge!(context, remaining, JUMPDEST);
    ip
}
