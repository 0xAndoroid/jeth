//! Opcode kernels shared by ordinary and locally cached gas paths.
//!
//! Pure kernels never call the host or yield. Memory expansion synchronizes
//! before consulting host gas parameters. Cached failures synchronize gas
//! before the ordinary halt helper builds its action. All other instructions
//! execute with canonical gas and reload the local value on return.

use crate::{
    interpreter_types::{
        InputsTr, InterpreterTypes, Jumps, MemoryTr, ReturnData, RuntimeFlag, StackTr,
    },
    InstructionContext, InstructionResult, Interpreter, Ip,
};
use core::ptr;
use primitives::{hardfork::SpecId, B256, U256};

/// Private control result exposes the known-success path to loop optimization.
/// Ordinary instruction functions still return precisely the original pointer.
pub(crate) enum Flow {
    Continue(Ip),
    Halt(Ip),
}

impl Flow {
    #[inline(always)]
    pub(crate) fn from_ip(ip: Ip) -> Self {
        if ip.is_null() {
            Self::Halt(ip)
        } else {
            Self::Continue(ip)
        }
    }

    #[inline(always)]
    pub(crate) fn into_ip(self) -> Ip {
        match self {
            Self::Continue(ip) | Self::Halt(ip) => ip,
        }
    }
}

macro_rules! charge {
    ($context:ident, $remaining:ident, $opcode:ident) => {
        const OPCODE: u8 = crate::bytecode::opcode::$opcode;
        const COST: u64 = super::static_gas(OPCODE, SpecId::FRONTIER);
        const {
            assert!(super::static_gas_is_spec_independent(OPCODE));
            assert!(COST <= i64::MAX as u64);
        };
        // Entry and every fallback reload admit only nonnegative signed budgets.
        // A wrapped subtraction is therefore negative exactly on out-of-gas.
        if LOCAL {
            *$remaining = crate::gas::sub_const::<COST>(*$remaining);
            if (*$remaining as i64) < 0 {
                // halt_oog spends the budget before capturing it.
                $context.interpreter.gas.set_remaining(0);
                return Flow::Halt($context.interpreter.halt_oog());
            }
        } else {
            if $context.interpreter.gas.record_static_cost::<COST>() {
                return Flow::Halt($context.interpreter.halt_oog());
            }
        }
    };
}

#[inline(always)]
fn fail<const LOCAL: bool, W: InterpreterTypes>(
    interpreter: &mut Interpreter<W>,
    remaining: u64,
    result: InstructionResult,
) -> Flow {
    if LOCAL {
        interpreter.gas.set_remaining(remaining);
    }
    Flow::Halt(interpreter.halt(result))
}

macro_rules! binary {
    ($name:ident, $opcode:ident, $operation:expr $(, $spec:ident)?) => {
        #[inline(always)]
        pub(crate) fn $name<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
            ip: Ip,
            context: InstructionContext<'_, H, W>,
            remaining: &mut u64,
            stack: Option<&mut W::Stack>,
        ) -> Flow {
            charge!(context, remaining, $opcode);
            $(if !context.interpreter.runtime_flag.spec_id().is_enabled_in(SpecId::$spec) {
                return fail::<LOCAL, _>(context.interpreter, *remaining, InstructionResult::NotActivated);
            })?
            let Some(([a], top)) = stack.unwrap_or(&mut context.interpreter.stack).popn_top::<1>() else {
                return fail::<LOCAL, _>(context.interpreter, *remaining, InstructionResult::StackUnderflow);
            };
            ($operation)(a, top);
            Flow::Continue(ip)
        }
    };
}

binary!(add, ADD, |a: U256, b: &mut U256| *b =
    super::arithmetic::add_word(a, *b));
binary!(sub, SUB, |a: U256, b: &mut U256| *b = a.wrapping_sub(*b));
binary!(mul, MUL, |a: U256, b: &mut U256| *b =
    super::arithmetic::mul_word(a, *b));
binary!(div, DIV, |a: U256, b: &mut U256| {
    super::arithmetic::div_word(a, b)
});
binary!(lt, LT, |a: U256, b: &mut U256| *b =
    U256::from(super::bitwise::less_word(&a, b)));
binary!(gt, GT, |a: U256, b: &mut U256| *b =
    U256::from(super::bitwise::less_word(b, &a)));
binary!(eq, EQ, |a: U256, b: &mut U256| *b =
    U256::from(super::bitwise::equal_word(&a, b)));
binary!(bitand, AND, |a: U256, b: &mut U256| *b = a & *b);
binary!(bitor, OR, |a: U256, b: &mut U256| *b = a | *b);
binary!(
    shl,
    SHL,
    |a: U256, b: &mut U256| *b = super::bitwise::shift_word::<true>(*b, as_usize_saturated!(a)),
    CONSTANTINOPLE
);
binary!(
    shr,
    SHR,
    |a: U256, b: &mut U256| *b = super::bitwise::shift_word::<false>(*b, as_usize_saturated!(a)),
    CONSTANTINOPLE
);

macro_rules! unary {
    ($name:ident, $opcode:ident, $operation:expr) => {
        #[inline(always)]
        pub(crate) fn $name<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
            ip: Ip,
            context: InstructionContext<'_, H, W>,
            remaining: &mut u64,
            stack: Option<&mut W::Stack>,
        ) -> Flow {
            charge!(context, remaining, $opcode);
            let Some(([], top)) = stack
                .unwrap_or(&mut context.interpreter.stack)
                .popn_top::<0>()
            else {
                return fail::<LOCAL, _>(
                    context.interpreter,
                    *remaining,
                    InstructionResult::StackUnderflow,
                );
            };
            *top = ($operation)(*top);
            Flow::Continue(ip)
        }
    };
}

unary!(iszero, ISZERO, |a: U256| U256::from(a.is_zero()));
unary!(not, NOT, |a: U256| !a);

#[inline(always)]
pub(crate) fn pop<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, POP);
    if stack
        .unwrap_or(&mut context.interpreter.stack)
        .popn::<1>()
        .is_none()
    {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackUnderflow,
        );
    }
    Flow::Continue(ip)
}

#[inline(always)]
pub(crate) fn push0<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, PUSH0);
    if !context
        .interpreter
        .runtime_flag
        .spec_id()
        .is_enabled_in(SpecId::SHANGHAI)
    {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::NotActivated,
        );
    }
    if !stack
        .unwrap_or(&mut context.interpreter.stack)
        .push(U256::ZERO)
    {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackOverflow,
        );
    }
    Flow::Continue(ip)
}

#[inline(always)]
pub(crate) fn push<const N: usize, const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, PUSH1);
    // SAFETY: identical analysed-bytecode padding contract to stack::push.
    let value = unsafe { crate::interpreter::words::read_be_immediate::<N>(ip) };
    if !stack.unwrap_or(&mut context.interpreter.stack).push(value) {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackOverflow,
        );
    }
    // SAFETY: the immediate lies in the same padded bytecode allocation.
    Flow::Continue(unsafe { ip.add(N) })
}

#[inline(always)]
pub(crate) fn dup<const N: usize, const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, DUP1);
    if !stack.unwrap_or(&mut context.interpreter.stack).dup(N) {
        // Preserve the original DUP handler's result for both bounds failures.
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackOverflow,
        );
    }
    Flow::Continue(ip)
}

#[inline(always)]
pub(crate) fn swap<const N: usize, const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, SWAP1);
    assert!(N != 0);
    if !stack
        .unwrap_or(&mut context.interpreter.stack)
        .exchange(0, N)
    {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackUnderflow,
        );
    }
    Flow::Continue(ip)
}

#[inline(always)]
pub(crate) fn jumpdest<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    _stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, JUMPDEST);
    Flow::Continue(ip)
}

#[inline(always)]
pub(crate) fn jump<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    _ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, JUMP);
    let Some([target]) = stack.unwrap_or(&mut context.interpreter.stack).popn::<1>() else {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackUnderflow,
        );
    };
    jump_to::<LOCAL, _>(context.interpreter, *remaining, target)
}

#[inline(always)]
pub(crate) fn jumpi<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, JUMPI);
    let Some([target, condition]) = stack.unwrap_or(&mut context.interpreter.stack).popn::<2>()
    else {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackUnderflow,
        );
    };
    if condition.is_zero() {
        Flow::Continue(ip)
    } else {
        jump_to::<LOCAL, _>(context.interpreter, *remaining, target)
    }
}

#[inline(always)]
fn jump_to<const LOCAL: bool, W: InterpreterTypes>(
    interpreter: &mut Interpreter<W>,
    remaining: u64,
    target: U256,
) -> Flow {
    let target = as_usize_saturated!(target);
    if !interpreter.bytecode.is_valid_legacy_jump(target) {
        return fail::<LOCAL, _>(interpreter, remaining, InstructionResult::InvalidJump);
    }
    Flow::from_ip(interpreter.bytecode.jump_target(target))
}

#[inline(always)]
pub(crate) fn caller<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, CALLER);
    let value = context
        .interpreter
        .input
        .caller_address()
        .into_word()
        .into();
    if !stack.unwrap_or(&mut context.interpreter.stack).push(value) {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackOverflow,
        );
    }
    Flow::Continue(ip)
}

#[inline(always)]
pub(crate) fn calldatasize<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, CALLDATASIZE);
    let value = U256::from(context.interpreter.input.input().len());
    if !stack.unwrap_or(&mut context.interpreter.stack).push(value) {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackOverflow,
        );
    }
    Flow::Continue(ip)
}

#[inline(always)]
pub(crate) fn returndatasize<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, RETURNDATASIZE);
    if !context
        .interpreter
        .runtime_flag
        .spec_id()
        .is_enabled_in(SpecId::BYZANTIUM)
    {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::NotActivated,
        );
    }
    let value = U256::from(context.interpreter.return_data.buffer().len());
    if !stack.unwrap_or(&mut context.interpreter.stack).push(value) {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackOverflow,
        );
    }
    Flow::Continue(ip)
}

#[inline(always)]
pub(crate) fn gas<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, GAS);
    let value = if LOCAL {
        *remaining
    } else {
        context.interpreter.gas.remaining()
    };
    let value = U256::from(value);
    if !stack.unwrap_or(&mut context.interpreter.stack).push(value) {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackOverflow,
        );
    }
    Flow::Continue(ip)
}

#[inline(always)]
pub(crate) fn calldataload<const LOCAL: bool, W: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, CALLDATALOAD);
    let Some(([], offset_ptr)) = stack
        .unwrap_or(&mut context.interpreter.stack)
        .popn_top::<0>()
    else {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackUnderflow,
        );
    };
    let mut word = B256::ZERO;
    let offset = as_usize_saturated!(*offset_ptr);
    let input = context.interpreter.input.input();
    let input_len = input.len();
    if offset < input_len {
        let input = &*input.as_bytes_memory(&context.interpreter.memory);
        if offset + 32 <= input_len {
            // Word-wise (see interpreter::words).
            *offset_ptr = crate::interpreter::words::read_u256_be(input, offset);
            return Flow::Continue(ip);
        }
        let count = 32.min(input_len - offset);
        // SAFETY: `count` is bounded by the calldata length.
        // This is `word[..count].copy_from_slice(input[offset..offset + count])`, written using
        // raw pointers as apparently the compiler cannot optimize the slice version, and using
        // `get_unchecked` twice is uglier.
        unsafe { ptr::copy_nonoverlapping(input.as_ptr().add(offset), word.as_mut_ptr(), count) };
    }
    *offset_ptr = word.into();
    Flow::Continue(ip)
}

macro_rules! memory_offset {
    ($context:ident, $remaining:ident, $value:expr) => {{
        let words = $value.as_limbs();
        if (words[0] > usize::MAX as u64) | (words[1] != 0) | (words[2] != 0) | (words[3] != 0) {
            return fail::<LOCAL, _>(
                $context.interpreter,
                *$remaining,
                InstructionResult::InvalidOperandOOG,
            );
        }
        words[0] as usize
    }};
}

macro_rules! memory_resize {
    ($context:ident, $remaining:ident, $offset:ident) => {
        let result = if LOCAL {
            crate::interpreter::resize_memory_cached(
                &mut $context.interpreter.gas,
                &mut $context.interpreter.memory,
                $context.host,
                $remaining,
                $offset,
                32,
            )
        } else {
            crate::interpreter::resize_memory(
                &mut $context.interpreter.gas,
                &mut $context.interpreter.memory,
                $context.host.gas_params(),
                $offset,
                32,
            )
        };
        if let Err(result) = result {
            return fail::<LOCAL, _>($context.interpreter, *$remaining, result);
        }
    };
}

#[inline(always)]
pub(crate) fn mload<const LOCAL: bool, W: InterpreterTypes, H: context_interface::Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, MLOAD);
    let Some(([], top)) = stack
        .unwrap_or(&mut context.interpreter.stack)
        .popn_top::<0>()
    else {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackUnderflow,
        );
    };
    let offset = memory_offset!(context, remaining, top);
    memory_resize!(context, remaining, offset);
    *top = context.interpreter.memory.get_u256(offset);
    Flow::Continue(ip)
}

#[inline(always)]
pub(crate) fn mstore<
    const LOCAL: bool,
    W: InterpreterTypes,
    H: context_interface::Host + ?Sized,
>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
    remaining: &mut u64,
    stack: Option<&mut W::Stack>,
) -> Flow {
    charge!(context, remaining, MSTORE);
    let Some([offset, value]) = stack.unwrap_or(&mut context.interpreter.stack).popn::<2>() else {
        return fail::<LOCAL, _>(
            context.interpreter,
            *remaining,
            InstructionResult::StackUnderflow,
        );
    };
    let offset = memory_offset!(context, remaining, offset);
    memory_resize!(context, remaining, offset);
    context.interpreter.memory.set_u256(offset, value);
    Flow::Continue(ip)
}
