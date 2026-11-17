//! Bounds behind the `SAFETY` comments below. A handler runs for an opcode at an instruction
//! start of the bytecode analysis: the frame entry, a fall-through, or a destination the jump
//! table accepts (DUPN, SWAPN and EXCHANGE halt on an immediate in 0x5b..=0x7f, so the byte they
//! skip is never one the analysis reads as a JUMPDEST or a PUSH). The analysed buffer holds every
//! instruction's immediates and one more byte after every instruction other than a final STOP:
//! `analyze_legacy` in revm-bytecode pads it so, and jeth-core's code library embeds that output
//! (`embedded_entries_match_revm_analysis`).
use super::{bitwise, control, stack, InstructionTable};
use crate::{
    interpreter_types::{InterpreterTypes, Jumps, StackTr},
    Host, InstructionContext, Ip,
};
use bytecode::opcode::{EQ, ISZERO, JUMP, JUMPDEST, JUMPI, PUSH2};
use primitives::hardfork::SpecId;

const PUSH_COST: u64 = super::static_gas(PUSH2, SpecId::FRONTIER);
const JUMP_COST: u64 = super::static_gas(JUMP, SpecId::FRONTIER);
const JUMPI_COST: u64 = super::static_gas(JUMPI, SpecId::FRONTIER);
const DEST_COST: u64 = super::static_gas(JUMPDEST, SpecId::FRONTIER);
const TEST_COST: u64 = super::static_gas(ISZERO, SpecId::FRONTIER);
const _: () = assert!(
    super::static_gas_is_spec_independent(PUSH2)
        && super::static_gas_is_spec_independent(JUMP)
        && super::static_gas_is_spec_independent(JUMPI)
        && super::static_gas_is_spec_independent(JUMPDEST)
        && super::static_gas_is_spec_independent(ISZERO)
        && super::static_gas_is_spec_independent(EQ)
        && super::static_gas(EQ, SpecId::FRONTIER) == TEST_COST
);

pub(crate) fn matches<W: InterpreterTypes, H: Host + ?Sized>(
    table: &InstructionTable<W, H>,
) -> bool {
    let jump: fn(Ip, InstructionContext<'_, H, W>) -> Ip = control::jump;
    let jumpi: fn(Ip, InstructionContext<'_, H, W>) -> Ip = control::jumpi;
    let dest: fn(Ip, InstructionContext<'_, H, W>) -> Ip = control::jumpdest;
    let push: fn(Ip, InstructionContext<'_, H, W>) -> Ip = push2;
    let iszero: fn(Ip, InstructionContext<'_, H, W>) -> Ip = test_jump::<false, _, _>;
    let eq: fn(Ip, InstructionContext<'_, H, W>) -> Ip = test_jump::<true, _, _>;
    core::ptr::fn_addr_eq(table[JUMP as usize].fn_, jump)
        && core::ptr::fn_addr_eq(table[JUMPI as usize].fn_, jumpi)
        && core::ptr::fn_addr_eq(table[JUMPDEST as usize].fn_, dest)
        && core::ptr::fn_addr_eq(table[PUSH2 as usize].fn_, push)
        // Not redundant: a custom ISZERO or EQ that delegates to the default handler reaches
        // `test_jump`, which would fuse and hand it the state after the jump.
        && core::ptr::fn_addr_eq(table[ISZERO as usize].fn_, iszero)
        && core::ptr::fn_addr_eq(table[EQ as usize].fn_, eq)
}

pub(crate) fn test_jump<const EQUAL: bool, W: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
) -> Ip {
    #[inline(always)]
    fn fallback<const EQ: bool, W: InterpreterTypes, H: Host + ?Sized>(
        ip: Ip,
        context: InstructionContext<'_, H, W>,
    ) -> Ip {
        if EQ {
            bitwise::eq(ip, context)
        } else {
            bitwise::iszero(ip, context)
        }
    }
    if context.interpreter.fuse_push_jumps == 0
        || !context.interpreter.stack.can_elide_test_result()
        // SAFETY: ISZERO and EQ are not STOP, so the byte at `ip` is in the buffer. `ip.add(3)` is
        // read only when that byte is PUSH2, whose two immediates and following byte are too.
        || unsafe { *ip != PUSH2 || *ip.add(3) != JUMPI }
        || !context.interpreter.stack.can_elide_push_pop()
    {
        return fallback::<EQUAL, _, _>(ip, context);
    }
    let values = context.interpreter.stack.data();
    let pops = if EQUAL { 2 } else { 1 };
    if values.len() < pops {
        return fallback::<EQUAL, _, _>(ip, context);
    }
    let top = values.last().unwrap();
    let taken = if EQUAL {
        *top == values[values.len() - 2]
    } else {
        top.is_zero()
    };
    let target = if taken {
        // SAFETY: the two immediates of the PUSH2 at `ip`.
        let offset = unsafe { ((*ip.add(1) as usize) << 8) | (*ip.add(2) as usize) };
        if !context.interpreter.bytecode.is_valid_legacy_jump(offset) {
            return fallback::<EQUAL, _, _>(ip, context);
        }
        Some(context.interpreter.bytecode.jump_target(offset))
    } else {
        None
    };
    let failed = if taken {
        context
            .interpreter
            .gas
            .record_static_cost::<{ TEST_COST + PUSH_COST + JUMPI_COST + DEST_COST }>()
    } else {
        context
            .interpreter
            .gas
            .record_static_cost::<{ TEST_COST + PUSH_COST + JUMPI_COST }>()
    };
    if failed {
        return fallback::<EQUAL, _, _>(ip, context);
    }
    if EQUAL {
        let popped = context.interpreter.stack.popn::<2>();
        debug_assert!(popped.is_some());
    } else {
        let popped = context.interpreter.stack.pop();
        debug_assert!(popped.is_some());
    }
    if let Some(target) = target {
        // SAFETY: `target` is a JUMPDEST the jump table accepted, so one more byte follows it.
        unsafe { target.add(1) }
    } else {
        // SAFETY: `ip.add(3)` is the JUMPI found above, so one more byte follows it.
        unsafe { ip.add(4) }
    }
}

pub(crate) fn push2<W: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
) -> Ip {
    if context.interpreter.fuse_push_jumps == 0 {
        return stack::push::<2, _, _>(ip, context);
    }
    // SAFETY: `ip` points at the two immediates of PUSH2, and one more byte follows them.
    let opcode = unsafe { *ip.add(2) };
    if (opcode != JUMP && opcode != JUMPI) || !context.interpreter.stack.can_elide_push_pop() {
        return stack::push::<2, _, _>(ip, context);
    }
    let taken = if opcode == JUMPI {
        let Some(condition) = context.interpreter.stack.data().last() else {
            return stack::push::<2, _, _>(ip, context);
        };
        !condition.is_zero()
    } else {
        true
    };
    let target = if taken {
        // SAFETY: the two immediates of this PUSH2.
        let offset = unsafe { ((*ip as usize) << 8) | (*ip.add(1) as usize) };
        if !context.interpreter.bytecode.is_valid_legacy_jump(offset) {
            return stack::push::<2, _, _>(ip, context);
        }
        Some(context.interpreter.bytecode.jump_target(offset))
    } else {
        None
    };
    // Failed charges leave gas unchanged. The original PUSH and jump handlers
    // then produce the original error, gas and stack state in their usual order.
    let failed = if opcode == JUMP {
        context
            .interpreter
            .gas
            .record_static_cost::<{ PUSH_COST + JUMP_COST + DEST_COST }>()
    } else if taken {
        context
            .interpreter
            .gas
            .record_static_cost::<{ PUSH_COST + JUMPI_COST + DEST_COST }>()
    } else {
        context
            .interpreter
            .gas
            .record_static_cost::<{ PUSH_COST + JUMPI_COST }>()
    };
    if failed {
        return stack::push::<2, _, _>(ip, context);
    }
    if opcode == JUMPI {
        let popped = context.interpreter.stack.pop();
        debug_assert!(popped.is_some());
    }
    if let Some(target) = target {
        // SAFETY: `target` is a JUMPDEST the jump table accepted, so one more byte follows it.
        unsafe { target.add(1) }
    } else {
        // SAFETY: `ip.add(2)` is the JUMPI found above, so one more byte follows it.
        unsafe { ip.add(3) }
    }
}

#[cfg(test)]
mod tests;
