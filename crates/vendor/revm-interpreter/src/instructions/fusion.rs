//! Fuse successful PUSH2 jump pairs in the plain interpreter.
use super::{control, stack, InstructionTable};
use crate::{
    interpreter_types::{InterpreterTypes, Jumps, StackTr},
    Host, InstructionContext, Ip,
};
use bytecode::opcode::{JUMP, JUMPDEST, JUMPI, PUSH2};
use primitives::hardfork::SpecId;

const PUSH_COST: u64 = super::static_gas(PUSH2, SpecId::FRONTIER);
const JUMP_COST: u64 = super::static_gas(JUMP, SpecId::FRONTIER);
const JUMPI_COST: u64 = super::static_gas(JUMPI, SpecId::FRONTIER);
const DEST_COST: u64 = super::static_gas(JUMPDEST, SpecId::FRONTIER);
const _: () = assert!(
    super::static_gas_is_spec_independent(PUSH2)
        && super::static_gas_is_spec_independent(JUMP)
        && super::static_gas_is_spec_independent(JUMPI)
        && super::static_gas_is_spec_independent(JUMPDEST)
);

pub(crate) fn matches<W: InterpreterTypes, H: Host + ?Sized>(
    table: &InstructionTable<W, H>,
) -> bool {
    let jump: fn(Ip, InstructionContext<'_, H, W>) -> Ip = control::jump;
    let jumpi: fn(Ip, InstructionContext<'_, H, W>) -> Ip = control::jumpi;
    let dest: fn(Ip, InstructionContext<'_, H, W>) -> Ip = control::jumpdest;
    core::ptr::fn_addr_eq(table[JUMP as usize].fn_, jump)
        && core::ptr::fn_addr_eq(table[JUMPI as usize].fn_, jumpi)
        && core::ptr::fn_addr_eq(table[JUMPDEST as usize].fn_, dest)
}

pub(crate) fn push2<W: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, W>,
) -> Ip {
    if context.interpreter.fuse_push_jumps == 0 {
        return stack::push::<2, _, _>(ip, context);
    }
    // Analyzed bytecode includes PUSH-immediate and STOP padding.
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
        // Read only the two-byte immediate; do not create a U256 stack value.
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
        // A valid JUMPDEST is followed by another opcode or analyzed STOP padding.
        unsafe { target.add(1) }
    } else {
        unsafe { ip.add(3) }
    }
}

#[cfg(test)]
mod tests;
