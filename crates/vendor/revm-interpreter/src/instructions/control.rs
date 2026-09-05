use crate::{
    interpreter::Interpreter,
    interpreter_types::{InterpreterTypes, Jumps, MemoryTr, RuntimeFlag, StackTr},
    InstructionResult, InterpreterAction,
};
use context_interface::{cfg::GasParams, Host};
use primitives::{Bytes, U256};

use crate::{InstructionContext, Ip};

/// Implements the JUMP instruction.
///
/// Unconditional jump to a valid destination.
pub fn jump<ITy: InterpreterTypes, H: ?Sized>(
    _ip: Ip,
    context: InstructionContext<'_, H, ITy>,
) -> Ip {
    static_gas!(context.interpreter, JUMP);
    popn!([target], context.interpreter);
    jump_inner(context.interpreter, target)
}

/// Implements the JUMPI instruction.
///
/// Conditional jump to a valid destination if condition is true.
pub fn jumpi<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, JUMPI);
    popn!([target, cond], context.interpreter);
    if !cond.is_zero() {
        return jump_inner(context.interpreter, target);
    }
    ip
}

/// Internal helper function for jump operations.
///
/// Validates the jump target and returns the [`Ip`] of the destination.
#[inline(always)]
fn jump_inner<WIRE: InterpreterTypes>(interpreter: &mut Interpreter<WIRE>, target: U256) -> Ip {
    let target = as_usize_saturated!(target);
    if !interpreter.bytecode.is_valid_legacy_jump(target) {
        return interpreter.halt(InstructionResult::InvalidJump);
    }
    // `is_valid_legacy_jump` ensures that `target` is in bounds.
    interpreter.bytecode.jump_target(target)
}

/// Implements the JUMPDEST instruction.
///
/// Marks a valid destination for jump operations.
pub fn jumpdest<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, JUMPDEST);
    ip
}

/// Implements the PC instruction.
///
/// Pushes the current program counter onto the stack.
pub fn pc<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, PC);
    // - 1 because `ip` already points past the opcode.
    push!(
        context.interpreter,
        U256::from(context.interpreter.bytecode.pc_of(ip) - 1)
    );
    ip
}

#[inline]
/// Internal helper function for return operations.
///
/// Handles memory data retrieval and sets the return action.
fn return_inner(
    ip: Ip,
    interpreter: &mut Interpreter<impl InterpreterTypes>,
    gas_params: &GasParams,
    instruction_result: InstructionResult,
) -> Ip {
    popn!([offset, len], interpreter);
    let len = as_usize_or_fail!(interpreter, len);
    // Important: Offset must be ignored if len is zeros
    let mut output = Bytes::default();
    if len != 0 {
        let offset = as_usize_or_fail!(interpreter, offset);
        if !interpreter.resize_memory(gas_params, offset, len) {
            return core::ptr::null();
        }
        output = interpreter.memory.slice_len(offset, len).to_vec().into()
    }

    interpreter.set_action_at(
        ip,
        InterpreterAction::new_return(instruction_result, output, interpreter.gas),
    )
}

/// Implements the RETURN instruction.
///
/// Halts execution and returns data from memory.
pub fn ret<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    return_inner(
        ip,
        context.interpreter,
        context.host.gas_params(),
        InstructionResult::Return,
    )
}

/// EIP-140: REVERT instruction
pub fn revert<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    check!(context.interpreter, BYZANTIUM);
    return_inner(
        ip,
        context.interpreter,
        context.host.gas_params(),
        InstructionResult::Revert,
    )
}

/// Stop opcode. This opcode halts the execution.
pub fn stop<WIRE: InterpreterTypes, H: ?Sized>(
    _ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    context.interpreter.halt(InstructionResult::Stop)
}

/// Invalid opcode. This opcode halts the execution.
pub fn invalid<WIRE: InterpreterTypes, H: ?Sized>(
    _ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    context.interpreter.halt(InstructionResult::InvalidFEOpcode)
}

/// Unknown opcode. This opcode halts the execution.
pub fn unknown<WIRE: InterpreterTypes, H: ?Sized>(
    _ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    context.interpreter.halt(InstructionResult::OpcodeNotFound)
}
