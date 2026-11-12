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
    super::cached::jump::<false, _, _>(_ip, context, &mut 0, None).into_ip()
}

/// Implements the JUMPI instruction.
///
/// Conditional jump to a valid destination if condition is true.
#[inline(always)]
pub fn jumpi<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::jumpi::<false, _, _>(ip, context, &mut 0, None).into_ip()
}

/// Implements the JUMPDEST instruction.
///
/// Marks a valid destination for jump operations.
pub fn jumpdest<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::jumpdest::<false, _, _>(ip, context, &mut 0, None).into_ip()
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

/// Return data remains independently owned after the child memory is freed.
/// At the common aligned 32-byte size, emit four bounded word moves directly.
#[inline]
fn own_return_bytes(bytes: &[u8]) -> Bytes {
    if bytes.len() == 32 && bytes.as_ptr() as usize & 7 == 0 {
        let mut output = std::vec::Vec::<u8>::with_capacity(32);
        let dst = output.as_mut_ptr();
        if dst as usize & 7 == 0 {
            // SAFETY: both addresses have checked word alignment. The source
            // contains 32 initialized bytes and the new vector owns 32 writable
            // bytes. Four complete stores initialize the prefix before set_len.
            unsafe {
                let src = bytes.as_ptr().cast::<u64>();
                let dst = dst.cast::<u64>();
                dst.write_volatile(src.read_volatile());
                dst.add(1).write_volatile(src.add(1).read_volatile());
                dst.add(2).write_volatile(src.add(2).read_volatile());
                dst.add(3).write_volatile(src.add(3).read_volatile());
                output.set_len(32);
            }
        } else {
            output.extend_from_slice(bytes);
        }
        output.into()
    } else {
        bytes.to_vec().into()
    }
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
        output = own_return_bytes(&interpreter.memory.slice_len(offset, len))
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

#[cfg(test)]
mod return_copy_tests {
    use super::*;

    #[test]
    fn owned_return_words_match_slice_copy() {
        #[repr(align(8))]
        struct Aligned([u8; 264]);
        let mut source = Aligned([0; 264]);
        let mut seed = 0xb826_9a34_57df_c10eu64;
        for _ in 0..32 {
            for b in &mut source.0 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
            for offset in 0..8 {
                for len in [0, 1, 20, 31, 32, 33, 64, 256] {
                    let expected = source.0[offset..offset + len].to_vec();
                    let actual = own_return_bytes(&source.0[offset..offset + len]);
                    assert_eq!(actual.as_ref(), expected.as_slice());
                    let retained = actual.clone();
                    drop(actual);
                    source.0[offset] ^= 0xff;
                    assert_eq!(retained.as_ref(), expected.as_slice());
                }
            }
        }
    }
}
