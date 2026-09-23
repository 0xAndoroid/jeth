use crate::{
    interpreter_types::{InterpreterTypes, RuntimeFlag, StackTr},
    InstructionResult,
};
use primitives::U256;

use crate::{InstructionContext, Ip};

/// Implements the POP instruction.
///
/// Removes the top item from the stack.
pub fn pop<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, POP);
    // Can ignore return. as relative N jump is safe operation.
    popn!([_i], context.interpreter);
    ip
}

/// EIP-3855: PUSH0 instruction
///
/// Introduce a new instruction which pushes the constant value 0 onto the stack.
pub fn push0<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, PUSH0);
    check!(context.interpreter, SHANGHAI);
    push!(context.interpreter, U256::ZERO);
    ip
}

/// Implements the PUSH1-PUSH32 instructions.
///
/// Pushes N bytes from bytecode onto the stack as a 32-byte value.
// `ip` is the run loop's pointer into analysed bytecode (see [`Ip`]).
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn push<const N: usize, WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    // PUSH1..=PUSH32 share one static gas.
    static_gas!(context.interpreter, PUSH1);
    // SAFETY: `ip` points at the N immediate bytes (see `read_be_immediate`).
    let value = unsafe { crate::interpreter::words::read_be_immediate::<N>(ip) };
    if !context.interpreter.stack.push(value) {
        return context.interpreter.halt(InstructionResult::StackOverflow);
    }

    // SAFETY: skips the immediate bytes, which are inside the bytecode (see above).
    unsafe { ip.add(N) }
}

/// Implements the DUP1-DUP16 instructions.
///
/// Duplicates the Nth stack item to the top of the stack.
pub fn dup<const N: usize, WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    // DUP1..=DUP16 share one static gas.
    static_gas!(context.interpreter, DUP1);
    if !context.interpreter.stack.dup(N) {
        return context.interpreter.halt(InstructionResult::StackOverflow);
    }
    ip
}

/// Implements the SWAP1-SWAP16 instructions.
///
/// Swaps the top stack item with the Nth stack item.
pub fn swap<const N: usize, WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    // SWAP1..=SWAP16 share one static gas.
    static_gas!(context.interpreter, SWAP1);
    assert!(N != 0);
    if !context.interpreter.stack.exchange(0, N) {
        return context.interpreter.halt(InstructionResult::StackUnderflow);
    }
    ip
}

/// Implements the DUPN instruction.
///
/// Duplicates the Nth stack item to the top of the stack, with N given by an immediate.
// `ip` is the run loop's pointer into analysed bytecode (see [`Ip`]).
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn dupn<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, DUPN);
    check!(context.interpreter, AMSTERDAM);
    // SAFETY: `ip` points at the immediate byte (see `read_be_immediate`).
    let x: usize = unsafe { *ip }.into();
    if let Some(n) = decode_single(x) {
        if !context.interpreter.stack.dup(n) {
            return context.interpreter.halt(InstructionResult::StackOverflow);
        }
        // SAFETY: skips the immediate byte, which is inside the bytecode.
        unsafe { ip.add(1) }
    } else {
        context
            .interpreter
            .halt(InstructionResult::InvalidImmediateEncoding)
    }
}

/// Implements the SWAPN instruction.
///
/// Swaps the top stack item with the N+1th stack item, with N given by an immediate.
// `ip` is the run loop's pointer into analysed bytecode (see [`Ip`]).
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn swapn<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, SWAPN);
    check!(context.interpreter, AMSTERDAM);
    // SAFETY: `ip` points at the immediate byte (see `read_be_immediate`).
    let x: usize = unsafe { *ip }.into();
    if let Some(n) = decode_single(x) {
        if !context.interpreter.stack.exchange(0, n) {
            return context.interpreter.halt(InstructionResult::StackUnderflow);
        }
        // SAFETY: skips the immediate byte, which is inside the bytecode.
        unsafe { ip.add(1) }
    } else {
        context
            .interpreter
            .halt(InstructionResult::InvalidImmediateEncoding)
    }
}

/// Implements the EXCHANGE instruction.
///
/// Swaps the N+1th stack item with the M+1th stack item, with N, M given by an immediate.
// `ip` is the run loop's pointer into analysed bytecode (see [`Ip`]).
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn exchange<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, EXCHANGE);
    check!(context.interpreter, AMSTERDAM);
    // SAFETY: `ip` points at the immediate byte (see `read_be_immediate`).
    let x: usize = unsafe { *ip }.into();
    if let Some((n, m)) = decode_pair(x) {
        if !context.interpreter.stack.exchange(n, m - n) {
            return context.interpreter.halt(InstructionResult::StackUnderflow);
        }
        // SAFETY: skips the immediate byte, which is inside the bytecode.
        unsafe { ip.add(1) }
    } else {
        context
            .interpreter
            .halt(InstructionResult::InvalidImmediateEncoding)
    }
}

fn decode_single(x: usize) -> Option<usize> {
    if x <= 90 || x >= 128 {
        Some((x + 145) % 256)
    } else {
        None
    }
}

fn decode_pair(x: usize) -> Option<(usize, usize)> {
    if x > 81 && x < 128 {
        return None;
    }
    let k = x ^ 143;
    let q = k / 16;
    let r = k % 16;
    if q < r {
        Some((q + 1, r + 1))
    } else {
        Some((r + 1, 29 - q))
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        host::DummyHost,
        instructions::instruction_table,
        interpreter::{EthInterpreter, ExtBytecode, InputsImpl, SharedMemory},
        interpreter_types::LoopControl,
        Interpreter,
    };
    use bytecode::opcode::*;
    use bytecode::Bytecode;
    use primitives::{hardfork::SpecId, Bytes, U256};

    fn run_bytecode(code: &[u8]) -> Interpreter {
        let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(code));
        let mut interpreter = Interpreter::<EthInterpreter>::new(
            SharedMemory::new(),
            ExtBytecode::new(bytecode),
            InputsImpl::default(),
            false,
            SpecId::AMSTERDAM,
            u64::MAX,
        );
        let table = instruction_table::<EthInterpreter, DummyHost>();
        let mut host = DummyHost::new(SpecId::AMSTERDAM);
        interpreter.run_plain(&table, &mut host);
        interpreter
    }

    #[test]
    fn test_dupn() {
        let interpreter = run_bytecode(&[
            PUSH1, 0x01, PUSH1, 0x00, DUP1, DUP1, DUP1, DUP1, DUP1, DUP1, DUP1, DUP1, DUP1, DUP1,
            DUP1, DUP1, DUP1, DUP1, DUP1, DUPN, 0x80,
        ]);
        assert_eq!(interpreter.stack.len(), 18);
        assert_eq!(interpreter.stack.data()[17], U256::from(1));
        assert_eq!(interpreter.stack.data()[0], U256::from(1));
        for i in 1..17 {
            assert_eq!(interpreter.stack.data()[i], U256::ZERO);
        }
    }

    #[test]
    fn test_swapn() {
        let interpreter = run_bytecode(&[
            PUSH1, 0x01, PUSH1, 0x00, DUP1, DUP1, DUP1, DUP1, DUP1, DUP1, DUP1, DUP1, DUP1, DUP1,
            DUP1, DUP1, DUP1, DUP1, DUP1, PUSH1, 0x02, SWAPN, 0x80,
        ]);
        assert_eq!(interpreter.stack.len(), 18);
        assert_eq!(interpreter.stack.data()[17], U256::from(1));
        assert_eq!(interpreter.stack.data()[0], U256::from(2));
        for i in 1..17 {
            assert_eq!(interpreter.stack.data()[i], U256::ZERO);
        }
    }

    #[test]
    fn test_exchange() {
        let interpreter = run_bytecode(&[PUSH1, 0x00, PUSH1, 0x01, PUSH1, 0x02, EXCHANGE, 0x8E]);
        assert_eq!(interpreter.stack.len(), 3);
        assert_eq!(interpreter.stack.data()[2], U256::from(2));
        assert_eq!(interpreter.stack.data()[1], U256::from(0));
        assert_eq!(interpreter.stack.data()[0], U256::from(1));
    }

    #[test]
    fn test_swapn_invalid_immediate() {
        let mut interpreter = run_bytecode(&[SWAPN, JUMPDEST]);
        assert!(interpreter.bytecode.instruction_result().is_none());
    }

    #[test]
    fn test_jump_over_invalid_dupn() {
        let interpreter = run_bytecode(&[PUSH1, 0x04, JUMP, DUPN, JUMPDEST]);
        assert!(interpreter.bytecode.is_not_end());
    }

    #[test]
    fn test_exchange_with_iszero() {
        let interpreter = run_bytecode(&[
            PUSH1, 0x00, PUSH1, 0x00, PUSH1, 0x00, EXCHANGE, 0x8E, ISZERO,
        ]);
        assert_eq!(interpreter.stack.len(), 3);
        assert_eq!(interpreter.stack.data()[2], U256::from(1));
        assert_eq!(interpreter.stack.data()[1], U256::ZERO);
        assert_eq!(interpreter.stack.data()[0], U256::ZERO);
    }
}
