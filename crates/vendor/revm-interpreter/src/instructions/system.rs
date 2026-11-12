use crate::{
    interpreter_types::{
        InputsTr, InterpreterTypes, LegacyBytecode, MemoryTr, ReturnData, RuntimeFlag, StackTr,
    },
    CallInput, InstructionResult,
};
use context_interface::Host;
use primitives::{KECCAK_EMPTY, U256};

use crate::{InstructionContext, Ip};

/// Implements the KECCAK256 instruction.
///
/// Computes Keccak-256 hash of memory data.
#[inline(always)]
pub fn keccak256<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, KECCAK256);
    popn_top!([offset], top, context.interpreter);
    let len = as_usize_or_fail!(context.interpreter, top);
    gas!(
        context.interpreter,
        context.host.gas_params().keccak256_cost(len)
    );
    let hash = if len == 0 {
        KECCAK_EMPTY
    } else {
        let from = as_usize_or_fail!(context.interpreter, offset);
        resize_memory!(context.interpreter, context.host.gas_params(), from, len);
        primitives::keccak256(context.interpreter.memory.slice_len(from, len).as_ref())
    };
    *top = hash.into();
    ip
}

/// Implements the ADDRESS instruction.
///
/// Pushes the current contract's address onto the stack.
pub fn address<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, ADDRESS);
    push!(
        context.interpreter,
        context
            .interpreter
            .input
            .target_address()
            .into_word()
            .into()
    );
    ip
}

/// Implements the CALLER instruction.
///
/// Pushes the caller's address onto the stack.
#[inline(always)]
pub fn caller<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::caller::<false, _, _>(ip, context, &mut 0, None).into_ip()
}

/// Implements the CODESIZE instruction.
///
/// Pushes the size of running contract's bytecode onto the stack.
pub fn codesize<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, CODESIZE);
    push!(
        context.interpreter,
        U256::from(context.interpreter.bytecode.bytecode_len())
    );
    ip
}

/// Implements the CODECOPY instruction.
///
/// Copies running contract's bytecode to memory.
pub fn codecopy<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, CODECOPY);
    popn!([memory_offset, code_offset, len], context.interpreter);
    let len = as_usize_or_fail!(context.interpreter, len);
    gas!(
        context.interpreter,
        context.host.gas_params().copy_cost(len)
    );
    if len == 0 {
        return ip;
    }
    let memory_offset = as_usize_or_fail!(context.interpreter, memory_offset);
    resize_memory!(
        context.interpreter,
        context.host.gas_params(),
        memory_offset,
        len
    );
    let code_offset = as_usize_saturated!(code_offset);

    // Note: This can't panic because we resized memory to fit.
    context.interpreter.memory.set_data(
        memory_offset,
        code_offset,
        len,
        context.interpreter.bytecode.bytecode_slice(),
    );
    ip
}

/// Implements the CALLDATALOAD instruction.
///
/// Loads 32 bytes of input data from the specified offset.
#[inline(always)]
pub fn calldataload<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::calldataload::<false, _, _>(ip, context, &mut 0, None).into_ip()
}

/// Implements the CALLDATASIZE instruction.
///
/// Pushes the size of input data onto the stack.
#[inline(always)]
pub fn calldatasize<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::calldatasize::<false, _, _>(ip, context, &mut 0, None).into_ip()
}

/// Implements the CALLVALUE instruction.
///
/// Pushes the value sent with the current call onto the stack.
pub fn callvalue<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, CALLVALUE);
    push!(context.interpreter, context.interpreter.input.call_value());
    ip
}

/// Implements the CALLDATACOPY instruction.
///
/// Copies input data to memory.
pub fn calldatacopy<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, CALLDATACOPY);
    popn!([memory_offset, data_offset, len], context.interpreter);
    let len = as_usize_or_fail!(context.interpreter, len);
    gas!(
        context.interpreter,
        context.host.gas_params().copy_cost(len)
    );
    if len == 0 {
        return ip;
    }
    let memory_offset = as_usize_or_fail!(context.interpreter, memory_offset);
    resize_memory!(
        context.interpreter,
        context.host.gas_params(),
        memory_offset,
        len
    );

    let data_offset = as_usize_saturated!(data_offset);
    match context.interpreter.input.input() {
        CallInput::Bytes(bytes) => {
            context
                .interpreter
                .memory
                .set_data(memory_offset, data_offset, len, bytes.as_ref());
        }
        CallInput::SharedBuffer(range) => {
            context.interpreter.memory.set_data_from_global(
                memory_offset,
                data_offset,
                len,
                range.clone(),
            );
        }
    }
    ip
}

/// EIP-211: New opcodes: RETURNDATASIZE and RETURNDATACOPY
#[inline(always)]
pub fn returndatasize<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::returndatasize::<false, _, _>(ip, context, &mut 0, None).into_ip()
}

/// EIP-211: New opcodes: RETURNDATASIZE and RETURNDATACOPY
pub fn returndatacopy<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, RETURNDATACOPY);
    check!(context.interpreter, BYZANTIUM);
    popn!([memory_offset, offset, len], context.interpreter);

    let len = as_usize_or_fail!(context.interpreter, len);
    let data_offset = as_usize_saturated!(offset);

    // Old legacy behavior is to panic if data_end is out of scope of return buffer.
    let data_end = data_offset.saturating_add(len);
    if data_end > context.interpreter.return_data.buffer().len() {
        return context.interpreter.halt(InstructionResult::OutOfOffset);
    }

    gas!(
        context.interpreter,
        context.host.gas_params().copy_cost(len)
    );
    if len == 0 {
        return ip;
    }
    let memory_offset = as_usize_or_fail!(context.interpreter, memory_offset);
    resize_memory!(
        context.interpreter,
        context.host.gas_params(),
        memory_offset,
        len
    );

    // Note: This can't panic because we resized memory to fit.
    context.interpreter.memory.set_data(
        memory_offset,
        data_offset,
        len,
        context.interpreter.return_data.buffer(),
    );
    ip
}

/// Implements the GAS instruction.
///
/// Pushes the amount of remaining gas onto the stack.
/// Returns `gas_left` only (excluding the state gas reservoir) per EIP-8037.
/// On mainnet (no state gas), this is equivalent to returning `remaining`.
#[inline(always)]
pub fn gas<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::gas::<false, _, _>(ip, context, &mut 0, None).into_ip()
}
