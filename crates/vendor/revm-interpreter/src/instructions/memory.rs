use crate::interpreter_types::{InterpreterTypes, MemoryTr, RuntimeFlag, StackTr};
use context_interface::Host;
use core::cmp::max;
use primitives::U256;

use crate::{InstructionContext, Ip};

/// Implements the MLOAD instruction.
///
/// Loads a 32-byte word from memory.
#[inline(always)]
pub fn mload<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::mload::<false, _, _>(ip, context, &mut 0, None).into_ip()
}

/// Implements the MSTORE instruction.
///
/// Stores a 32-byte word to memory.
#[inline(always)]
pub fn mstore<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    super::cached::mstore::<false, _, _>(ip, context, &mut 0, None).into_ip()
}

/// Implements the MSTORE8 instruction.
///
/// Stores a single byte to memory.
pub fn mstore8<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, MSTORE8);
    popn!([offset, value], context.interpreter);
    let offset = as_usize_or_fail!(context.interpreter, offset);
    resize_memory!(context.interpreter, context.host.gas_params(), offset, 1);
    context.interpreter.memory.set(offset, &[value.byte(0)]);
    ip
}

/// Implements the MSIZE instruction.
///
/// Gets the size of active memory in bytes.
pub fn msize<WIRE: InterpreterTypes, H: ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, MSIZE);
    push!(
        context.interpreter,
        U256::from(context.interpreter.memory.size())
    );
    ip
}

/// Implements the MCOPY instruction.
///
/// EIP-5656: Memory copying instruction that copies memory from one location to another.
pub fn mcopy<WIRE: InterpreterTypes, H: Host + ?Sized>(
    ip: Ip,
    context: InstructionContext<'_, H, WIRE>,
) -> Ip {
    static_gas!(context.interpreter, MCOPY);
    check!(context.interpreter, CANCUN);
    popn!([dst, src, len], context.interpreter);

    // Into usize or fail
    let len = as_usize_or_fail!(context.interpreter, len);
    // Deduce gas
    gas!(
        context.interpreter,
        context.host.gas_params().mcopy_cost(len)
    );

    if len == 0 {
        return ip;
    }

    let dst = as_usize_or_fail!(context.interpreter, dst);
    let src = as_usize_or_fail!(context.interpreter, src);
    // Resize memory
    resize_memory!(
        context.interpreter,
        context.host.gas_params(),
        max(dst, src),
        len
    );
    // Copy memory in place
    context.interpreter.memory.copy(dst, src, len);
    ip
}
