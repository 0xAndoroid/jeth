//! EVM opcode implementations.

#[macro_use]
pub mod macros;
/// Arithmetic operations (ADD, SUB, MUL, DIV, etc.).
pub mod arithmetic;
/// Bitwise operations (AND, OR, XOR, NOT, etc.).
pub mod bitwise;
/// Block information instructions (COINBASE, TIMESTAMP, etc.).
pub mod block_info;
/// Contract operations (CALL, CREATE, DELEGATECALL, etc.).
pub mod contract;
/// Control flow instructions (JUMP, JUMPI, REVERT, etc.).
pub mod control;
/// Host environment interactions (SLOAD, SSTORE, LOG, etc.).
pub mod host;
/// Signed 256-bit integer operations.
pub mod i256;
/// Intrinsic transaction gas (word-at-a-time calldata token count).
pub mod initial_gas;
/// Memory operations (MLOAD, MSTORE, MSIZE, etc.).
pub mod memory;
/// Stack operations (PUSH, POP, DUP, SWAP, etc.).
pub mod stack;
/// System information instructions (ADDRESS, CALLER, etc.).
pub mod system;
/// Transaction information instructions (ORIGIN, GASPRICE, etc.).
pub mod tx_info;
/// Utility functions and helpers for instruction implementation.
pub mod utility;

pub use context_interface::cfg::gas::{self, *};
// Explicit import: shadows the glob's `calculate_initial_tx_gas_for_tx` (this
// is the name revm-handler's validation imports from `instructions`).
pub use initial_gas::calculate_initial_tx_gas_for_tx;

use crate::{interpreter_types::InterpreterTypes, Host, InstructionContext};
use primitives::hardfork::SpecId;

/// EVM opcode function pointer. The table entry is a bare pointer: static gas is charged
/// by each instruction through [`static_gas!`] so the dispatch loop never touches gas.
#[derive(Debug)]
#[repr(transparent)]
pub struct Instruction<W: InterpreterTypes, H: ?Sized> {
    fn_: fn(InstructionContext<'_, H, W>),
}

impl<W: InterpreterTypes, H: Host + ?Sized> Instruction<W, H> {
    /// Creates a new instruction from its function.
    #[inline]
    pub const fn new(fn_: fn(InstructionContext<'_, H, W>)) -> Self {
        Self { fn_ }
    }

    /// Creates an unknown/invalid instruction.
    #[inline]
    pub const fn unknown() -> Self {
        Self {
            fn_: control::unknown,
        }
    }

    /// Executes the instruction with the given context.
    #[inline(always)]
    pub fn execute(self, ctx: InstructionContext<'_, H, W>) {
        (self.fn_)(ctx)
    }
}

impl<W: InterpreterTypes, H: Host + ?Sized> Copy for Instruction<W, H> {}
impl<W: InterpreterTypes, H: Host + ?Sized> Clone for Instruction<W, H> {
    fn clone(&self) -> Self {
        *self
    }
}

/// Instruction table is list of instruction function pointers mapped to 256 EVM opcodes.
pub type InstructionTable<W, H> = [Instruction<W, H>; 256];

/// Returns the default instruction table for the given interpreter types and host.
#[inline]
pub const fn instruction_table<WIRE: InterpreterTypes, H: Host>() -> [Instruction<WIRE, H>; 256] {
    const { instruction_table_impl::<WIRE, H>() }
}

/// Returns the instruction table for `spec`.
///
/// Static gas is spec-adjusted inside each instruction ([`static_gas`]), so the table itself
/// is spec-independent and this is [`instruction_table`]. Kept for `revm-handler`'s
/// `EthInstructions` constructors.
#[inline]
pub fn instruction_table_gas_changes_spec<WIRE: InterpreterTypes, H: Host>(
    _spec: SpecId,
) -> [Instruction<WIRE, H>; 256] {
    instruction_table()
}

/// Static gas of `opcode` under `spec`: the pre-Berlin base costs plus the EIP-150
/// (Tangerine), EIP-1884 (Istanbul) and EIP-2929 (Berlin) repricings.
///
/// Called by every instruction with its own constant opcode, so the match folds to a
/// constant everywhere except the repriced opcodes, which keep a spec switch.
/// Undefined opcodes and opcodes whose gas is fully dynamic (`SSTORE`, `CREATE*`, `RETURN`,
/// `REVERT`, `STOP`, `INVALID`) are 0.
pub const fn static_gas(opcode: u8, spec: SpecId) -> u64 {
    use bytecode::opcode::*;
    use SpecId::*;
    match opcode {
        STOP | SSTORE | CREATE | CREATE2 | RETURN | REVERT | INVALID => 0,

        ADD
        | SUB
        | LT
        | GT
        | SLT
        | SGT
        | EQ
        | ISZERO
        | AND
        | OR
        | XOR
        | NOT
        | BYTE
        | SHL
        | SHR
        | SAR
        | CALLDATALOAD
        | CALLDATACOPY
        | CODECOPY
        | RETURNDATACOPY
        | BLOBHASH
        | MLOAD
        | MSTORE
        | MSTORE8
        | MCOPY
        | PUSH1..=PUSH32
        | DUP1..=DUP16
        | SWAP1..=SWAP16
        | DUPN
        | SWAPN
        | EXCHANGE => 3,

        MUL | DIV | SDIV | MOD | SMOD | SIGNEXTEND | CLZ | SELFBALANCE => 5,
        ADDMOD | MULMOD | JUMP => 8,
        JUMPI => 10,
        JUMPDEST => 1,

        ADDRESS | ORIGIN | CALLER | CALLVALUE | CALLDATASIZE | CODESIZE | GASPRICE
        | RETURNDATASIZE | COINBASE | TIMESTAMP | NUMBER | DIFFICULTY | GASLIMIT | CHAINID
        | BASEFEE | BLOBBASEFEE | SLOTNUM | POP | PC | MSIZE | GAS | PUSH0 => 2,

        EXP => gas::EXP,
        KECCAK256 => gas::KECCAK256,
        BLOCKHASH => 20,
        TLOAD | TSTORE => 100,
        LOG0..=LOG4 => gas::LOG,

        // EIP-150 / EIP-1884 / EIP-2929 repricings.
        SLOAD => {
            if spec.is_enabled_in(BERLIN) {
                gas::WARM_STORAGE_READ_COST
            } else if spec.is_enabled_in(ISTANBUL) {
                gas::ISTANBUL_SLOAD_GAS
            } else if spec.is_enabled_in(TANGERINE) {
                200
            } else {
                50
            }
        }
        BALANCE => {
            if spec.is_enabled_in(BERLIN) {
                gas::WARM_STORAGE_READ_COST
            } else if spec.is_enabled_in(ISTANBUL) {
                700
            } else if spec.is_enabled_in(TANGERINE) {
                400
            } else {
                20
            }
        }
        EXTCODESIZE | EXTCODECOPY => {
            if spec.is_enabled_in(BERLIN) {
                gas::WARM_STORAGE_READ_COST
            } else if spec.is_enabled_in(TANGERINE) {
                700
            } else {
                20
            }
        }
        EXTCODEHASH => {
            if spec.is_enabled_in(BERLIN) {
                gas::WARM_STORAGE_READ_COST
            } else if spec.is_enabled_in(ISTANBUL) {
                700
            } else {
                400
            }
        }
        CALL | CALLCODE | DELEGATECALL | STATICCALL => {
            if spec.is_enabled_in(BERLIN) {
                gas::WARM_STORAGE_READ_COST
            } else if spec.is_enabled_in(TANGERINE) {
                700
            } else {
                40
            }
        }
        SELFDESTRUCT if spec.is_enabled_in(TANGERINE) => 5000,

        // Pre-Tangerine SELFDESTRUCT and undefined opcodes.
        _ => 0,
    }
}

/// Whether [`static_gas`] of `opcode` is the same under every [`SpecId`].
///
/// [`static_gas`] only switches at the Tangerine, Istanbul and Berlin thresholds, so those
/// plus the endpoints are exhaustive; `instructions_charge_static_gas_first` checks the
/// resulting charge against every spec.
pub const fn static_gas_is_spec_independent(opcode: u8) -> bool {
    use SpecId::*;
    let base = static_gas(opcode, FRONTIER);
    let specs = [TANGERINE, ISTANBUL, BERLIN, AMSTERDAM];
    let mut i = 0;
    while i < specs.len() {
        if static_gas(opcode, specs[i]) != base {
            return false;
        }
        i += 1;
    }
    true
}

const fn instruction_table_impl<WIRE: InterpreterTypes, H: Host>() -> [Instruction<WIRE, H>; 256] {
    use bytecode::opcode::*;
    let mut table = [Instruction::unknown(); 256];

    table[STOP as usize] = Instruction::new(control::stop);
    table[ADD as usize] = Instruction::new(arithmetic::add);
    table[MUL as usize] = Instruction::new(arithmetic::mul);
    table[SUB as usize] = Instruction::new(arithmetic::sub);
    table[DIV as usize] = Instruction::new(arithmetic::div);
    table[SDIV as usize] = Instruction::new(arithmetic::sdiv);
    table[MOD as usize] = Instruction::new(arithmetic::rem);
    table[SMOD as usize] = Instruction::new(arithmetic::smod);
    table[ADDMOD as usize] = Instruction::new(arithmetic::addmod);
    table[MULMOD as usize] = Instruction::new(arithmetic::mulmod);
    table[EXP as usize] = Instruction::new(arithmetic::exp);
    table[SIGNEXTEND as usize] = Instruction::new(arithmetic::signextend);

    table[LT as usize] = Instruction::new(bitwise::lt);
    table[GT as usize] = Instruction::new(bitwise::gt);
    table[SLT as usize] = Instruction::new(bitwise::slt);
    table[SGT as usize] = Instruction::new(bitwise::sgt);
    table[EQ as usize] = Instruction::new(bitwise::eq);
    table[ISZERO as usize] = Instruction::new(bitwise::iszero);
    table[AND as usize] = Instruction::new(bitwise::bitand);
    table[OR as usize] = Instruction::new(bitwise::bitor);
    table[XOR as usize] = Instruction::new(bitwise::bitxor);
    table[NOT as usize] = Instruction::new(bitwise::not);
    table[BYTE as usize] = Instruction::new(bitwise::byte);
    table[SHL as usize] = Instruction::new(bitwise::shl);
    table[SHR as usize] = Instruction::new(bitwise::shr);
    table[SAR as usize] = Instruction::new(bitwise::sar);
    table[CLZ as usize] = Instruction::new(bitwise::clz);

    table[KECCAK256 as usize] = Instruction::new(system::keccak256);

    table[ADDRESS as usize] = Instruction::new(system::address);
    table[BALANCE as usize] = Instruction::new(host::balance);
    table[ORIGIN as usize] = Instruction::new(tx_info::origin);
    table[CALLER as usize] = Instruction::new(system::caller);
    table[CALLVALUE as usize] = Instruction::new(system::callvalue);
    table[CALLDATALOAD as usize] = Instruction::new(system::calldataload);
    table[CALLDATASIZE as usize] = Instruction::new(system::calldatasize);
    table[CALLDATACOPY as usize] = Instruction::new(system::calldatacopy);
    table[CODESIZE as usize] = Instruction::new(system::codesize);
    table[CODECOPY as usize] = Instruction::new(system::codecopy);

    table[GASPRICE as usize] = Instruction::new(tx_info::gasprice);
    table[EXTCODESIZE as usize] = Instruction::new(host::extcodesize);
    table[EXTCODECOPY as usize] = Instruction::new(host::extcodecopy);
    table[RETURNDATASIZE as usize] = Instruction::new(system::returndatasize);
    table[RETURNDATACOPY as usize] = Instruction::new(system::returndatacopy);
    table[EXTCODEHASH as usize] = Instruction::new(host::extcodehash);
    table[BLOCKHASH as usize] = Instruction::new(host::blockhash);
    table[COINBASE as usize] = Instruction::new(block_info::coinbase);
    table[TIMESTAMP as usize] = Instruction::new(block_info::timestamp);
    table[NUMBER as usize] = Instruction::new(block_info::block_number);
    table[DIFFICULTY as usize] = Instruction::new(block_info::difficulty);
    table[GASLIMIT as usize] = Instruction::new(block_info::gaslimit);
    table[CHAINID as usize] = Instruction::new(block_info::chainid);
    table[SELFBALANCE as usize] = Instruction::new(host::selfbalance);
    table[BASEFEE as usize] = Instruction::new(block_info::basefee);
    table[BLOBHASH as usize] = Instruction::new(tx_info::blob_hash);
    table[BLOBBASEFEE as usize] = Instruction::new(block_info::blob_basefee);
    table[SLOTNUM as usize] = Instruction::new(block_info::slot_num);

    table[POP as usize] = Instruction::new(stack::pop);
    table[MLOAD as usize] = Instruction::new(memory::mload);
    table[MSTORE as usize] = Instruction::new(memory::mstore);
    table[MSTORE8 as usize] = Instruction::new(memory::mstore8);
    table[SLOAD as usize] = Instruction::new(host::sload);
    table[SSTORE as usize] = Instruction::new(host::sstore);
    table[JUMP as usize] = Instruction::new(control::jump);
    table[JUMPI as usize] = Instruction::new(control::jumpi);
    table[PC as usize] = Instruction::new(control::pc);
    table[MSIZE as usize] = Instruction::new(memory::msize);
    table[GAS as usize] = Instruction::new(system::gas);
    table[JUMPDEST as usize] = Instruction::new(control::jumpdest);
    table[TLOAD as usize] = Instruction::new(host::tload);
    table[TSTORE as usize] = Instruction::new(host::tstore);
    table[MCOPY as usize] = Instruction::new(memory::mcopy);

    table[PUSH0 as usize] = Instruction::new(stack::push0);
    table[PUSH1 as usize] = Instruction::new(stack::push::<1, _, _>);
    table[PUSH2 as usize] = Instruction::new(stack::push::<2, _, _>);
    table[PUSH3 as usize] = Instruction::new(stack::push::<3, _, _>);
    table[PUSH4 as usize] = Instruction::new(stack::push::<4, _, _>);
    table[PUSH5 as usize] = Instruction::new(stack::push::<5, _, _>);
    table[PUSH6 as usize] = Instruction::new(stack::push::<6, _, _>);
    table[PUSH7 as usize] = Instruction::new(stack::push::<7, _, _>);
    table[PUSH8 as usize] = Instruction::new(stack::push::<8, _, _>);
    table[PUSH9 as usize] = Instruction::new(stack::push::<9, _, _>);
    table[PUSH10 as usize] = Instruction::new(stack::push::<10, _, _>);
    table[PUSH11 as usize] = Instruction::new(stack::push::<11, _, _>);
    table[PUSH12 as usize] = Instruction::new(stack::push::<12, _, _>);
    table[PUSH13 as usize] = Instruction::new(stack::push::<13, _, _>);
    table[PUSH14 as usize] = Instruction::new(stack::push::<14, _, _>);
    table[PUSH15 as usize] = Instruction::new(stack::push::<15, _, _>);
    table[PUSH16 as usize] = Instruction::new(stack::push::<16, _, _>);
    table[PUSH17 as usize] = Instruction::new(stack::push::<17, _, _>);
    table[PUSH18 as usize] = Instruction::new(stack::push::<18, _, _>);
    table[PUSH19 as usize] = Instruction::new(stack::push::<19, _, _>);
    table[PUSH20 as usize] = Instruction::new(stack::push::<20, _, _>);
    table[PUSH21 as usize] = Instruction::new(stack::push::<21, _, _>);
    table[PUSH22 as usize] = Instruction::new(stack::push::<22, _, _>);
    table[PUSH23 as usize] = Instruction::new(stack::push::<23, _, _>);
    table[PUSH24 as usize] = Instruction::new(stack::push::<24, _, _>);
    table[PUSH25 as usize] = Instruction::new(stack::push::<25, _, _>);
    table[PUSH26 as usize] = Instruction::new(stack::push::<26, _, _>);
    table[PUSH27 as usize] = Instruction::new(stack::push::<27, _, _>);
    table[PUSH28 as usize] = Instruction::new(stack::push::<28, _, _>);
    table[PUSH29 as usize] = Instruction::new(stack::push::<29, _, _>);
    table[PUSH30 as usize] = Instruction::new(stack::push::<30, _, _>);
    table[PUSH31 as usize] = Instruction::new(stack::push::<31, _, _>);
    table[PUSH32 as usize] = Instruction::new(stack::push::<32, _, _>);

    table[DUP1 as usize] = Instruction::new(stack::dup::<1, _, _>);
    table[DUP2 as usize] = Instruction::new(stack::dup::<2, _, _>);
    table[DUP3 as usize] = Instruction::new(stack::dup::<3, _, _>);
    table[DUP4 as usize] = Instruction::new(stack::dup::<4, _, _>);
    table[DUP5 as usize] = Instruction::new(stack::dup::<5, _, _>);
    table[DUP6 as usize] = Instruction::new(stack::dup::<6, _, _>);
    table[DUP7 as usize] = Instruction::new(stack::dup::<7, _, _>);
    table[DUP8 as usize] = Instruction::new(stack::dup::<8, _, _>);
    table[DUP9 as usize] = Instruction::new(stack::dup::<9, _, _>);
    table[DUP10 as usize] = Instruction::new(stack::dup::<10, _, _>);
    table[DUP11 as usize] = Instruction::new(stack::dup::<11, _, _>);
    table[DUP12 as usize] = Instruction::new(stack::dup::<12, _, _>);
    table[DUP13 as usize] = Instruction::new(stack::dup::<13, _, _>);
    table[DUP14 as usize] = Instruction::new(stack::dup::<14, _, _>);
    table[DUP15 as usize] = Instruction::new(stack::dup::<15, _, _>);
    table[DUP16 as usize] = Instruction::new(stack::dup::<16, _, _>);

    table[SWAP1 as usize] = Instruction::new(stack::swap::<1, _, _>);
    table[SWAP2 as usize] = Instruction::new(stack::swap::<2, _, _>);
    table[SWAP3 as usize] = Instruction::new(stack::swap::<3, _, _>);
    table[SWAP4 as usize] = Instruction::new(stack::swap::<4, _, _>);
    table[SWAP5 as usize] = Instruction::new(stack::swap::<5, _, _>);
    table[SWAP6 as usize] = Instruction::new(stack::swap::<6, _, _>);
    table[SWAP7 as usize] = Instruction::new(stack::swap::<7, _, _>);
    table[SWAP8 as usize] = Instruction::new(stack::swap::<8, _, _>);
    table[SWAP9 as usize] = Instruction::new(stack::swap::<9, _, _>);
    table[SWAP10 as usize] = Instruction::new(stack::swap::<10, _, _>);
    table[SWAP11 as usize] = Instruction::new(stack::swap::<11, _, _>);
    table[SWAP12 as usize] = Instruction::new(stack::swap::<12, _, _>);
    table[SWAP13 as usize] = Instruction::new(stack::swap::<13, _, _>);
    table[SWAP14 as usize] = Instruction::new(stack::swap::<14, _, _>);
    table[SWAP15 as usize] = Instruction::new(stack::swap::<15, _, _>);
    table[SWAP16 as usize] = Instruction::new(stack::swap::<16, _, _>);

    table[DUPN as usize] = Instruction::new(stack::dupn);
    table[SWAPN as usize] = Instruction::new(stack::swapn);
    table[EXCHANGE as usize] = Instruction::new(stack::exchange);

    table[LOG0 as usize] = Instruction::new(host::log::<0, _>);
    table[LOG1 as usize] = Instruction::new(host::log::<1, _>);
    table[LOG2 as usize] = Instruction::new(host::log::<2, _>);
    table[LOG3 as usize] = Instruction::new(host::log::<3, _>);
    table[LOG4 as usize] = Instruction::new(host::log::<4, _>);

    table[CREATE as usize] = Instruction::new(contract::create::<_, false, _>);
    table[CALL as usize] = Instruction::new(contract::call);
    table[CALLCODE as usize] = Instruction::new(contract::call_code);
    table[RETURN as usize] = Instruction::new(control::ret);
    table[DELEGATECALL as usize] = Instruction::new(contract::delegate_call);
    table[CREATE2 as usize] = Instruction::new(contract::create::<_, true, _>);

    table[STATICCALL as usize] = Instruction::new(contract::static_call);
    table[REVERT as usize] = Instruction::new(control::revert);
    table[INVALID as usize] = Instruction::new(control::invalid);
    table[SELFDESTRUCT as usize] = Instruction::new(host::selfdestruct);
    table
}

#[cfg(test)]
mod tests {
    use super::{instruction_table, static_gas};
    use crate::{
        host::DummyHost,
        interpreter::{EthInterpreter, ExtBytecode, InputsImpl, SharedMemory},
        interpreter_types::LoopControl,
        InstructionResult, Interpreter,
    };
    use bytecode::{opcode::*, Bytecode};
    use primitives::{hardfork::SpecId, Bytes};

    fn all_specs() -> Vec<SpecId> {
        (0..=u8::MAX).filter_map(SpecId::try_from_u8).collect()
    }

    /// The per-spec static gas table this crate shipped before static gas moved into the
    /// instructions: `instruction_table_impl` base costs plus
    /// `instruction_table_gas_changes_spec`.
    fn legacy_static_gas_table(spec: SpecId) -> [u64; 256] {
        use super::gas;
        use SpecId::*;
        let mut t = [0u64; 256];
        t[STOP as usize] = 0;
        t[ADD as usize] = 3;
        t[MUL as usize] = 5;
        t[SUB as usize] = 3;
        t[DIV as usize] = 5;
        t[SDIV as usize] = 5;
        t[MOD as usize] = 5;
        t[SMOD as usize] = 5;
        t[ADDMOD as usize] = 8;
        t[MULMOD as usize] = 8;
        t[EXP as usize] = gas::EXP;
        t[SIGNEXTEND as usize] = 5;
        t[LT as usize] = 3;
        t[GT as usize] = 3;
        t[SLT as usize] = 3;
        t[SGT as usize] = 3;
        t[EQ as usize] = 3;
        t[ISZERO as usize] = 3;
        t[AND as usize] = 3;
        t[OR as usize] = 3;
        t[XOR as usize] = 3;
        t[NOT as usize] = 3;
        t[BYTE as usize] = 3;
        t[SHL as usize] = 3;
        t[SHR as usize] = 3;
        t[SAR as usize] = 3;
        t[CLZ as usize] = 5;
        t[KECCAK256 as usize] = gas::KECCAK256;
        t[ADDRESS as usize] = 2;
        t[BALANCE as usize] = 20;
        t[ORIGIN as usize] = 2;
        t[CALLER as usize] = 2;
        t[CALLVALUE as usize] = 2;
        t[CALLDATALOAD as usize] = 3;
        t[CALLDATASIZE as usize] = 2;
        t[CALLDATACOPY as usize] = 3;
        t[CODESIZE as usize] = 2;
        t[CODECOPY as usize] = 3;
        t[GASPRICE as usize] = 2;
        t[EXTCODESIZE as usize] = 20;
        t[EXTCODECOPY as usize] = 20;
        t[RETURNDATASIZE as usize] = 2;
        t[RETURNDATACOPY as usize] = 3;
        t[EXTCODEHASH as usize] = 400;
        t[BLOCKHASH as usize] = 20;
        t[COINBASE as usize] = 2;
        t[TIMESTAMP as usize] = 2;
        t[NUMBER as usize] = 2;
        t[DIFFICULTY as usize] = 2;
        t[GASLIMIT as usize] = 2;
        t[CHAINID as usize] = 2;
        t[SELFBALANCE as usize] = 5;
        t[BASEFEE as usize] = 2;
        t[BLOBHASH as usize] = 3;
        t[BLOBBASEFEE as usize] = 2;
        t[SLOTNUM as usize] = 2;
        t[POP as usize] = 2;
        t[MLOAD as usize] = 3;
        t[MSTORE as usize] = 3;
        t[MSTORE8 as usize] = 3;
        t[SLOAD as usize] = 50;
        t[SSTORE as usize] = 0;
        t[JUMP as usize] = 8;
        t[JUMPI as usize] = 10;
        t[PC as usize] = 2;
        t[MSIZE as usize] = 2;
        t[GAS as usize] = 2;
        t[JUMPDEST as usize] = 1;
        t[TLOAD as usize] = 100;
        t[TSTORE as usize] = 100;
        t[MCOPY as usize] = 3;
        t[PUSH0 as usize] = 2;
        t[PUSH1 as usize] = 3;
        t[PUSH2 as usize] = 3;
        t[PUSH3 as usize] = 3;
        t[PUSH4 as usize] = 3;
        t[PUSH5 as usize] = 3;
        t[PUSH6 as usize] = 3;
        t[PUSH7 as usize] = 3;
        t[PUSH8 as usize] = 3;
        t[PUSH9 as usize] = 3;
        t[PUSH10 as usize] = 3;
        t[PUSH11 as usize] = 3;
        t[PUSH12 as usize] = 3;
        t[PUSH13 as usize] = 3;
        t[PUSH14 as usize] = 3;
        t[PUSH15 as usize] = 3;
        t[PUSH16 as usize] = 3;
        t[PUSH17 as usize] = 3;
        t[PUSH18 as usize] = 3;
        t[PUSH19 as usize] = 3;
        t[PUSH20 as usize] = 3;
        t[PUSH21 as usize] = 3;
        t[PUSH22 as usize] = 3;
        t[PUSH23 as usize] = 3;
        t[PUSH24 as usize] = 3;
        t[PUSH25 as usize] = 3;
        t[PUSH26 as usize] = 3;
        t[PUSH27 as usize] = 3;
        t[PUSH28 as usize] = 3;
        t[PUSH29 as usize] = 3;
        t[PUSH30 as usize] = 3;
        t[PUSH31 as usize] = 3;
        t[PUSH32 as usize] = 3;
        t[DUP1 as usize] = 3;
        t[DUP2 as usize] = 3;
        t[DUP3 as usize] = 3;
        t[DUP4 as usize] = 3;
        t[DUP5 as usize] = 3;
        t[DUP6 as usize] = 3;
        t[DUP7 as usize] = 3;
        t[DUP8 as usize] = 3;
        t[DUP9 as usize] = 3;
        t[DUP10 as usize] = 3;
        t[DUP11 as usize] = 3;
        t[DUP12 as usize] = 3;
        t[DUP13 as usize] = 3;
        t[DUP14 as usize] = 3;
        t[DUP15 as usize] = 3;
        t[DUP16 as usize] = 3;
        t[SWAP1 as usize] = 3;
        t[SWAP2 as usize] = 3;
        t[SWAP3 as usize] = 3;
        t[SWAP4 as usize] = 3;
        t[SWAP5 as usize] = 3;
        t[SWAP6 as usize] = 3;
        t[SWAP7 as usize] = 3;
        t[SWAP8 as usize] = 3;
        t[SWAP9 as usize] = 3;
        t[SWAP10 as usize] = 3;
        t[SWAP11 as usize] = 3;
        t[SWAP12 as usize] = 3;
        t[SWAP13 as usize] = 3;
        t[SWAP14 as usize] = 3;
        t[SWAP15 as usize] = 3;
        t[SWAP16 as usize] = 3;
        t[DUPN as usize] = 3;
        t[SWAPN as usize] = 3;
        t[EXCHANGE as usize] = 3;
        t[LOG0 as usize] = gas::LOG;
        t[LOG1 as usize] = gas::LOG;
        t[LOG2 as usize] = gas::LOG;
        t[LOG3 as usize] = gas::LOG;
        t[LOG4 as usize] = gas::LOG;
        t[CREATE as usize] = 0;
        t[CALL as usize] = 40;
        t[CALLCODE as usize] = 40;
        t[RETURN as usize] = 0;
        t[DELEGATECALL as usize] = 40;
        t[CREATE2 as usize] = 0;
        t[STATICCALL as usize] = 40;
        t[REVERT as usize] = 0;
        t[INVALID as usize] = 0;
        t[SELFDESTRUCT as usize] = 0;

        if spec.is_enabled_in(TANGERINE) {
            t[SLOAD as usize] = 200;
            t[BALANCE as usize] = 400;
            t[EXTCODESIZE as usize] = 700;
            t[EXTCODECOPY as usize] = 700;
            t[CALL as usize] = 700;
            t[CALLCODE as usize] = 700;
            t[DELEGATECALL as usize] = 700;
            t[STATICCALL as usize] = 700;
            t[SELFDESTRUCT as usize] = 5000;
        }
        if spec.is_enabled_in(ISTANBUL) {
            t[SLOAD as usize] = gas::ISTANBUL_SLOAD_GAS;
            t[BALANCE as usize] = 700;
            t[EXTCODEHASH as usize] = 700;
        }
        if spec.is_enabled_in(BERLIN) {
            t[SLOAD as usize] = gas::WARM_STORAGE_READ_COST;
            t[BALANCE as usize] = gas::WARM_STORAGE_READ_COST;
            t[EXTCODESIZE as usize] = gas::WARM_STORAGE_READ_COST;
            t[EXTCODEHASH as usize] = gas::WARM_STORAGE_READ_COST;
            t[EXTCODECOPY as usize] = gas::WARM_STORAGE_READ_COST;
            t[CALL as usize] = gas::WARM_STORAGE_READ_COST;
            t[CALLCODE as usize] = gas::WARM_STORAGE_READ_COST;
            t[DELEGATECALL as usize] = gas::WARM_STORAGE_READ_COST;
            t[STATICCALL as usize] = gas::WARM_STORAGE_READ_COST;
        }
        t
    }

    #[test]
    fn static_gas_matches_legacy_table() {
        let specs = all_specs();
        assert!(specs.contains(&SpecId::AMSTERDAM));
        for spec in specs {
            let legacy = legacy_static_gas_table(spec);
            for op in 0..=u8::MAX {
                assert_eq!(
                    static_gas(op, spec),
                    legacy[op as usize],
                    "opcode 0x{op:02X} under {spec:?}"
                );
            }
        }
    }

    /// Runs `op` alone with `gas_limit` and returns the halt result, if any.
    fn step_result(op: u8, spec: SpecId, gas_limit: u64) -> Option<InstructionResult> {
        let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(&[op, 0, 0]));
        let mut interpreter = Interpreter::<EthInterpreter>::new(
            SharedMemory::new(),
            ExtBytecode::new(bytecode),
            InputsImpl::default(),
            false,
            spec,
            gas_limit,
        );
        let table = instruction_table::<EthInterpreter, DummyHost>();
        let mut host = DummyHost::new(spec);
        interpreter.step(&table, &mut host);
        interpreter
            .bytecode
            .action()
            .as_ref()
            .and_then(|a| a.instruction_result())
    }

    /// Every instruction charges exactly `static_gas` before doing anything else: one gas
    /// short is out-of-gas, exactly enough is never out-of-gas.
    #[test]
    fn instructions_charge_static_gas_first() {
        for spec in all_specs() {
            for op in 0..=u8::MAX {
                let cost = static_gas(op, spec);
                if cost > 0 {
                    assert_eq!(
                        step_result(op, spec, cost - 1),
                        Some(InstructionResult::OutOfGas),
                        "opcode 0x{op:02X} under {spec:?} with {} gas",
                        cost - 1
                    );
                }
                // `DummyHost` has no prevrandao, which post-Merge DIFFICULTY unwraps.
                if op == DIFFICULTY && spec.is_enabled_in(SpecId::MERGE) {
                    continue;
                }
                assert_ne!(
                    step_result(op, spec, cost),
                    Some(InstructionResult::OutOfGas),
                    "opcode 0x{op:02X} under {spec:?} with {cost} gas"
                );
            }
        }
    }

    #[test]
    fn all_instructions_and_opcodes_used() {
        // known unknown instruction we compare it with other instructions from table.
        let unknown_instruction = 0x0C_usize;
        let instr_table = instruction_table::<EthInterpreter, DummyHost>();

        let unknown_istr = instr_table[unknown_instruction];
        for (i, instr) in instr_table.iter().enumerate() {
            let is_opcode_unknown = OpCode::new(i as u8).is_none();
            //
            let is_instr_unknown = std::ptr::fn_addr_eq(instr.fn_, unknown_istr.fn_);
            assert_eq!(
                is_instr_unknown, is_opcode_unknown,
                "Opcode 0x{i:X?} is not handled",
            );
        }
    }
}
