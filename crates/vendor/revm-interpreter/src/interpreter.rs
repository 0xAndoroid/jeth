//! Core interpreter implementation and components.

/// Extended bytecode functionality.
pub mod ext_bytecode;
mod input;
mod loop_control;
mod return_data;
mod runtime_flags;
mod shared_memory;
mod stack;
pub(crate) mod words;

use context_interface::cfg::GasParams;
// re-exports
pub use ext_bytecode::ExtBytecode;
pub use input::InputsImpl;
pub use return_data::ReturnDataImpl;
pub use runtime_flags::RuntimeFlags;
pub use shared_memory::{num_words, resize_memory, SharedMemory};
pub use stack::{Stack, STACK_LIMIT};

// imports
use crate::{
    host::DummyHost, instruction_context::InstructionContext, interpreter_types::*, Gas, Host,
    InstructionResult, InstructionTable, InterpreterAction,
};
use bytecode::Bytecode;
use primitives::{hardfork::SpecId, Bytes};

// Keep the existing classifier. Only these host-free kernels use local gas.
macro_rules! cached_dispatch {
    (arithmetic::add, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure add, $ip, $interpreter, $host, $remaining) };
    (arithmetic::sub, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure sub, $ip, $interpreter, $host, $remaining) };
    (arithmetic::mul, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure mul, $ip, $interpreter, $host, $remaining) };
    (arithmetic::div, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure div, $ip, $interpreter, $host, $remaining) };
    (bitwise::lt, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure lt, $ip, $interpreter, $host, $remaining) };
    (bitwise::gt, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure gt, $ip, $interpreter, $host, $remaining) };
    (bitwise::eq, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure eq, $ip, $interpreter, $host, $remaining) };
    (bitwise::iszero, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure iszero, $ip, $interpreter, $host, $remaining) };
    (bitwise::bitand, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure bitand, $ip, $interpreter, $host, $remaining) };
    (bitwise::bitor, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure bitor, $ip, $interpreter, $host, $remaining) };
    (bitwise::not, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure not, $ip, $interpreter, $host, $remaining) };
    (bitwise::shl, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure shl, $ip, $interpreter, $host, $remaining) };
    (bitwise::shr, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure shr, $ip, $interpreter, $host, $remaining) };
    (stack::pop, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure pop, $ip, $interpreter, $host, $remaining) };
    (stack::push0, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure push0, $ip, $interpreter, $host, $remaining) };
    (control::jumpdest, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@pure jumpdest, $ip, $interpreter, $host, $remaining) };
    (stack::push::<$n:literal>, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@generic push::<$n>, $ip, $interpreter, $host, $remaining) };
    (stack::dup::<$n:literal>, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@generic dup::<$n>, $ip, $interpreter, $host, $remaining) };
    (stack::swap::<$n:literal>, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => { cached_dispatch!(@generic swap::<$n>, $ip, $interpreter, $host, $remaining) };
    (@pure $name:ident, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => {
        crate::instructions::cached::$name($ip, InstructionContext {
            interpreter: &mut *$interpreter, host: &mut *$host,
        }, $remaining)
    };
    (@generic $name:ident::<$n:literal>, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => {
        crate::instructions::cached::$name::<$n, _, _>($ip, InstructionContext {
            interpreter: &mut *$interpreter, host: &mut *$host,
        }, $remaining)
    };
    ($module:ident::$name:ident $(::<$n:literal>)?, $ip:expr, $interpreter:expr, $host:expr, $remaining:expr) => {{
        let cache = $remaining;
        $interpreter.gas.set_remaining(*cache);
        let next = crate::instructions::$module::$name $(::<$n, _, _>)?($ip, InstructionContext {
            interpreter: &mut *$interpreter, host: &mut *$host,
        });
        *cache = $interpreter.gas.remaining();
        next
    }};
}

// Keep the identity checks and direct calls tied to the same opcode list.
macro_rules! inline_dispatch {
    ($wire:ident; $( $opcode:ident => $module:ident::$name:ident $(::<$n:literal>)? ),+ $(,)?) => {
        /// Executes until halt or yield, specializing only canonical instruction tables.
        #[inline]
        pub fn run_plain<H: Host + ?Sized>(
            &mut self,
            instruction_table: &InstructionTable<$wire, H>,
            host: &mut H,
        ) -> InterpreterAction {
            use bytecode::opcode::*;
            let canonical = true $( && instruction_table[$opcode as usize].is(
                crate::Instruction::new(crate::instructions::$module::$name $(::<$n, $wire, H>)?)
            ))+;
            if canonical {
                self.run_plain_inner::<H, true>(instruction_table, host)
            } else {
                self.run_plain_inner::<H, false>(instruction_table, host)
            }
        }

        #[inline(never)]
        fn run_plain_inner<H: Host + ?Sized, const INLINE: bool>(
            &mut self,
            instruction_table: &InstructionTable<$wire, H>,
            host: &mut H,
        ) -> InterpreterAction {
            use bytecode::opcode::*;
            let mut ip = self.bytecode.ip();
            let mut remaining = if INLINE { self.gas.remaining() } else { 0 };
            loop {
                // SAFETY: analysed bytecode is padded with STOP, as in `step`.
                let (opcode, next) = unsafe { (*ip, ip.add(1)) };
                ip = match opcode {
                    $( $opcode if INLINE => cached_dispatch!($module::$name $(::<$n>)?, next, self, host, &mut remaining), )+
                    _ => {
                        let instruction = unsafe { instruction_table.get_unchecked(opcode as usize) };
                        if INLINE { self.gas.set_remaining(remaining); }
                        let next = instruction.execute(next, InstructionContext { interpreter: self, host });
                        if INLINE { remaining = self.gas.remaining(); }
                        next
                    }
                };
                if ip.is_null() {
                    // Failures synchronized before constructing the action. OOG
                    // has spent the gas; do not restore the old local budget.
                    break;
                }
            }
            self.take_next_action()
        }
    };
}

/// Main interpreter structure that contains all components defined in [`InterpreterTypes`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Interpreter<WIRE: InterpreterTypes = EthInterpreter> {
    /// Bytecode being executed.
    pub bytecode: WIRE::Bytecode,
    /// Gas tracking for execution costs.
    pub gas: Gas,
    /// EVM stack for computation.
    pub stack: WIRE::Stack,
    /// Buffer for return data from calls.
    pub return_data: WIRE::ReturnData,
    /// EVM memory for data storage.
    pub memory: WIRE::Memory,
    /// Input data for current execution context.
    pub input: WIRE::Input,
    /// Runtime flags controlling execution behavior.
    pub runtime_flag: WIRE::RuntimeFlag,
    /// Extended functionality and customizations.
    pub extend: WIRE::Extend,
}

impl<EXT: Default> Interpreter<EthInterpreter<EXT>> {
    /// Create new interpreter
    pub fn new(
        memory: SharedMemory,
        bytecode: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: SpecId,
        gas_limit: u64,
    ) -> Self {
        Self::new_inner(
            Stack::new(),
            memory,
            bytecode,
            input,
            is_static,
            spec_id,
            gas_limit,
        )
    }

    /// Create a new interpreter with default extended functionality.
    pub fn default_ext() -> Self {
        Self::do_default(Stack::new(), SharedMemory::new())
    }

    /// Create a new invalid interpreter.
    pub fn invalid() -> Self {
        Self::do_default(Stack::invalid(), SharedMemory::invalid())
    }

    fn do_default(stack: Stack, memory: SharedMemory) -> Self {
        Self::new_inner(
            stack,
            memory,
            ExtBytecode::default(),
            InputsImpl::default(),
            false,
            SpecId::default(),
            u64::MAX,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        stack: Stack,
        memory: SharedMemory,
        bytecode: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: SpecId,
        gas_limit: u64,
    ) -> Self {
        Self {
            bytecode,
            gas: Gas::new(gas_limit),
            stack,
            return_data: Default::default(),
            memory,
            input,
            runtime_flag: RuntimeFlags { is_static, spec_id },
            extend: Default::default(),
        }
    }

    /// Clears and reinitializes the interpreter with new parameters.
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub fn clear(
        &mut self,
        memory: SharedMemory,
        bytecode: ExtBytecode,
        input: InputsImpl,
        is_static: bool,
        spec_id: SpecId,
        gas_limit: u64,
        reservoir_remaining_gas: u64,
    ) {
        let Self {
            bytecode: bytecode_ref,
            gas,
            stack,
            return_data,
            memory: memory_ref,
            input: input_ref,
            runtime_flag,
            extend,
        } = self;
        *bytecode_ref = bytecode;
        *gas = Gas::new_with_regular_gas_and_reservoir(gas_limit, reservoir_remaining_gas);
        if stack.data().capacity() == 0 {
            *stack = Stack::new();
        } else {
            stack.clear();
        }
        return_data.0.clear();
        *memory_ref = memory;
        *input_ref = input;
        *runtime_flag = RuntimeFlags { spec_id, is_static };
        *extend = EXT::default();
    }

    /// Sets the bytecode that is going to be executed
    pub fn with_bytecode(mut self, bytecode: Bytecode) -> Self {
        self.bytecode = ExtBytecode::new(bytecode);
        self
    }
}

impl Default for Interpreter<EthInterpreter> {
    fn default() -> Self {
        Self::default_ext()
    }
}

/// Default types for Ethereum interpreter.
#[derive(Debug)]
pub struct EthInterpreter<EXT = (), MG = SharedMemory> {
    _phantom: core::marker::PhantomData<fn() -> (EXT, MG)>,
}

impl<EXT> InterpreterTypes for EthInterpreter<EXT> {
    type Stack = Stack;
    type Memory = SharedMemory;
    type Bytecode = ExtBytecode;
    type ReturnData = ReturnDataImpl;
    type Input = InputsImpl;
    type RuntimeFlag = RuntimeFlags;
    type Extend = EXT;
    type Output = InterpreterAction;
}

impl<IW: InterpreterTypes> Interpreter<IW> {
    /// Performs EVM memory resize.
    #[inline]
    #[must_use]
    pub fn resize_memory(&mut self, gas_params: &GasParams, offset: usize, len: usize) -> bool {
        if let Err(result) = resize_memory(&mut self.gas, &mut self.memory, gas_params, offset, len)
        {
            let _ = self.halt(result);
            return false;
        }
        true
    }

    /// Takes the next action from the control and returns it.
    #[inline]
    pub fn take_next_action(&mut self) -> InterpreterAction {
        core::mem::take(self.bytecode.action()).expect("Interpreter to set action")
    }

    /// Halt the interpreter with the given result.
    ///
    /// This will set the action to [`InterpreterAction::Return`] and set the gas to the current gas.
    /// Returns the null [`Ip`] that stops the run loop; instructions return it directly.
    #[cold]
    #[inline(never)]
    #[must_use]
    pub fn halt(&mut self, result: InstructionResult) -> Ip {
        self.bytecode
            .set_action(InterpreterAction::new_halt(result, self.gas));
        // Opaque null: if callers could see the constant they would materialise it after the
        // call instead of tail-calling, which puts a `ra` spill/reload on every instruction's
        // hot path.
        core::hint::black_box(core::ptr::null())
    }

    /// Halt the interpreter with the given result.
    ///
    /// This will set the action to [`InterpreterAction::Return`] and set the gas to the current gas.
    #[cold]
    #[inline(never)]
    #[must_use]
    pub fn halt_fatal(&mut self) -> Ip {
        self.halt(InstructionResult::FatalExternalError)
    }

    /// Halt the interpreter with an out-of-gas error.
    #[cold]
    #[inline(never)]
    #[must_use]
    pub fn halt_oog(&mut self) -> Ip {
        self.gas.spend_all();
        self.halt(InstructionResult::OutOfGas)
    }

    /// Halt the interpreter with an out-of-gas error.
    #[cold]
    #[inline(never)]
    #[must_use]
    pub fn halt_memory_oog(&mut self) -> Ip {
        self.halt(InstructionResult::MemoryOOG)
    }

    /// Halt the interpreter with an out-of-gas error.
    #[cold]
    #[inline(never)]
    #[must_use]
    pub fn halt_memory_limit_oog(&mut self) -> Ip {
        self.halt(InstructionResult::MemoryLimitOOG)
    }

    /// Halt the interpreter with and overflow error.
    #[cold]
    #[inline(never)]
    #[must_use]
    pub fn halt_overflow(&mut self) -> Ip {
        self.halt(InstructionResult::StackOverflow)
    }

    /// Halt the interpreter with and underflow error.
    #[cold]
    #[inline(never)]
    #[must_use]
    pub fn halt_underflow(&mut self) -> Ip {
        self.halt(InstructionResult::StackUnderflow)
    }

    /// Halt the interpreter with and not activated error.
    #[cold]
    #[inline(never)]
    #[must_use]
    pub fn halt_not_activated(&mut self) -> Ip {
        self.halt(InstructionResult::NotActivated)
    }

    /// Yields the frame at `ip`: persists `ip` so the frame resumes at the next instruction,
    /// sets `action`, and returns the null [`Ip`] that stops the run loop.
    ///
    /// Like the `halt*` helpers, this produces the null [`Ip`] that stops the run loop.
    #[inline]
    #[must_use]
    pub fn set_action_at(&mut self, ip: Ip, action: InterpreterAction) -> Ip {
        self.bytecode.set_ip(ip);
        self.bytecode.set_action(action);
        core::ptr::null()
    }

    /// Return with the given output.
    ///
    /// This will set the action to [`InterpreterAction::Return`] and set the gas to the current gas.
    pub fn return_with_output(&mut self, output: Bytes) {
        self.bytecode.set_action(InterpreterAction::new_return(
            InstructionResult::Return,
            output,
            self.gas,
        ));
    }

    /// Executes the instruction at the persisted instruction pointer and persists the next one.
    ///
    /// Single-step entry for inspectors (`revm_inspector::inspect_instructions`); the run loop
    /// ([`run_plain`](Self::run_plain)) keeps the pointer in a register instead.
    #[inline]
    pub fn step<H: Host + ?Sized>(
        &mut self,
        instruction_table: &InstructionTable<IW, H>,
        host: &mut H,
    ) {
        let ip = self.bytecode.ip();
        // SAFETY: In analysis we are doing padding of bytecode so that we are sure that last
        // byte instruction is STOP so we are safe to just increment program_counter bcs on last instruction
        // it will do noop and just stop execution of this contract
        let (opcode, ip) = unsafe { (*ip, ip.add(1)) };
        // Persist the incremented pointer first so `pc()` after a halt is the byte after the opcode.
        self.bytecode.set_ip(ip);

        let instruction = unsafe { instruction_table.get_unchecked(opcode as usize) };

        let context = InstructionContext {
            interpreter: self,
            host,
        };
        let next = instruction.execute(ip, context);
        if !next.is_null() {
            self.bytecode.set_ip(next);
        }
    }

    /// Executes the instruction at the current instruction pointer.
    ///
    /// Internally it will increment instruction pointer by one.
    ///
    /// This uses dummy Host.
    #[inline]
    pub fn step_dummy(&mut self, instruction_table: &InstructionTable<IW, DummyHost>) {
        self.step(instruction_table, &mut DummyHost::default());
    }

    inline_dispatch!(IW;
        KECCAK256 => system::keccak256,
        MUL => arithmetic::mul,
        DIV => arithmetic::div,
        SIGNEXTEND => arithmetic::signextend,
        SLT => bitwise::slt,
        OR => bitwise::bitor,
        NOT => bitwise::not,
        SHL => bitwise::shl,
        SHR => bitwise::shr,
        CALLER => system::caller,
        CALLDATALOAD => system::calldataload,
        CALLDATASIZE => system::calldatasize,
        RETURNDATASIZE => system::returndatasize,
        GAS => system::gas,
        STOP => control::stop,
        ADD => arithmetic::add,
        SUB => arithmetic::sub,
        LT => bitwise::lt,
        GT => bitwise::gt,
        EQ => bitwise::eq,
        ISZERO => bitwise::iszero,
        AND => bitwise::bitand,
        POP => stack::pop,
        MLOAD => memory::mload,
        MSTORE => memory::mstore,
        JUMP => control::jump,
        JUMPI => control::jumpi,
        JUMPDEST => control::jumpdest,
        PUSH0 => stack::push0,
        PUSH1 => stack::push::<1>,
        PUSH2 => stack::push::<2>,
        PUSH3 => stack::push::<3>,
        PUSH4 => stack::push::<4>,
        PUSH8 => stack::push::<8>,
        PUSH20 => stack::push::<20>,
        PUSH32 => stack::push::<32>,
        DUP1 => stack::dup::<1>,
        DUP2 => stack::dup::<2>,
        DUP3 => stack::dup::<3>,
        DUP4 => stack::dup::<4>,
        DUP5 => stack::dup::<5>,
        DUP6 => stack::dup::<6>,
        DUP7 => stack::dup::<7>,
        DUP8 => stack::dup::<8>,
        DUP9 => stack::dup::<9>,
        DUP10 => stack::dup::<10>,
        DUP11 => stack::dup::<11>,
        DUP12 => stack::dup::<12>,
        DUP13 => stack::dup::<13>,
        SWAP1 => stack::swap::<1>,
        SWAP2 => stack::swap::<2>,
        SWAP3 => stack::swap::<3>,
        SWAP4 => stack::swap::<4>,
        SWAP5 => stack::swap::<5>,
        SWAP6 => stack::swap::<6>,
        SWAP7 => stack::swap::<7>,
        SELFDESTRUCT => host::selfdestruct,
    );
}

/* used for cargo asm
pub fn asm_step(
    interpreter: &mut Interpreter<EthInterpreter>,
    instruction_table: &InstructionTable<EthInterpreter, DummyHost>,
    host: &mut DummyHost,
) {
    interpreter.step(instruction_table, host);
}

pub fn asm_run(
    interpreter: &mut Interpreter<EthInterpreter>,
    instruction_table: &InstructionTable<EthInterpreter, DummyHost>,
    host: &mut DummyHost,
) {
    interpreter.run_plain(instruction_table, host);
}
*/

/// The result of an interpreter operation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(::serde::Serialize, ::serde::Deserialize))]
pub struct InterpreterResult {
    /// The result of the instruction execution.
    pub result: InstructionResult,
    /// The output of the instruction execution.
    pub output: Bytes,
    /// The gas usage information.
    pub gas: Gas,
}

impl InterpreterResult {
    /// Returns a new `InterpreterResult` with the given values.
    pub fn new(result: InstructionResult, output: Bytes, gas: Gas) -> Self {
        Self {
            result,
            output,
            gas,
        }
    }

    /// Returns a new `InterpreterResult` for an out-of-gas error with the given gas limit.
    pub fn new_oog(gas_limit: u64) -> Self {
        Self {
            result: InstructionResult::OutOfGas,
            output: Bytes::default(),
            gas: Gas::new_spent(gas_limit),
        }
    }

    /// Returns whether the instruction result is a success.
    #[inline]
    pub const fn is_ok(&self) -> bool {
        self.result.is_ok()
    }

    /// Returns whether the instruction result is a revert.
    #[inline]
    pub const fn is_revert(&self) -> bool {
        self.result.is_revert()
    }

    /// Returns whether the instruction result is an error.
    #[inline]
    pub const fn is_error(&self) -> bool {
        self.result.is_error()
    }
}

// Special implementation for types where Output can be created from InterpreterAction
impl<IW: InterpreterTypes> Interpreter<IW>
where
    IW::Output: From<InterpreterAction>,
{
    /// Takes the next action from the control and returns it as the specific Output type.
    #[inline]
    pub fn take_next_action_as_output(&mut self) -> IW::Output {
        From::from(self.take_next_action())
    }

    /// Executes the interpreter until it returns or stops, returning the specific Output type.
    #[inline]
    pub fn run_plain_as_output<H: Host + ?Sized>(
        &mut self,
        instruction_table: &InstructionTable<IW, H>,
        host: &mut H,
    ) -> IW::Output {
        From::from(self.run_plain(instruction_table, host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compare_cached_path(
        code: &[u8],
        gas: u64,
        initial_stack: usize,
        spec: SpecId,
        observe_fallback: bool,
    ) -> InterpreterAction {
        use crate::instructions::instruction_table;
        fn observer(ip: Ip, context: InstructionContext<'_, DummyHost, EthInterpreter>) -> Ip {
            assert_eq!(context.interpreter.gas.remaining(), 95);
            context.interpreter.gas.set_remaining(80);
            ip
        }
        let mut table = instruction_table::<EthInterpreter, DummyHost>();
        if observe_fallback {
            // ADDRESS is outside the canonical inline set, so this exercises
            // synchronization around an overridden fallback while caching is on.
            table[bytecode::opcode::ADDRESS as usize] = crate::Instruction::new(observer);
        }
        let mut result = None;
        for reservoir in [0, 97] {
            let make = || {
                let mut interpreter = Interpreter::<EthInterpreter>::new(
                    SharedMemory::new(),
                    ExtBytecode::new(Bytecode::new_raw(Bytes::copy_from_slice(code))),
                    InputsImpl::default(),
                    false,
                    spec,
                    gas,
                );
                interpreter.gas = Gas::new_with_regular_gas_and_reservoir(gas, reservoir);
                for i in 0..initial_stack {
                    assert!(interpreter.stack.push(primitives::U256::from(i)));
                }
                interpreter
            };
            let mut cached = make();
            let mut plain = make();
            let actual = cached.run_plain(&table, &mut DummyHost::default());
            let expected =
                plain.run_plain_inner::<DummyHost, false>(&table, &mut DummyHost::default());
            assert_eq!(actual, expected, "action and captured gas");
            assert_eq!(cached.gas, plain.gas, "all gas fields");
            assert_eq!(cached.stack, plain.stack, "stack contents and length");
            assert_eq!(cached.bytecode.pc(), plain.bytecode.pc());
            result = Some(actual);
        }
        result.unwrap()
    }

    #[test]
    fn cached_gas_fault_boundaries_match_uncached() {
        use bytecode::opcode::*;
        for (code, gas, stack, result) in [
            (
                vec![PUSH1, 1, PUSH1, 2, ADD, STOP],
                8,
                0,
                InstructionResult::OutOfGas,
            ),
            (
                vec![PUSH1, 1, POP, ADD, STOP],
                20,
                0,
                InstructionResult::StackUnderflow,
            ),
            (
                vec![PUSH1, 7, DUP1, STOP],
                20,
                1023,
                InstructionResult::StackOverflow,
            ),
            (
                vec![PUSH1, 7, DUP1, STOP],
                5,
                1023,
                InstructionResult::OutOfGas,
            ),
            (
                vec![PUSH1, 7, POP, DUP1, STOP],
                20,
                0,
                InstructionResult::StackOverflow,
            ),
        ] {
            let action = compare_cached_path(&code, gas, stack, SpecId::OSAKA, false);
            assert_eq!(action.instruction_result(), Some(result));
        }
    }

    #[test]
    fn cached_gas_activation_priority_matches_uncached() {
        use bytecode::opcode::*;
        for (gas, result) in [
            (20, InstructionResult::NotActivated),
            (7, InstructionResult::OutOfGas),
        ] {
            let action = compare_cached_path(
                &[PUSH1, 0, POP, SHL, STOP],
                gas,
                0,
                SpecId::BYZANTIUM,
                false,
            );
            assert_eq!(action.instruction_result(), Some(result));
        }
    }

    #[test]
    fn cached_gas_fallback_observes_and_reloads_budget() {
        use bytecode::opcode::*;
        let action = compare_cached_path(
            &[PUSH1, 1, POP, ADDRESS, PUSH1, 2, STOP],
            100,
            0,
            SpecId::OSAKA,
            true,
        );
        assert_eq!(action.instruction_result(), Some(InstructionResult::Stop));
        match action {
            InterpreterAction::Return(result) => assert_eq!(result.gas.remaining(), 77),
            _ => panic!("expected return"),
        }
    }

    #[test]
    fn cached_gas_return_boundary_matches_uncached() {
        use bytecode::opcode::*;
        let action =
            compare_cached_path(&[PUSH1, 0, PUSH1, 0, RETURN], 100, 0, SpecId::OSAKA, false);
        assert_eq!(action.instruction_result(), Some(InstructionResult::Return));
    }

    #[test]
    fn cached_gas_respects_canonical_table_override() {
        use bytecode::opcode::*;
        fn overridden_add(
            ip: Ip,
            context: InstructionContext<'_, DummyHost, EthInterpreter>,
        ) -> Ip {
            assert_eq!(context.interpreter.gas.remaining(), 94);
            context.interpreter.gas.set_remaining(50);
            ip
        }
        let mut table = crate::instructions::instruction_table::<EthInterpreter, DummyHost>();
        table[ADD as usize] = crate::Instruction::new(overridden_add);
        let mut interpreter = Interpreter::<EthInterpreter>::new(
            SharedMemory::new(),
            ExtBytecode::new(Bytecode::new_raw(Bytes::from_static(&[
                PUSH1, 1, PUSH1, 2, ADD, STOP,
            ]))),
            InputsImpl::default(),
            false,
            SpecId::OSAKA,
            100,
        );
        let action = interpreter.run_plain(&table, &mut DummyHost::default());
        assert_eq!(action.instruction_result(), Some(InstructionResult::Stop));
        assert_eq!(interpreter.gas.remaining(), 50);
        assert_eq!(interpreter.stack.len(), 2);
    }

    #[test]
    fn cached_gas_mixed_sequences_match_uncached() {
        use bytecode::opcode::*;
        let binary = [ADD, SUB, MUL, DIV, LT, GT, EQ, AND, OR, SHL, SHR];
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..64 {
            let mut code = Vec::new();
            for _ in 0..16 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                code.extend_from_slice(&[PUSH1, seed as u8, PUSH1, (seed >> 8) as u8]);
                code.push(binary[(seed as usize >> 16) % binary.len()]);
                code.extend_from_slice(&[DUP1, SWAP1, POP, NOT, ISZERO, POP, GAS, POP, JUMPDEST]);
            }
            code.push(STOP);
            let action = compare_cached_path(&code, 100_000, 0, SpecId::OSAKA, false);
            assert_eq!(action.instruction_result(), Some(InstructionResult::Stop));
        }
    }

    #[test]
    #[cfg(feature = "serde")]
    fn test_interpreter_serde() {
        use super::*;
        use bytecode::Bytecode;
        use primitives::Bytes;

        let bytecode = Bytecode::new_raw(Bytes::from(&[0x60, 0x00, 0x60, 0x00, 0x01][..]));
        let interpreter = Interpreter::<EthInterpreter>::new(
            SharedMemory::new(),
            ExtBytecode::new(bytecode),
            InputsImpl::default(),
            false,
            SpecId::default(),
            u64::MAX,
        );

        let serialized = serde_json::to_string_pretty(&interpreter).unwrap();
        let deserialized: Interpreter<EthInterpreter> = serde_json::from_str(&serialized).unwrap();

        assert_eq!(
            interpreter.bytecode.pc(),
            deserialized.bytecode.pc(),
            "Program counter should be preserved"
        );
    }
}

#[test]
fn test_mstore_big_offset_memory_oog() {
    use super::*;
    use crate::{host::DummyHost, instructions::instruction_table};
    use bytecode::Bytecode;
    use primitives::Bytes;

    let code = Bytes::from(
        &[
            0x60, 0x00, // PUSH1 0x00
            0x61, 0x27, 0x10, // PUSH2 0x2710  (10,000)
            0x52, // MSTORE
            0x00, // STOP
        ][..],
    );
    let bytecode = Bytecode::new_raw(code);

    let mut interpreter = Interpreter::<EthInterpreter>::new(
        SharedMemory::new(),
        ExtBytecode::new(bytecode),
        InputsImpl::default(),
        false,
        SpecId::default(),
        1000,
    );

    let table = instruction_table::<EthInterpreter, DummyHost>();
    let mut host = DummyHost::default();
    let action = interpreter.run_plain(&table, &mut host);

    assert!(action.is_return());
    assert_eq!(
        action.instruction_result(),
        Some(InstructionResult::MemoryOOG)
    );
}

#[test]
#[cfg(feature = "memory_limit")]
fn test_mstore_big_offset_memory_limit_oog() {
    use super::*;
    use crate::{host::DummyHost, instructions::instruction_table};
    use bytecode::Bytecode;
    use primitives::Bytes;

    let code = Bytes::from(
        &[
            0x60, 0x00, // PUSH1 0x00
            0x61, 0x27, 0x10, // PUSH2 0x2710  (10,000)
            0x52, // MSTORE
            0x00, // STOP
        ][..],
    );
    let bytecode = Bytecode::new_raw(code);

    let mut interpreter = Interpreter::<EthInterpreter>::new(
        SharedMemory::new_with_memory_limit(1000),
        ExtBytecode::new(bytecode),
        InputsImpl::default(),
        false,
        SpecId::default(),
        100000,
    );

    let table = instruction_table::<EthInterpreter, DummyHost>();
    let mut host = DummyHost::default();
    let action = interpreter.run_plain(&table, &mut host);

    assert!(action.is_return());
    assert_eq!(
        action.instruction_result(),
        Some(InstructionResult::MemoryLimitOOG)
    );
}
