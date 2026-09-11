//! Utility macros to help implementing opcode instruction functions.
//!
//! A failing check returns the null [`Ip`](crate::Ip) produced by the `Interpreter::halt*`
//! helpers, which stops the run loop. The `$ret` arms serve helper functions that report the
//! halt through their own return value instead.

/// Fails the instruction if the current call is static.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! require_non_staticcall {
    ($interpreter:expr) => {
        if $interpreter.runtime_flag.is_static() {
            return $interpreter.halt($crate::InstructionResult::StateChangeDuringStaticCall);
        }
    };
}

/// Check if the `SPEC` is enabled, and fail the instruction if it is not.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! check {
    ($interpreter:expr, $min:ident) => {
        if !$interpreter
            .runtime_flag
            .spec_id()
            .is_enabled_in(primitives::hardfork::SpecId::$min)
        {
            return $interpreter.halt_not_activated();
        }
    };
}

/// Records a state gas cost (EIP-8037) and fails the instruction if it would exceed the available gas.
/// State gas only deducts from `remaining` (not `regular_gas_remaining`).
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! state_gas {
    ($interpreter:expr, $gas:expr) => {{
        if !$interpreter.gas.record_state_cost($gas) {
            return $interpreter.halt_oog();
        }
    }};
    ($interpreter:expr, $gas:expr, $ret:expr) => {{
        if !$interpreter.gas.record_state_cost($gas) {
            let _ = $interpreter.halt_oog();
            return $ret;
        }
    }};
}

/// Records a `gas` cost and fails the instruction if it would exceed the available gas.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! gas {
    ($interpreter:expr, $gas:expr) => {
        if !$interpreter.gas.record_regular_cost($gas) {
            return $interpreter.halt_oog();
        }
    };
    ($interpreter:expr, $gas:expr, $ret:expr) => {
        if !$interpreter.gas.record_regular_cost($gas) {
            let _ = $interpreter.halt_oog();
            return $ret;
        }
    };
}

/// Charges the opcode's static gas ([`crate::instructions::static_gas`]) and fails the
/// instruction on out-of-gas. Every instruction runs this before any other check so
/// out-of-gas keeps priority over stack underflow and activation errors.
///
/// Spec-independent opcodes charge a compile-time constant; the repriced ones read the
/// spec at runtime.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! static_gas {
    ($interpreter:expr, $opcode:ident) => {{
        const OPCODE: u8 = $crate::bytecode::opcode::$opcode;
        if const { $crate::instructions::static_gas_is_spec_independent(OPCODE) } {
            if $interpreter.gas.record_static_cost::<{
                $crate::instructions::static_gas(
                    OPCODE,
                    $crate::primitives::hardfork::SpecId::FRONTIER,
                )
            }>() {
                return $interpreter.halt_oog();
            }
        } else {
            $crate::gas!(
                $interpreter,
                $crate::instructions::static_gas(
                    OPCODE,
                    $crate::interpreter_types::RuntimeFlag::spec_id(&$interpreter.runtime_flag)
                )
            )
        }
    }};
}

/// Loads account and account berlin gas cost accounting.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! berlin_load_account {
    ($context:expr, $address:expr, $load_code:expr) => {{
        let cold_load_gas = $context.host.gas_params().cold_account_additional_cost();
        let skip_cold_load = $context.interpreter.gas.remaining() < cold_load_gas;
        match $context
            .host
            .load_account_info_skip_cold_load($address, $load_code, skip_cold_load)
        {
            Ok(account) => {
                if account.is_cold {
                    $crate::gas!($context.interpreter, cold_load_gas);
                }
                account
            }
            Err(LoadError::ColdLoadSkipped) => return $context.interpreter.halt_oog(),
            Err(LoadError::DBError) => return $context.interpreter.halt_fatal(),
        }
    }};
}

/// Resizes the interpreter memory if necessary. Fails the instruction if the memory or gas limit
/// is exceeded.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! resize_memory {
    ($interpreter:expr, $gas_params:expr, $offset:expr, $len:expr) => {
        if let Err(result) = $crate::interpreter::resize_memory(
            &mut $interpreter.gas,
            &mut $interpreter.memory,
            $gas_params,
            $offset,
            $len,
        ) {
            return $interpreter.halt(result);
        }
    };
    ($interpreter:expr, $gas_params:expr, $offset:expr, $len:expr, $ret:expr) => {
        if let Err(result) = $crate::interpreter::resize_memory(
            &mut $interpreter.gas,
            &mut $interpreter.memory,
            $gas_params,
            $offset,
            $len,
        ) {
            let _ = $interpreter.halt(result);
            return $ret;
        }
    };
}

/// Pops n values from the stack. Fails the instruction if n values can't be popped.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! popn {
    ([ $($x:ident),* ],$interpreter:expr) => {
        let Some([$( $x ),*]) = $interpreter.stack.popn() else {
            return $interpreter.halt_underflow();
        };
    };
    ([ $($x:ident),* ],$interpreter:expr, $ret:expr) => {
        let Some([$( $x ),*]) = $interpreter.stack.popn() else {
            let _ = $interpreter.halt_underflow();
            return $ret;
        };
    };
}

#[doc(hidden)]
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! _count {
    (@count) => { 0 };
    (@count $head:tt $($tail:tt)*) => { 1 + _count!(@count $($tail)*) };
    ($($arg:tt)*) => { _count!(@count $($arg)*) };
}

/// Pops n values from the stack and returns the top value. Fails the instruction if n values can't be popped.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! popn_top {
    ([ $($x:ident),* ], $top:ident, $interpreter:expr) => {
        /*
        let Some(([$( $x ),*], $top)) = $interpreter.stack.popn_top() else {
            return $interpreter.halt($crate::InstructionResult::StackUnderflow);
        };
        */

        // Workaround for https://github.com/rust-lang/rust/issues/144329.
        if $interpreter.stack.len() < (1 + $crate::_count!($($x)*)) {
            return $interpreter.halt_underflow();
        }
        let ([$( $x ),*], $top) = unsafe { $interpreter.stack.popn_top().unwrap_unchecked() };
    };
}

/// Pushes a `B256` value onto the stack. Fails the instruction if the stack is full.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! push {
    ($interpreter:expr, $x:expr) => {
        if !($interpreter.stack.push($x)) {
            return $interpreter.halt_overflow();
        }
    };
}

/// Converts a `U256` value to a `u64`, saturating to `MAX` if the value is too large.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! as_u64_saturated {
    ($v:expr) => {
        u64::try_from($v).unwrap_or(u64::MAX)
    };
}

/// Converts a `U256` value to a `usize`, saturating to `MAX` if the value is too large.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! as_usize_saturated {
    ($v:expr) => {
        usize::try_from($v).unwrap_or(usize::MAX)
    };
}

/// Converts a `U256` value to a `isize`, saturating to `isize::MAX` if the value is too large.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! as_isize_saturated {
    ($v:expr) => {
        isize::try_from($v).unwrap_or(isize::MAX)
    };
}

/// Converts a `U256` value to a `usize`, failing the instruction if the value is too large.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! as_usize_or_fail {
    ($interpreter:expr, $v:expr) => {
        match $v.as_limbs() {
            x => {
                if (x[0] > usize::MAX as u64) | (x[1] != 0) | (x[2] != 0) | (x[3] != 0) {
                    return $interpreter.halt($crate::InstructionResult::InvalidOperandOOG);
                }
                x[0] as usize
            }
        }
    };
}

/// Converts a `U256` value to a `usize` and returns `ret`,
/// failing the instruction if the value is too large.
#[macro_export]
#[collapse_debuginfo(yes)]
macro_rules! as_usize_or_fail_ret {
    ($interpreter:expr, $v:expr, $ret:expr) => {
        match $v.as_limbs() {
            x => {
                if (x[0] > usize::MAX as u64) | (x[1] != 0) | (x[2] != 0) | (x[3] != 0) {
                    let _ = $interpreter.halt($crate::InstructionResult::InvalidOperandOOG);
                    return $ret;
                }
                x[0] as usize
            }
        }
    };
}
