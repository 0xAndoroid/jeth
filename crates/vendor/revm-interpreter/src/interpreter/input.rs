use crate::{interpreter_types::InputsTr, CallInput};
use primitives::{Address, U256};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Inputs for the interpreter that are used for execution of the call.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InputsImpl {
    /// Storage of this account address is being used.
    pub target_address: Address,
    /// Address of the bytecode that is being executed. This field is not used inside Interpreter but it is used
    /// by dependent projects that would need to know the address of the bytecode.
    pub bytecode_address: Option<Address>,
    /// Address of the caller of the call.
    pub caller_address: Address,
    /// Input data for the call.
    pub input: CallInput,
    /// Value of the call.
    pub call_value: U256,
}

impl InputsTr for InputsImpl {
    fn target_address(&self) -> Address {
        self.target_address
    }

    #[inline(always)]
    fn target_address_word(&self) -> U256 {
        super::words::address_word(&self.target_address)
    }

    fn caller_address(&self) -> Address {
        self.caller_address
    }

    #[inline(always)]
    fn caller_address_word(&self) -> U256 {
        super::words::address_word(&self.caller_address)
    }

    fn bytecode_address(&self) -> Option<&Address> {
        self.bytecode_address.as_ref()
    }

    fn input(&self) -> &CallInput {
        &self.input
    }

    fn call_value(&self) -> U256 {
        self.call_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_words_observe_current_fields() {
        let mut input = InputsImpl::default();
        for value in [0u8, 1, 0x80, 0xff] {
            input.target_address = Address::from([value; 20]);
            input.caller_address = Address::from([value ^ 0x55; 20]);
            let target: U256 = input.target_address().into_word().into();
            let caller: U256 = input.caller_address().into_word().into();
            assert_eq!(input.target_address_word(), target);
            assert_eq!(input.caller_address_word(), caller);
        }
    }
}
