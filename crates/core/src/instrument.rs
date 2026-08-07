//! Instrumented trie wrapper: cycle markers + keccak-counter checkpoints around
//! the witness reveal and post-state-root phases (guest builds only).
//!
//! jeth-core cannot depend on jolt-sdk (host builds), so the guest binary
//! provides two `extern "C"` hooks that forward to jolt's cycle tracking and
//! print the keccak counters.

use alloy_primitives::{Address, B256, U256};
use alloy_rpc_types_debug::ExecutionWitness;
use tries::{StatelessTrie, StatelessTrieError, WitnessDbError};

extern "C" {
    fn jeth_phase_start(ptr: *const u8, len: usize);
    fn jeth_phase_end(ptr: *const u8, len: usize);
}

fn phase_start(label: &'static str) {
    unsafe { jeth_phase_start(label.as_ptr(), label.len()) }
}
fn phase_end(label: &'static str) {
    unsafe { jeth_phase_end(label.as_ptr(), label.len()) }
}

/// Marker with a non-`'static` label (per-tx markers reuse a stack buffer; the
/// tracer copies the label at start and keys the active marker by pointer).
pub(crate) fn phase_start_dyn(label: &str) {
    unsafe { jeth_phase_start(label.as_ptr(), label.len()) }
}
pub(crate) fn phase_end_dyn(label: &str) {
    unsafe { jeth_phase_end(label.as_ptr(), label.len()) }
}

/// [`crate::zeth_trie::SparseState`] with phase hooks around reveal and root calc.
#[derive(Debug)]
pub struct InstrumentedTrie(crate::zeth_trie::SparseState);

impl InstrumentedTrie {
    /// [`crate::zeth_trie::SparseState::new_with_codes`] with reveal markers.
    pub fn new_with_codes(
        witness: &ExecutionWitness,
        pre_state_root: B256,
    ) -> Result<(Self, crate::validation::CodeMap), StatelessTrieError> {
        phase_start("witness_reveal");
        let result = crate::zeth_trie::SparseState::new_with_codes(witness, pre_state_root);
        phase_end("witness_reveal");
        result.map(|(inner, codes)| (Self(inner), codes))
    }
}

impl StatelessTrie for InstrumentedTrie {
    fn new(
        witness: &ExecutionWitness,
        pre_state_root: B256,
    ) -> Result<
        (
            Self,
            alloy_primitives::map::B256IndexMap<revm_bytecode::Bytecode>,
        ),
        StatelessTrieError,
    >
    where
        Self: Sized,
    {
        phase_start("witness_reveal");
        let result = crate::zeth_trie::SparseState::new(witness, pre_state_root);
        phase_end("witness_reveal");
        result.map(|(inner, bytecode)| (Self(inner), bytecode))
    }

    fn account(&self, address: Address) -> Result<Option<alloy_trie::TrieAccount>, WitnessDbError> {
        self.0.account(address)
    }

    fn storage(&self, address: Address, slot: U256) -> Result<U256, WitnessDbError> {
        self.0.storage(address, slot)
    }

    fn calculate_state_root(
        &mut self,
        state: reth_trie_common::HashedPostState,
    ) -> Result<B256, StatelessTrieError> {
        phase_start("post_root");
        let result = self.0.calculate_state_root(state);
        phase_end("post_root");
        result
    }
}
