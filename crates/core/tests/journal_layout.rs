use alloy_primitives::{Address, U256};
use reth_evm::revm::context_interface::journaled_state::entry::JournalEntry;

#[test]
fn journal_payloads_keep_word_alignment() -> Result<(), Box<dyn std::error::Error>> {
    let entries = [
        JournalEntry::AccountWarmed {
            address: Address::ZERO,
        },
        JournalEntry::StorageWarmed {
            address: Address::ZERO,
            key: U256::ZERO,
        },
        JournalEntry::StorageChanged {
            address: Address::ZERO,
            key: U256::ZERO,
            had_value: U256::ZERO,
        },
    ];
    for entry in &entries {
        let address = match entry {
            JournalEntry::AccountWarmed { address }
            | JournalEntry::StorageWarmed { address, .. }
            | JournalEntry::StorageChanged { address, .. } => address,
            _ => return Err("unexpected journal test variant".into()),
        };
        assert_eq!(
            core::ptr::from_ref(address).addr() % core::mem::align_of::<u64>(),
            0
        );
    }
    Ok(())
}
