//! Extract final values without constructing a block rollback bundle.
use reth_evm::revm::database::{BundleAccount, TransitionAccount};

pub(crate) fn final_account(transition: TransitionAccount) -> Option<BundleAccount> {
    // Preserve the removal of unchanged accounts. Sending them through the
    // trie would rebuild paths that the ordinary bundle leaves untouched.
    let unchanged = if transition.status.was_destroyed() {
        transition.info.is_none() && transition.previous_info.is_none()
    } else {
        transition.info == transition.previous_info
            && !transition.storage.values().any(|slot| slot.is_changed())
    };
    if unchanged {
        return None;
    }
    Some(BundleAccount {
        info: transition.info,
        original_info: transition.previous_info,
        storage: transition.storage,
        status: transition.status,
    })
}

#[cfg(test)]
mod tests {
    use super::final_account;
    use reth_evm::revm::database::primitives::{Address, U256};
    use reth_evm::revm::database::state::{Account, AccountInfo, EvmStorageSlot};
    use reth_evm::revm::database::states::bundle_state::BundleRetention;
    use reth_evm::revm::database::{BundleState, CacheState, TransitionState};

    #[test]
    fn matches_bundle_after_transaction_sequences() {
        for seed in 1..=512u64 {
            let mut rng = seed;
            let mut next = || {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                rng
            };
            let mut cache = CacheState::default();
            for i in 0..8u8 {
                let address = Address::repeat_byte(i);
                match i.cmp(&4) {
                    core::cmp::Ordering::Less => {
                        cache.insert_account(
                            address,
                            AccountInfo {
                                nonce: 1,
                                balance: U256::from(100),
                                ..Default::default()
                            },
                        );
                    }
                    core::cmp::Ordering::Equal => {
                        cache.insert_account(address, AccountInfo::default());
                    }
                    core::cmp::Ordering::Greater => {
                        cache.insert_not_existing(address);
                    }
                }
            }
            let mut transitions = TransitionState::default();
            for tx in 0..64 {
                let address = Address::repeat_byte((next() % 8) as u8);
                let cached = &cache.accounts[&address];
                let mut account = Account::from(cached.account_info().unwrap_or_default());
                let action = next() % 7;
                match action {
                    0 => { /* touched but unchanged */ }
                    1 => {
                        account.info.balance = U256::from(100 * (next() % 2));
                    }
                    2 => {
                        account.mark_selfdestruct();
                    }
                    3 if cached.account.is_none() => {
                        account.info.nonce = 1;
                        account.mark_created();
                    }
                    _ => {
                        account.info.nonce = account.info.nonce.max(1);
                        let key = U256::from(next() % 8);
                        let old = cached.storage_slot(key).unwrap_or_default();
                        let new = U256::from(next() % 4);
                        account
                            .storage
                            .insert(key, EvmStorageSlot::new_changed(old, new, tx));
                    }
                }
                account.mark_touch();
                transitions.add_transitions(cache.apply_evm_state([(address, account)], |_, _| {}));
            }
            let mut reference = BundleState::default();
            reference.apply_transitions_and_create_reverts(
                transitions.clone(),
                BundleRetention::Reverts,
            );
            for (address, transition) in transitions.transitions {
                assert_eq!(
                    reference.state.get(&address),
                    final_account(transition).as_ref(),
                    "seed {seed}, address {address}"
                );
            }
        }
    }
}
