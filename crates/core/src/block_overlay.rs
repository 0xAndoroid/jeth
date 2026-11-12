//! One block cache for database reads and committed transaction changes.
//!
//! revm still owns transaction rollback and warm/cold accounting. This layer
//! retains the block's original values and final values without constructing
//! intermediate transition maps or block revert records. Commits consume every
//! present slot: a retained journal's slot original is transaction-relative.

use alloy_primitives::{
    map::{hash_map::EntryRef, AddressMap, B256Map, Entry},
    Address, B256, U256,
};
use reth_evm::revm::database::{states::plain_account::StorageSlot, AccountStatus, BundleAccount};
use revm_bytecode::Bytecode;
use revm_database_interface::{Database, DatabaseCommit};
use revm_state::{Account, AccountInfo};

/// Skip net-zero changes, just as the bundle's empty-revert filter does.
pub(crate) fn is_changed(account: &BundleAccount) -> bool {
    account.is_info_changed()
        || (account.status.was_destroyed() && account.original_info.is_some())
        || account.storage.values().any(StorageSlot::is_changed)
}

#[derive(Debug)]
pub(crate) struct BlockOverlay<DB> {
    database: DB,
    pub(crate) accounts: AddressMap<BundleAccount>,
    contracts: B256Map<Bytecode>,
}

impl<DB: Database> BlockOverlay<DB> {
    pub(crate) fn new(database: DB, capacity: usize) -> Self {
        Self {
            database,
            accounts: AddressMap::with_capacity_and_hasher(capacity, Default::default()),
            contracts: B256Map::default(),
        }
    }

    fn load_account<'a>(
        accounts: &'a mut AddressMap<BundleAccount>,
        database: &mut DB,
        address: &Address,
    ) -> Result<&'a mut BundleAccount, DB::Error> {
        match accounts.entry_ref(address) {
            EntryRef::Occupied(entry) => Ok(entry.into_mut()),
            EntryRef::Vacant(entry) => {
                let info = database.basic(*address)?;
                let status = match &info {
                    None => AccountStatus::LoadedNotExisting,
                    Some(info) if info.is_empty() => AccountStatus::LoadedEmptyEIP161,
                    Some(_) => AccountStatus::Loaded,
                };
                Ok(entry.insert(BundleAccount::new(
                    info.clone(),
                    info,
                    Default::default(),
                    status,
                )))
            }
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "revm loads every account before committing its transaction changes"
    )]
    fn commit_account(&mut self, address: Address, account: Account) {
        if !account.is_touched() {
            return;
        }
        let cached = self
            .accounts
            .get_mut(&address)
            .expect("committed account must be loaded");
        if account.is_selfdestructed() {
            cached.status = cached.status.on_selfdestructed();
            cached.info = None;
            cached.storage.clear();
            return;
        }
        if account.is_created() {
            cached.status = cached.status.on_created();
            cached.storage.clear();
        } else if account.is_empty() {
            cached.status = cached.status.on_touched_empty_post_eip161();
            cached.info = None;
            cached.storage.clear();
            return;
        } else {
            cached.status = cached.status.on_changed(
                cached
                    .info
                    .as_ref()
                    .is_some_and(AccountInfo::has_no_code_and_nonce),
            );
        }
        cached.info = Some(account.info);
        for (key, slot) in account.storage {
            match cached.storage.entry(key) {
                Entry::Occupied(mut entry) => entry.get_mut().present_value = slot.present_value,
                Entry::Vacant(entry) => {
                    // Existing storage reads are already cached above. A
                    // vacant slot is known zero or belongs to a new account.
                    entry.insert(StorageSlot::new_changed(U256::ZERO, slot.present_value));
                }
            }
        }
    }
}

impl<DB: Database> Database for BlockOverlay<DB> {
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(
            Self::load_account(&mut self.accounts, &mut self.database, &address)?
                .info
                .clone(),
        )
    }

    fn code_by_hash(&mut self, hash: B256) -> Result<Bytecode, Self::Error> {
        match self.contracts.entry(hash) {
            Entry::Occupied(entry) => Ok(entry.get().clone()),
            Entry::Vacant(entry) => {
                let code = self.database.code_by_hash(hash)?;
                Ok(entry.insert(code).clone())
            }
        }
    }

    fn storage(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
        let account = Self::load_account(&mut self.accounts, &mut self.database, &address)?;
        let storage_known = account.status.is_storage_known();
        match account.storage.entry_ref(&key) {
            EntryRef::Occupied(entry) => Ok(entry.get().present_value),
            EntryRef::Vacant(_) if storage_known => Ok(U256::ZERO),
            EntryRef::Vacant(entry) => {
                let value = self.database.storage(address, key)?;
                entry.insert(StorageSlot::new(value));
                Ok(value)
            }
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.database.block_hash(number)
    }
}

impl<DB: Database> DatabaseCommit for BlockOverlay<DB> {
    fn commit(&mut self, changes: AddressMap<Account>) {
        for (address, account) in changes {
            self.commit_account(address, account);
        }
    }

    fn commit_iter(&mut self, changes: &mut dyn Iterator<Item = (Address, Account)>) {
        for (address, account) in changes {
            self.commit_account(address, account);
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "test database operations and loaded account assertions are infallible"
)]
mod tests {
    use super::*;
    use crate::keccak_memo::{hashed_post_state, AddressMemo, SlotMemo};
    use core::cell::RefCell;
    use reth_evm::revm::database::{states::bundle_state::BundleRetention, InMemoryDB, State};
    use reth_trie_common::{HashedPostState, KeccakKeyHasher};
    use revm_state::EvmStorageSlot;

    #[test]
    fn storage_reads_keep_originals_and_skip_known_empty_state() {
        let address = Address::from([7; 20]);
        let key = U256::from(1);
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            address,
            AccountInfo {
                nonce: 1,
                ..Default::default()
            },
        );
        db.insert_account_storage(address, key, U256::from(3))
            .unwrap();
        let mut overlay = BlockOverlay::new(db, 1);
        assert_eq!(overlay.storage(address, key).unwrap(), U256::from(3));
        overlay
            .database
            .insert_account_storage(address, key, U256::from(99))
            .unwrap();
        assert_eq!(overlay.storage(address, key).unwrap(), U256::from(3));
        let cached = overlay.accounts.get_mut(&address).unwrap();
        let slot = cached.storage.get_mut(&key).unwrap();
        assert_eq!(slot.previous_or_original_value, U256::from(3));
        slot.present_value = U256::from(5);
        assert_eq!(overlay.storage(address, key).unwrap(), U256::from(5));
        let cached = overlay.accounts.get_mut(&address).unwrap();
        assert_eq!(
            cached.storage[&key].previous_or_original_value,
            U256::from(3)
        );
        cached.status = cached.status.on_selfdestructed();
        cached.storage.clear();
        assert_eq!(overlay.storage(address, key).unwrap(), U256::ZERO);
        assert!(overlay.accounts[&address].storage.is_empty());
    }

    #[test]
    fn commits_match_state_across_restore_destroy_and_recreate() {
        let address = Address::from([7; 20]);
        let absent = Address::from([8; 20]);
        let unchanged = Address::from([9; 20]);
        let info = AccountInfo {
            balance: U256::from(10),
            nonce: 1,
            ..Default::default()
        };
        let mut db = InMemoryDB::default();
        db.insert_account_info(address, info.clone());
        db.insert_account_info(unchanged, info);
        db.insert_account_storage(address, U256::from(1), U256::from(3))
            .unwrap();
        let mut overlay = BlockOverlay::new(db.clone(), 2);
        let mut state = State::builder()
            .with_database(db)
            .with_bundle_update()
            .build();
        for address in [address, absent, unchanged] {
            assert_eq!(
                overlay.basic(address).unwrap(),
                state.basic(address).unwrap()
            );
        }
        for (step, value) in [7, 3, 0, 9, 0].into_iter().enumerate() {
            let previous = overlay.storage(address, U256::from(1)).unwrap();
            assert_eq!(previous, state.storage(address, U256::from(1)).unwrap());
            let mut account = Account::from(overlay.basic(address).unwrap().unwrap_or_default());
            account.mark_touch();
            match step {
                2 => account.mark_selfdestruct(),
                3 => {
                    account.mark_created();
                    account.info.nonce = 1;
                }
                _ => {}
            }
            account.storage.insert(
                U256::from(1),
                EvmStorageSlot::new_changed(previous, U256::from(value), step),
            );
            let mut changes = AddressMap::default();
            changes.insert(address, account);
            let mut empty = Account::default();
            empty.mark_touch();
            changes.insert(absent, empty);
            let mut touched = Account::from(overlay.basic(unchanged).unwrap().unwrap());
            touched.mark_touch();
            changes.insert(unchanged, touched);
            overlay.commit(changes.clone());
            state.commit(changes);
            assert_eq!(
                overlay.basic(address).unwrap(),
                state.basic(address).unwrap()
            );
            assert_eq!(
                overlay.storage(address, U256::from(1)).unwrap(),
                state.storage(address, U256::from(1)).unwrap()
            );
            assert_eq!(
                overlay.storage(address, U256::from(2)).unwrap(),
                state.storage(address, U256::from(2)).unwrap()
            );
        }
        state.merge_transitions(BundleRetention::PlainState);
        let expected =
            HashedPostState::from_bundle_state::<KeccakKeyHasher>(&state.take_bundle().state);
        let actual = hashed_post_state(
            overlay
                .accounts
                .iter()
                .filter(|(_, account)| is_changed(account)),
            &RefCell::new(AddressMemo::with_capacity(0)),
            &RefCell::new(SlotMemo::with_capacity(0)),
        );
        assert_eq!(actual, expected);
        assert!(actual.storages[&alloy_primitives::keccak256(address)].wiped);
        assert!(!actual
            .accounts
            .contains_key(&alloy_primitives::keccak256(absent)));
    }
    #[test]
    fn retained_journal_matches_state_after_no_op_write() {
        use alloy_primitives::{Bytes, TxKind};
        use reth_evm::revm::context::{BlockEnv, CfgEnv, TxEnv};
        use reth_evm::{EthEvmFactory, Evm, EvmEnv, EvmFactory};
        let caller = Address::from([0x11; 20]);
        let target = Address::from([0x22; 20]);
        let reverting = Address::from([0x33; 20]);
        let mut db = InMemoryDB::default();
        db.insert_account_info(
            caller,
            AccountInfo {
                balance: U256::MAX,
                ..Default::default()
            },
        );
        for (address, bytes) in [
            (target, &[0x60, 0, 0x35, 0x60, 0, 0x55, 0][..]),
            (
                reverting,
                &[0x60, 0, 0x35, 0x60, 0, 0x55, 0x60, 0, 0x60, 0, 0xfd][..],
            ),
        ] {
            let code = Bytecode::new_raw(Bytes::copy_from_slice(bytes));
            db.insert_account_info(
                address,
                AccountInfo {
                    nonce: 1,
                    code_hash: code.hash_slow(),
                    code: Some(code),
                    ..Default::default()
                },
            );
        }
        let env = EvmEnv {
            block_env: BlockEnv::default(),
            cfg_env: CfgEnv::default(),
        };
        let mut normal = EthEvmFactory::default().create_evm(
            State::builder()
                .with_database(db.clone())
                .with_bundle_update()
                .build(),
            env.clone(),
        );
        let mut retained = EthEvmFactory::default().create_evm(BlockOverlay::new(db, 3), env);
        retained.retain_transactions();
        for (nonce, (address, value)) in [(target, 1), (reverting, 2), (target, 3), (target, 3)]
            .into_iter()
            .enumerate()
        {
            let tx = TxEnv {
                caller,
                kind: TxKind::Call(address),
                nonce: nonce as u64,
                gas_limit: 100_000,
                data: Bytes::from(U256::from(value).to_be_bytes::<32>().to_vec()),
                ..Default::default()
            };
            let expected = normal.transact_raw(tx.clone()).unwrap();
            let actual = retained.transact_raw(tx).unwrap();
            assert_eq!(actual.result, expected.result);
            assert!(actual.state.is_empty());
            normal.db_mut().commit(expected.state);
        }
        let changes = retained.take_retained_state();
        retained.db_mut().commit(changes);
        for address in [caller, target, reverting, Address::ZERO] {
            assert_eq!(
                retained.db_mut().basic(address).unwrap(),
                normal.db_mut().basic(address).unwrap()
            );
            assert_eq!(
                retained.db_mut().storage(address, U256::ZERO).unwrap(),
                normal.db_mut().storage(address, U256::ZERO).unwrap()
            );
        }
        normal
            .db_mut()
            .merge_transitions(BundleRetention::PlainState);
        let expected = HashedPostState::from_bundle_state::<KeccakKeyHasher>(
            &normal.db_mut().take_bundle().state,
        );
        let actual = hashed_post_state(
            retained
                .db()
                .accounts
                .iter()
                .filter(|(_, account)| is_changed(account)),
            &RefCell::new(AddressMemo::with_capacity(0)),
            &RefCell::new(SlotMemo::with_capacity(0)),
        );
        assert_eq!(actual, expected);
    }
}
