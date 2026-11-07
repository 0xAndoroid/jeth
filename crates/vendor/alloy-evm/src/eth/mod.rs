//! Ethereum EVM implementation.

pub use env::NextEvmEnvAttributes;

use crate::{env::EvmEnv, evm::EvmFactory, precompiles::PrecompilesMap, Database, Evm};
use alloy_primitives::{Address, Bytes};
use core::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use revm::{
    context::{BlockEnv, CfgEnv, Evm as RevmEvm, TxEnv},
    context_interface::result::{EVMError, HaltReason, ResultAndState},
    handler::{instructions::EthInstructions, EthFrame, EthPrecompiles, PrecompileProvider},
    inspector::NoOpInspector,
    interpreter::{interpreter::EthInterpreter, InterpreterResult},
    precompile::{PrecompileSpecId, Precompiles},
    primitives::hardfork::SpecId,
    Context, ExecuteEvm, InspectEvm, Inspector, MainBuilder, MainContext, SystemCallEvm,
};

mod block;
pub use block::*;

pub mod dao_fork;
pub mod eip6110;
pub mod receipt_builder;
pub mod spec;

mod env;
pub(crate) mod spec_id;

/// The Ethereum EVM context type.
pub type EthEvmContext<DB> = Context<BlockEnv, TxEnv, CfgEnv, DB>;

/// Helper builder to construct `EthEvm` instances in a unified way.
#[derive(Debug)]
pub struct EthEvmBuilder<DB: Database, I = NoOpInspector> {
    db: DB,
    block_env: BlockEnv,
    cfg_env: CfgEnv,
    inspector: I,
    inspect: bool,
    precompiles: Option<PrecompilesMap>,
}

impl<DB: Database> EthEvmBuilder<DB, NoOpInspector> {
    /// Creates a builder from the provided `EvmEnv` and database.
    pub fn new(db: DB, env: EvmEnv) -> Self {
        Self {
            db,
            block_env: env.block_env,
            cfg_env: env.cfg_env,
            inspector: NoOpInspector {},
            inspect: false,
            precompiles: None,
        }
    }
}

impl<DB: Database, I> EthEvmBuilder<DB, I> {
    /// Sets a custom inspector
    pub fn inspector<J>(self, inspector: J) -> EthEvmBuilder<DB, J> {
        EthEvmBuilder {
            db: self.db,
            block_env: self.block_env,
            cfg_env: self.cfg_env,
            inspector,
            inspect: self.inspect,
            precompiles: self.precompiles,
        }
    }

    /// Sets a custom inspector and enables invoking it during transaction execution.
    pub fn activate_inspector<J>(self, inspector: J) -> EthEvmBuilder<DB, J> {
        self.inspector(inspector).inspect()
    }

    /// Sets whether to invoke the inspector during transaction execution.
    pub const fn set_inspect(mut self, inspect: bool) -> Self {
        self.inspect = inspect;
        self
    }

    /// Enables invoking the inspector during transaction execution.
    pub const fn inspect(self) -> Self {
        self.set_inspect(true)
    }

    /// Overrides the precompiles map. If not provided, it will be derived from the `SpecId` in
    /// `CfgEnv`.
    pub fn precompiles(mut self, precompiles: PrecompilesMap) -> Self {
        self.precompiles = Some(precompiles);
        self
    }

    /// Builds the `EthEvm` instance.
    pub fn build(self) -> EthEvm<DB, I, PrecompilesMap>
    where
        I: Inspector<EthEvmContext<DB>>,
    {
        let precompiles = match self.precompiles {
            Some(p) => p,
            None => PrecompilesMap::from_static(Precompiles::new(PrecompileSpecId::from_spec_id(
                self.cfg_env.spec,
            ))),
        };

        let inner = Context::mainnet()
            .with_block(self.block_env)
            .with_cfg(self.cfg_env)
            .with_db(self.db)
            .build_mainnet_with_inspector(self.inspector)
            .with_precompiles(precompiles);

        EthEvm {
            inner,
            inspect: self.inspect,
            retain_journal: false,
        }
    }
}

/// Ethereum EVM implementation.
///
/// This is a wrapper type around the `revm` ethereum evm with optional [`Inspector`] (tracing)
/// support. [`Inspector`] support is configurable at runtime because it's part of the underlying
/// [`RevmEvm`] type.
#[expect(missing_debug_implementations)]
pub struct EthEvm<DB: Database, I, PRECOMPILE = EthPrecompiles> {
    inner: RevmEvm<
        EthEvmContext<DB>,
        I,
        EthInstructions<EthInterpreter, EthEvmContext<DB>>,
        PRECOMPILE,
        EthFrame,
    >,
    inspect: bool,
    retain_journal: bool,
}

impl<DB: Database, I, PRECOMPILE> EthEvm<DB, I, PRECOMPILE> {
    /// Creates a new Ethereum EVM instance.
    ///
    /// The `inspect` argument determines whether the configured [`Inspector`] of the given
    /// [`RevmEvm`] should be invoked on [`Evm::transact`].
    pub const fn new(
        evm: RevmEvm<
            EthEvmContext<DB>,
            I,
            EthInstructions<EthInterpreter, EthEvmContext<DB>>,
            PRECOMPILE,
            EthFrame,
        >,
        inspect: bool,
    ) -> Self {
        Self {
            inner: evm,
            inspect,
            retain_journal: false,
        }
    }

    /// Retain transaction changes in revm's journal until the explicit flush.
    ///
    /// This mode returns empty per-transaction state maps. It is only suitable
    /// when neither receipt construction nor state hooks consume those maps.
    /// Call `take_retained_state` and apply its changes before accessing the database directly
    /// or applying post-block changes. Inspector execution keeps normal behavior.
    pub const fn retain_transactions(&mut self) {
        self.retain_journal = true;
    }

    /// Take retained changes and restore ordinary transaction finalization.
    ///
    /// Slot originals describe the last transaction that accessed the slot.
    /// The caller must preserve block originals separately or commit all present
    /// slot values. Passing this directly to a change-filtering State database
    /// can drop a write followed by a later no-op access.
    pub fn take_retained_state(&mut self) -> revm::state::EvmState {
        self.retain_journal = false;
        self.inner.ctx.journaled_state.inner.finalize()
    }

    /// Consumes self and return the inner EVM instance.
    pub fn into_inner(
        self,
    ) -> RevmEvm<
        EthEvmContext<DB>,
        I,
        EthInstructions<EthInterpreter, EthEvmContext<DB>>,
        PRECOMPILE,
        EthFrame,
    > {
        self.inner
    }

    /// Provides a reference to the EVM context.
    pub const fn ctx(&self) -> &EthEvmContext<DB> {
        &self.inner.ctx
    }

    /// Provides a mutable reference to the EVM context.
    pub const fn ctx_mut(&mut self) -> &mut EthEvmContext<DB> {
        &mut self.inner.ctx
    }
}

impl<DB: Database, I, PRECOMPILE> Deref for EthEvm<DB, I, PRECOMPILE> {
    type Target = EthEvmContext<DB>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.ctx()
    }
}

impl<DB: Database, I, PRECOMPILE> DerefMut for EthEvm<DB, I, PRECOMPILE> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.ctx_mut()
    }
}

impl<DB, I, PRECOMPILE> Evm for EthEvm<DB, I, PRECOMPILE>
where
    DB: Database,
    I: Inspector<EthEvmContext<DB>>,
    PRECOMPILE: PrecompileProvider<EthEvmContext<DB>, Output = InterpreterResult>,
{
    type DB = DB;
    type Tx = TxEnv;
    type Error = EVMError<DB::Error>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PRECOMPILE;
    type Inspector = I;

    fn block(&self) -> &BlockEnv {
        &self.block
    }

    fn cfg_env(&self) -> &CfgEnv<Self::Spec> {
        &self.cfg
    }

    fn chain_id(&self) -> u64 {
        self.cfg.chain_id
    }

    fn transact_raw(
        &mut self,
        tx: Self::Tx,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        if self.inspect {
            self.inner.inspect_tx(tx)
        } else if self.retain_journal {
            self.inner
                .transact_one(tx)
                .map(|result| ResultAndState::new(result, Default::default()))
        } else {
            self.inner.transact(tx)
        }
    }

    fn transact_system_call(
        &mut self,
        caller: Address,
        contract: Address,
        data: Bytes,
    ) -> Result<ResultAndState<Self::HaltReason>, Self::Error> {
        self.inner.system_call_with_caller(caller, contract, data)
    }

    fn finish(self) -> (Self::DB, EvmEnv<Self::Spec>) {
        let Context {
            block: block_env,
            cfg: cfg_env,
            journaled_state,
            ..
        } = self.inner.ctx;

        (journaled_state.database, EvmEnv { block_env, cfg_env })
    }

    fn set_inspector_enabled(&mut self, enabled: bool) {
        self.inspect = enabled;
    }

    fn components(&self) -> (&Self::DB, &Self::Inspector, &Self::Precompiles) {
        (
            &self.inner.ctx.journaled_state.database,
            &self.inner.inspector,
            &self.inner.precompiles,
        )
    }

    fn components_mut(&mut self) -> (&mut Self::DB, &mut Self::Inspector, &mut Self::Precompiles) {
        (
            &mut self.inner.ctx.journaled_state.database,
            &mut self.inner.inspector,
            &mut self.inner.precompiles,
        )
    }
}

/// Factory producing [`EthEvm`].
#[derive(Debug, Default, Clone, Copy)]
#[non_exhaustive]
pub struct EthEvmFactory;

impl EvmFactory for EthEvmFactory {
    type Evm<DB: Database, I: Inspector<EthEvmContext<DB>>> = EthEvm<DB, I, Self::Precompiles>;
    type Context<DB: Database> = Context<BlockEnv, TxEnv, CfgEnv, DB>;
    type Tx = TxEnv;
    type Error<DBError: core::error::Error + Send + Sync + 'static> = EVMError<DBError>;
    type HaltReason = HaltReason;
    type Spec = SpecId;
    type BlockEnv = BlockEnv;
    type Precompiles = PrecompilesMap;

    fn create_evm<DB: Database>(&self, db: DB, input: EvmEnv) -> Self::Evm<DB, NoOpInspector> {
        EthEvmBuilder::new(db, input).build()
    }

    fn create_evm_with_inspector<DB: Database, I: Inspector<Self::Context<DB>>>(
        &self,
        db: DB,
        input: EvmEnv,
        inspector: I,
    ) -> Self::Evm<DB, I> {
        EthEvmBuilder::new(db, input)
            .activate_inspector(inspector)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use revm::{database_interface::EmptyDB, primitives::hardfork::SpecId};

    #[test]
    fn retained_transactions_match_separate_commits() {
        use alloy_primitives::{Bytes, TxKind, U256};
        use revm::{
            database::InMemoryDB,
            database_interface::DatabaseCommit,
            state::{AccountInfo, Bytecode},
        };
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
        // SSTORE(0, CALLDATALOAD(0)), then STOP or REVERT.
        for (address, code) in [
            (target, &[0x60, 0, 0x35, 0x60, 0, 0x55, 0][..]),
            (
                reverting,
                &[0x60, 0, 0x35, 0x60, 0, 0x55, 0x60, 0, 0x60, 0, 0xfd][..],
            ),
        ] {
            let code = Bytecode::new_raw(Bytes::copy_from_slice(code));
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
        let mut normal = EthEvmFactory.create_evm(db.clone(), env.clone());
        let mut retained = EthEvmFactory.create_evm(db, env);
        retained.retain_transactions();
        for (nonce, address) in [target, reverting, target].into_iter().enumerate() {
            let tx = TxEnv {
                caller,
                kind: TxKind::Call(address),
                nonce: nonce as u64,
                gas_limit: 100_000,
                data: Bytes::from(U256::from(nonce + 1).to_be_bytes::<32>().to_vec()),
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
        use revm::database_interface::Database as _;
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
    }

    #[test]
    fn test_precompiles_with_correct_spec() {
        // create tests where precompile should be available for later specs but not earlier ones
        let specs_to_test = [
            // MODEXP (0x05) was added in Byzantium, should not exist in Frontier
            (
                address!("0x0000000000000000000000000000000000000005"),
                SpecId::FRONTIER,  // Early spec - should NOT have this precompile
                SpecId::BYZANTIUM, // Later spec - should have this precompile
                "MODEXP",
            ),
            // BLAKE2F (0x09) was added in Istanbul, should not exist in Byzantium
            (
                address!("0x0000000000000000000000000000000000000009"),
                SpecId::BYZANTIUM, // Early spec - should NOT have this precompile
                SpecId::ISTANBUL,  // Later spec - should have this precompile
                "BLAKE2F",
            ),
        ];

        for (precompile_addr, early_spec, later_spec, name) in specs_to_test {
            let mut early_cfg_env = CfgEnv::default();
            early_cfg_env.spec = early_spec;
            early_cfg_env.chain_id = 1;

            let early_env = EvmEnv {
                block_env: BlockEnv::default(),
                cfg_env: early_cfg_env,
            };
            let factory = EthEvmFactory;
            let mut early_evm = factory.create_evm(EmptyDB::default(), early_env);

            // precompile should NOT be available in early spec
            assert!(
                early_evm.precompiles_mut().get(&precompile_addr).is_none(),
                "{name} precompile at {precompile_addr:?} should NOT be available for early spec {early_spec:?}"
            );

            let mut later_cfg_env = CfgEnv::default();
            later_cfg_env.spec = later_spec;
            later_cfg_env.chain_id = 1;

            let later_env = EvmEnv {
                block_env: BlockEnv::default(),
                cfg_env: later_cfg_env,
            };
            let mut later_evm = factory.create_evm(EmptyDB::default(), later_env);

            // precompile should be available in later spec
            assert!(
                later_evm.precompiles_mut().get(&precompile_addr).is_some(),
                "{name} precompile at {precompile_addr:?} should be available for later spec {later_spec:?}"
            );
        }
    }
}
