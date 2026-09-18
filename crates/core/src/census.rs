//! `jeth touches`: native state-touch census (host-only, `census` feature).
//!
//! Runs the same validation as [`crate::validation::validate_recovered_pertx`]
//! (revm `State` over the witness trie, one `commit` per transaction) with
//!
//! 1. a counting wrapper around [`WitnessDatabase`] — the real cold reads:
//!    `basic` / `storage` / `code_by_hash` calls that fall through revm's
//!    `State` cache to the trie walk or the code map;
//! 2. the per-transaction `EvmState` the journal hands back: every account and
//!    slot revm re-loaded from `State` in that transaction (journal misses);
//! 3. an inspector counting the state-touching opcodes and the code hash of
//!    every frame.
//!
//! The proven code path is untouched: this module is never built into the
//! guest and shares the validation prologue/epilogue with the vendored loop.

use alloc::{rc::Rc, string::ToString, sync::Arc, vec::Vec};
use core::cell::{Cell, RefCell};

use alloy_consensus::{BlockHeader, Header};
use alloy_primitives::{
    keccak256,
    map::{AddressMap, B256Map, HashMap},
    Address, B256, U256,
};
use reth_ethereum_consensus::validate_block_post_execution;
use reth_ethereum_primitives::Block;
use reth_evm::{
    block::TxResult,
    execute::BlockExecutor,
    revm::{
        database::{states::bundle_state::BundleRetention, State},
        interpreter::{
            interpreter::EthInterpreter,
            interpreter_types::{InputsTr, Jumps},
            Interpreter,
        },
        Inspector,
    },
    ConfigureEvm,
};
use reth_primitives_traits::{RecoveredBlock, SealedHeader};
use revm_bytecode::{opcode, Bytecode};
use revm_database_interface::Database;
use revm_state::AccountInfo;
use stateless::{validation::StatelessValidationError, ExecutionWitness, StatelessTrie};
use tries::WitnessDbError;

use crate::validation::{
    compute_ancestor_hashes, receipt_root_bloom, validate_block_consensus, WitnessDatabase,
    BLOCKHASH_ANCESTOR_LIMIT,
};

/// Accesses to one key and the number of distinct transactions making them.
#[derive(Clone, Copy, Debug)]
pub struct Touch {
    pub accesses: u64,
    pub txs: u64,
    last_tx: usize,
}

impl Default for Touch {
    fn default() -> Self {
        Self {
            accesses: 0,
            txs: 0,
            last_tx: usize::MAX,
        }
    }
}

impl Touch {
    fn hit(&mut self, tx: usize) {
        self.accesses += 1;
        if self.last_tx != tx {
            self.last_tx = tx;
            self.txs += 1;
        }
    }
}

/// Calls that reached the witness database (revm's `State` cache missed).
#[derive(Clone, Copy, Debug, Default)]
pub struct DbCounts {
    pub basic: u64,
    pub basic_none: u64,
    pub storage: u64,
    pub storage_zero: u64,
    pub code_by_hash: u64,
    pub code_from_library: u64,
    pub block_hash: u64,
}

/// State-touching opcode executions.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpCounts {
    pub steps: u64,
    pub sload: u64,
    pub sstore: u64,
    pub balance: u64,
    pub selfbalance: u64,
    pub extcodesize: u64,
    pub extcodehash: u64,
    pub extcodecopy: u64,
    pub call: u64,
    pub callcode: u64,
    pub delegatecall: u64,
    pub staticcall: u64,
    pub create: u64,
    pub create2: u64,
}

/// Per-key-class summary: journal loads (one per transaction touching the
/// key), keys touched by two or more transactions, and opcode accesses.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeyStats {
    /// Distinct keys loaded during execution.
    pub distinct: u64,
    /// Sum over transactions of distinct keys loaded in that transaction
    /// (= `State::basic` / `State::storage` calls the journal made).
    pub tx_loads: u64,
    /// Keys loaded by at least two transactions.
    pub repeated: u64,
    /// `tx_loads` restricted to repeated keys.
    pub repeated_tx_loads: u64,
    /// Opcode accesses naming the key.
    pub op_accesses: u64,
    /// `op_accesses` restricted to repeated keys.
    pub repeated_op_accesses: u64,
    /// Keys whose value changed in some transaction (slots only).
    pub written: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CodeStats {
    /// Interpreter frames started (calls into non-empty code + initcode).
    pub frames: u64,
    pub initcode_frames: u64,
    pub distinct_hashes: u64,
    pub hashes_in_2plus_txs: u64,
    pub frames_on_repeated: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct HotAccount {
    pub address: Address,
    pub txs: u64,
    pub slots_loaded: u64,
    pub slot_ops: u64,
    pub address_ops: u64,
}

#[derive(Clone, Debug)]
pub struct CensusReport {
    pub block: u64,
    pub block_hash: B256,
    pub gas_used: u64,
    pub txs: usize,
    pub witness_nodes: usize,
    pub witness_codes: usize,
    pub ops: OpCounts,
    pub db: DbCounts,
    pub accounts: KeyStats,
    pub slots: KeyStats,
    pub codes: CodeStats,
    pub hottest: Vec<HotAccount>,
    /// Transactions touching at least one of `hottest`.
    pub hottest_union_txs: u64,
}

struct CountingDb<'a> {
    inner: WitnessDatabase<'a, crate::Trie>,
    counts: Rc<RefCell<DbCounts>>,
}

impl core::fmt::Debug for CountingDb<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "CountingDb({:?})", self.counts.borrow())
    }
}

impl Database for CountingDb<'_> {
    type Error = WitnessDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let info = self.inner.basic(address)?;
        let mut counts = self.counts.borrow_mut();
        counts.basic += 1;
        counts.basic_none += info.is_none() as u64;
        Ok(info)
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        let value = self.inner.storage(address, slot)?;
        let mut counts = self.counts.borrow_mut();
        counts.storage += 1;
        counts.storage_zero += value.is_zero() as u64;
        Ok(value)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        let code = self.inner.code_by_hash(code_hash)?;
        let mut counts = self.counts.borrow_mut();
        counts.code_by_hash += 1;
        counts.code_from_library += crate::code_library::lookup(&code_hash).is_some() as u64;
        Ok(code)
    }

    fn block_hash(&mut self, block_number: u64) -> Result<B256, Self::Error> {
        self.counts.borrow_mut().block_hash += 1;
        self.inner.block_hash(block_number)
    }
}

/// Opcode census: state-touching instructions keyed by the state they name.
struct Census {
    tx: Rc<Cell<usize>>,
    ops: OpCounts,
    /// SLOAD/SSTORE per (executing contract, slot).
    slot_ops: HashMap<(Address, U256), Touch>,
    /// BALANCE/EXTCODE*/SELFBALANCE/CALL-family per named address.
    address_ops: AddressMap<Touch>,
    code_frames: B256Map<Touch>,
    initcode_frames: u64,
}

impl Census {
    fn new(tx: Rc<Cell<usize>>) -> Self {
        Self {
            tx,
            ops: OpCounts::default(),
            slot_ops: HashMap::default(),
            address_ops: AddressMap::default(),
            code_frames: B256Map::default(),
            initcode_frames: 0,
        }
    }
}

impl<CTX> Inspector<CTX, EthInterpreter> for Census {
    fn initialize_interp(&mut self, interp: &mut Interpreter<EthInterpreter>, _ctx: &mut CTX) {
        let tx = self.tx.get();
        match interp.bytecode.hash() {
            Some(hash) => self.code_frames.entry(hash).or_default().hit(tx),
            None => self.initcode_frames += 1,
        }
    }

    fn step(&mut self, interp: &mut Interpreter<EthInterpreter>, _ctx: &mut CTX) {
        self.ops.steps += 1;
        let tx = self.tx.get();
        let stack = interp.stack.data();
        let from_top = |n: usize| stack.len().checked_sub(1 + n).map(|i| stack[i]);
        let op = interp.bytecode.opcode();
        let named = match op {
            opcode::SLOAD | opcode::SSTORE => {
                if op == opcode::SLOAD {
                    self.ops.sload += 1;
                } else {
                    self.ops.sstore += 1;
                }
                let target = interp.input.target_address();
                if let Some(slot) = from_top(0) {
                    self.slot_ops.entry((target, slot)).or_default().hit(tx);
                }
                Some(target)
            }
            opcode::BALANCE => {
                self.ops.balance += 1;
                from_top(0).map(word_address)
            }
            opcode::SELFBALANCE => {
                self.ops.selfbalance += 1;
                Some(interp.input.target_address())
            }
            opcode::EXTCODESIZE => {
                self.ops.extcodesize += 1;
                from_top(0).map(word_address)
            }
            opcode::EXTCODEHASH => {
                self.ops.extcodehash += 1;
                from_top(0).map(word_address)
            }
            opcode::EXTCODECOPY => {
                self.ops.extcodecopy += 1;
                from_top(0).map(word_address)
            }
            opcode::CALL => {
                self.ops.call += 1;
                from_top(1).map(word_address)
            }
            opcode::CALLCODE => {
                self.ops.callcode += 1;
                from_top(1).map(word_address)
            }
            opcode::DELEGATECALL => {
                self.ops.delegatecall += 1;
                from_top(1).map(word_address)
            }
            opcode::STATICCALL => {
                self.ops.staticcall += 1;
                from_top(1).map(word_address)
            }
            opcode::CREATE => {
                self.ops.create += 1;
                None
            }
            opcode::CREATE2 => {
                self.ops.create2 += 1;
                None
            }
            _ => None,
        };
        if let Some(address) = named {
            self.address_ops.entry(address).or_default().hit(tx);
        }
    }
}

fn word_address(word: U256) -> Address {
    Address::from_word(B256::from(word))
}

fn exec_error(e: impl ToString) -> StatelessValidationError {
    StatelessValidationError::StatelessExecutionFailed(e.to_string())
}

/// Validate `current_block` natively while counting state touches; errors on
/// any consensus failure exactly like the vendored loop.
pub fn run(
    current_block: RecoveredBlock<Block>,
    witness: ExecutionWitness,
    top: usize,
) -> Result<CensusReport, StatelessValidationError> {
    let chain_spec = Arc::new(crate::mainnet_spec());
    let evm_config = crate::EthEvmConfig::new(chain_spec.clone());

    let mut ancestor_headers: Vec<_> = witness
        .headers
        .iter()
        .map(|bytes| {
            let hash = keccak256(bytes);
            alloy_rlp::decode_exact::<Header>(bytes)
                .map(|h| SealedHeader::new(h, hash))
                .map_err(|_| StatelessValidationError::HeaderDeserializationFailed)
        })
        .collect::<Result<_, _>>()?;
    ancestor_headers.sort_by_key(|header| header.number());
    let count = ancestor_headers.len();
    if count > BLOCKHASH_ANCESTOR_LIMIT {
        return Err(StatelessValidationError::AncestorHeaderLimitExceeded {
            count,
            limit: BLOCKHASH_ANCESTOR_LIMIT,
        });
    }
    let ancestor_hashes = compute_ancestor_hashes(&current_block, &ancestor_headers)?;
    let parent = ancestor_headers
        .last()
        .ok_or(StatelessValidationError::MissingAncestorHeader)?;
    validate_block_consensus(chain_spec.clone(), &current_block, parent)?;

    let (mut trie, bytecode) = crate::Trie::new_with_codes(&witness, parent.state_root)?;
    let db_counts = Rc::new(RefCell::new(DbCounts::default()));
    let db = CountingDb {
        inner: WitnessDatabase::new(&trie, bytecode, ancestor_hashes),
        counts: db_counts.clone(),
    };
    let mut state = State::builder()
        .with_database(db)
        .with_bundle_update()
        .build();

    // Pre/post-execution system calls are attributed to a pseudo transaction.
    let tx_cursor = Rc::new(Cell::new(usize::MAX));
    let mut census = Census::new(tx_cursor.clone());
    let evm_env = evm_config
        .evm_env(current_block.sealed_block().header())
        .map_err(exec_error)?;
    let evm = evm_config.evm_with_env_and_inspector(&mut state, evm_env, &mut census);
    let ctx = evm_config
        .context_for_block(current_block.sealed_block())
        .map_err(exec_error)?;
    let mut executor = evm_config.create_executor(evm, ctx);
    executor.apply_pre_execution_changes().map_err(exec_error)?;

    let mut account_loads: AddressMap<Touch> = AddressMap::default();
    let mut slot_loads: HashMap<(Address, U256), Touch> = HashMap::default();
    let mut written: HashMap<(Address, U256), ()> = HashMap::default();
    let mut per_tx_accounts: Vec<Vec<Address>> = Vec::new();
    for (i, tx) in current_block.transactions_recovered().enumerate() {
        tx_cursor.set(i);
        let output = executor
            .execute_transaction_without_commit(tx)
            .map_err(exec_error)?;
        let mut loaded = Vec::with_capacity(output.result().state.len());
        for (address, account) in &output.result().state {
            loaded.push(*address);
            account_loads.entry(*address).or_default().hit(i);
            for (slot, value) in &account.storage {
                slot_loads.entry((*address, *slot)).or_default().hit(i);
                if value.is_changed() {
                    written.insert((*address, *slot), ());
                }
            }
        }
        per_tx_accounts.push(loaded);
        executor.commit_transaction(output).map_err(exec_error)?;
    }
    tx_cursor.set(usize::MAX);
    let result = executor
        .apply_post_execution_changes()
        .map_err(exec_error)?;

    state.merge_transitions(BundleRetention::Reverts);
    let bundle = state.take_bundle();
    let root_bloom = receipt_root_bloom(&result.receipts, |address| trie.hashed_address(address));
    validate_block_post_execution(&current_block, &chain_spec, &result, Some(root_bloom))
        .map_err(StatelessValidationError::ConsensusValidationFailed)?;
    let hashed_state = trie.hashed_post_state(&bundle.state);
    let state_root = trie.calculate_state_root(hashed_state)?;
    if state_root != current_block.state_root {
        return Err(StatelessValidationError::PostStateRootMismatch {
            got: state_root,
            expected: current_block.state_root,
        });
    }

    let accounts = key_stats(account_loads.iter().map(|(address, touch)| {
        let ops = census.address_ops.get(address).map_or(0, |t| t.accesses);
        (*touch, ops)
    }));
    let mut slots = key_stats(slot_loads.iter().map(|(key, touch)| {
        let ops = census.slot_ops.get(key).map_or(0, |t| t.accesses);
        (*touch, ops)
    }));
    slots.written = written.len() as u64;

    let mut codes = CodeStats {
        initcode_frames: census.initcode_frames,
        frames: census.initcode_frames,
        distinct_hashes: census.code_frames.len() as u64,
        ..CodeStats::default()
    };
    for touch in census.code_frames.values() {
        codes.frames += touch.accesses;
        if touch.txs >= 2 {
            codes.hashes_in_2plus_txs += 1;
            codes.frames_on_repeated += touch.accesses;
        }
    }

    let mut ranked: Vec<(Address, Touch)> = account_loads
        .iter()
        .map(|(address, touch)| (*address, *touch))
        .collect();
    ranked.sort_by(|a, b| b.1.txs.cmp(&a.1.txs).then(a.0.cmp(&b.0)));
    ranked.truncate(top);
    let hottest: Vec<HotAccount> = ranked
        .iter()
        .map(|(address, touch)| {
            let slot_ops = census
                .slot_ops
                .iter()
                .filter(|((a, _), _)| a == address)
                .map(|(_, t)| t.accesses)
                .sum();
            HotAccount {
                address: *address,
                txs: touch.txs,
                slots_loaded: slot_loads.keys().filter(|(a, _)| a == address).count() as u64,
                slot_ops,
                address_ops: census.address_ops.get(address).map_or(0, |t| t.accesses),
            }
        })
        .collect();
    let hot_set: AddressMap<()> = ranked.iter().map(|(a, _)| (*a, ())).collect();
    let hottest_union_txs = per_tx_accounts
        .iter()
        .filter(|loaded| loaded.iter().any(|a| hot_set.contains_key(a)))
        .count() as u64;

    let db = *db_counts.borrow();
    Ok(CensusReport {
        block: current_block.number,
        block_hash: current_block.hash_slow(),
        gas_used: result.gas_used,
        txs: per_tx_accounts.len(),
        witness_nodes: witness.state.len(),
        witness_codes: witness.codes.len(),
        ops: census.ops,
        db,
        accounts,
        slots,
        codes,
        hottest,
        hottest_union_txs,
    })
}

/// Fold `(loads of one key, opcode accesses naming it)` pairs into [`KeyStats`].
fn key_stats(keys: impl Iterator<Item = (Touch, u64)>) -> KeyStats {
    let mut stats = KeyStats::default();
    for (touch, ops) in keys {
        stats.distinct += 1;
        stats.tx_loads += touch.txs;
        stats.op_accesses += ops;
        if touch.txs >= 2 {
            stats.repeated += 1;
            stats.repeated_tx_loads += touch.txs;
            stats.repeated_op_accesses += ops;
        }
    }
    stats
}
