//! Stateless validation with an expanded transaction loop.
//!
//! Vendored from `stateless::validation::stateless_validation_recovered_with_trie`
//! @ 6e55612 (Apache-2.0/MIT, Paradigm) with `Executor::execute` expanded into the
//! underlying `BlockExecutor` phases so jeth can:
//!
//! 1. emit a cycle marker around every transaction (`pertx-markers` feature) —
//!    the host `jeth txprofile` command parses the tracer's marker output into a
//!    per-transaction cycle table;
//! 2. defer bytecode analysis to first execution (`lazy-analysis` feature) —
//!    `analyze_legacy` over every witness code measured 39.7M rows (2.7%) on
//!    block 25698189 while only a subset of codes ever runs.
//!
//! Behavior is otherwise identical to upstream: same consensus checks, same
//! `WitnessDatabase` semantics (vendored below because upstream's is
//! `pub(crate)`), same post-execution checks and state-root comparison. The
//! native gate (`jeth run-native`) still runs the *upstream* path, so every
//! bench cross-checks this loop bit-for-bit against stateless 6e55612.

use alloc::{collections::btree_map::BTreeMap, format, string::ToString, sync::Arc, vec::Vec};
use alloy_consensus::{
    proofs::calculate_receipt_root, BlockHeader, Header, ReceiptWithBloom, TxReceipt,
};
use alloy_primitives::{
    keccak256,
    map::{AddressMap, B256IndexMap, B256Map},
    Address, Bloom, Bytes, B256, U256,
};
#[cfg(feature = "lazy-analysis")]
use core::cell::RefCell;
use reth_consensus::{Consensus, HeaderValidator};
use reth_ethereum_consensus::{validate_block_post_execution, EthBeaconConsensus};
use reth_ethereum_primitives::{Block, EthereumReceipt};
use reth_evm::{
    execute::{BlockExecutionOutput, BlockExecutor},
    revm::database::{states::bundle_state::BundleRetention, State},
    ConfigureEvm,
};
use reth_primitives_traits::{RecoveredBlock, SealedHeader};
use revm_bytecode::Bytecode;
use revm_database_interface::Database;
use revm_state::AccountInfo;
use stateless::{validation::StatelessValidationError, ExecutionWitness, StatelessTrie};
use tries::WitnessDbError;

/// BLOCKHASH ancestor lookup window limit per EVM.
const BLOCKHASH_ANCESTOR_LIMIT: usize = 256;

/// Per-transaction cycle marker labels: "tx0000".."tx9999". The tracer keys
/// active markers by the label pointer, so one reused buffer is fine for
/// strictly nested start/end pairs.
#[cfg(feature = "pertx-markers")]
fn tx_label(i: usize, buf: &mut [u8; 6]) -> &str {
    *buf = *b"tx0000";
    buf[2] = b'0' + (i / 1000 % 10) as u8;
    buf[3] = b'0' + (i / 100 % 10) as u8;
    buf[4] = b'0' + (i / 10 % 10) as u8;
    buf[5] = b'0' + (i % 10) as u8;
    // Safety: ASCII by construction.
    unsafe { core::str::from_utf8_unchecked(buf) }
}

/// Result of the vendored validation: consensus-relevant outputs plus the
/// per-tx receipts (cumulative gas — the host txprofile joins these with the
/// per-tx cycle markers).
pub struct ValidatedBlock {
    pub block_hash: B256,
    pub gas_used: u64,
    pub receipts: Vec<EthereumReceipt>,
}

/// Stateless validation with the tx loop expanded in-line (see module docs).
// The enumerate index feeds the per-tx markers, which are feature-gated.
#[allow(clippy::unused_enumerate_index)]
pub fn validate_recovered_pertx(
    current_block: RecoveredBlock<Block>,
    witness: ExecutionWitness,
    chain_spec: Arc<crate::ChainSpec>,
    evm_config: crate::EthEvmConfig,
) -> Result<ValidatedBlock, StatelessValidationError> {
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

    let db = WitnessDatabase::new(&trie, bytecode, ancestor_hashes);
    let mut state = State::builder()
        .with_database(db)
        .with_bundle_update()
        .build();

    let mut executor = evm_config
        .executor_for_block(&mut state, current_block.sealed_block())
        .map_err(|e| StatelessValidationError::StatelessExecutionFailed(e.to_string()))?;

    executor
        .apply_pre_execution_changes()
        .map_err(|e| StatelessValidationError::StatelessExecutionFailed(e.to_string()))?;

    #[cfg(feature = "pertx-markers")]
    let mut label_buf = *b"tx0000";
    for (_i, tx) in current_block.transactions_recovered().enumerate() {
        #[cfg(feature = "pertx-markers")]
        crate::instrument::phase_start_dyn(tx_label(_i, &mut label_buf));
        executor
            .execute_transaction(tx)
            .map_err(|e| StatelessValidationError::StatelessExecutionFailed(e.to_string()))?;
        #[cfg(feature = "pertx-markers")]
        crate::instrument::phase_end_dyn(tx_label(_i, &mut label_buf));
    }

    let result = executor
        .apply_post_execution_changes()
        .map_err(|e| StatelessValidationError::StatelessExecutionFailed(e.to_string()))?;

    state.merge_transitions(BundleRetention::Reverts);
    let output = BlockExecutionOutput {
        state: state.take_bundle(),
        result,
    };
    // Single-shot process: leak the block state instead of tearing it down.
    core::mem::forget(state);

    let root_bloom = receipt_root_bloom(&output.result.receipts);
    validate_block_post_execution(
        &current_block,
        &chain_spec,
        &output.result,
        Some(root_bloom),
    )
    .map_err(StatelessValidationError::ConsensusValidationFailed)?;

    let hashed_state = trie.hashed_post_state(&output.state.state);
    let state_root = trie.calculate_state_root(hashed_state)?;
    if state_root != current_block.state_root {
        return Err(StatelessValidationError::PostStateRootMismatch {
            got: state_root,
            expected: current_block.state_root,
        });
    }

    let validated = ValidatedBlock {
        block_hash: current_block.hash_slow(),
        gas_used: output.result.gas_used,
        receipts: output.result.receipts,
    };
    core::mem::forget(trie);
    core::mem::forget(output.state);
    core::mem::forget(witness);
    core::mem::forget(current_block);
    Ok(validated)
}

fn validate_block_consensus(
    chain_spec: Arc<crate::ChainSpec>,
    block: &RecoveredBlock<Block>,
    parent: &SealedHeader<Header>,
) -> Result<(), StatelessValidationError> {
    let consensus = EthBeaconConsensus::new(chain_spec);
    consensus.validate_header(block.sealed_header())?;
    consensus.validate_header_against_parent(block.sealed_header(), parent)?;
    consensus.validate_block_pre_execution(block)?;
    Ok(())
}

fn compute_ancestor_hashes(
    current_block: &RecoveredBlock<Block>,
    ancestor_headers: &[SealedHeader],
) -> Result<BTreeMap<u64, B256>, StatelessValidationError> {
    let mut ancestor_hashes = BTreeMap::new();
    let mut child_header = current_block.sealed_header();

    for parent_header in ancestor_headers.iter().rev() {
        let parent_hash = child_header.parent_hash();
        ancestor_hashes.insert(parent_header.number, parent_hash);

        if parent_hash != parent_header.hash() {
            return Err(StatelessValidationError::InvalidAncestorParentHash {
                child_number: child_header.number,
                parent_number: parent_header.number,
                expected_parent_hash: parent_hash,
                actual_parent_hash: parent_header.hash(),
            });
        }

        if parent_header.number + 1 != child_header.number {
            return Err(StatelessValidationError::InvalidAncestorNumber {
                child_number: child_header.number,
                expected_parent_number: child_header.number.saturating_sub(1),
                parent_number: parent_header.number,
            });
        }

        child_header = parent_header;
    }

    Ok(ancestor_hashes)
}

/// Bytecode map handed to [`WitnessDatabase`]: eagerly analyzed (upstream
/// behavior) or raw bytes analyzed on first execution (`lazy-analysis`).
///
/// Manual `Debug` (revm's `State` DB bound requires it) — a map dump would be
/// megabytes of bytecode.
pub enum CodeMap {
    Eager(B256IndexMap<Bytecode>),
    #[cfg(feature = "lazy-analysis")]
    Lazy {
        raw: B256IndexMap<Bytes>,
        analyzed: RefCell<B256IndexMap<Bytecode>>,
    },
}

impl CodeMap {
    /// Build from witness codes + their (computed or trusted) hashes.
    pub fn build<'a>(codes: impl Iterator<Item = (B256, &'a Bytes)>) -> Self {
        #[cfg(feature = "lazy-analysis")]
        {
            CodeMap::Lazy {
                raw: codes.map(|(hash, code)| (hash, code.clone())).collect(),
                analyzed: RefCell::new(B256IndexMap::default()),
            }
        }
        #[cfg(not(feature = "lazy-analysis"))]
        {
            CodeMap::Eager(
                codes
                    .map(|(hash, code)| (hash, Bytecode::new_raw(code.clone())))
                    .collect(),
            )
        }
    }

    fn get(&self, code_hash: &B256) -> Result<Bytecode, WitnessDbError> {
        if let Some(code) = crate::code_library::lookup(code_hash) {
            return Ok(code);
        }
        match self {
            CodeMap::Eager(map) => map.get(code_hash).cloned().ok_or_else(|| {
                WitnessDbError::TrieWitness(format!("bytecode for {code_hash} not found"))
            }),
            #[cfg(feature = "lazy-analysis")]
            CodeMap::Lazy { raw, analyzed } => {
                if let Some(code) = analyzed.borrow().get(code_hash) {
                    return Ok(code.clone());
                }
                let bytes = raw.get(code_hash).ok_or_else(|| {
                    WitnessDbError::TrieWitness(format!("bytecode for {code_hash} not found"))
                })?;
                let code = Bytecode::new_raw(bytes.clone());
                analyzed.borrow_mut().insert(*code_hash, code.clone());
                Ok(code)
            }
        }
    }
}

impl core::fmt::Debug for CodeMap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CodeMap::Eager(map) => write!(f, "CodeMap::Eager({} codes)", map.len()),
            #[cfg(feature = "lazy-analysis")]
            CodeMap::Lazy { raw, analyzed } => write!(
                f,
                "CodeMap::Lazy({} codes, {} analyzed)",
                raw.len(),
                analyzed.borrow().len()
            ),
        }
    }
}

/// Vendored from `stateless::witness_db` @ 6e55612 (upstream type is
/// `pub(crate)`); extended with [`CodeMap`] for lazy bytecode analysis.
#[derive(Debug)]
pub struct WitnessDatabase<'a, T: StatelessTrie> {
    block_hashes_by_block_number: BTreeMap<u64, B256>,
    bytecode: CodeMap,
    trie: &'a T,
}

impl<'a, T: StatelessTrie> WitnessDatabase<'a, T> {
    pub const fn new(trie: &'a T, bytecode: CodeMap, ancestor_hashes: BTreeMap<u64, B256>) -> Self {
        Self {
            trie,
            block_hashes_by_block_number: ancestor_hashes,
            bytecode,
        }
    }
}

impl<T: StatelessTrie> Database for WitnessDatabase<'_, T> {
    type Error = WitnessDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.trie.account(address).map(|opt| {
            opt.map(|account| AccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash,
                code: None,
                account_id: None,
            })
        })
    }

    fn storage(&mut self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        self.trie.storage(address, slot)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.bytecode.get(&code_hash)
    }

    fn block_hash(&mut self, block_number: u64) -> Result<B256, Self::Error> {
        self.block_hashes_by_block_number
            .get(&block_number)
            .copied()
            .ok_or(WitnessDbError::StateNotFound(block_number))
    }
}

fn receipt_root_bloom(receipts: &[EthereumReceipt]) -> (B256, Bloom) {
    let mut topics = B256Map::default();
    let mut addresses = AddressMap::default();
    let receipts: Vec<_> = receipts
        .iter()
        .map(|receipt| {
            let mut logs_bloom = Bloom::ZERO;
            for log in receipt.logs() {
                let hash = addresses
                    .entry(log.address)
                    .or_insert_with(|| keccak256(log.address.as_slice()));
                logs_bloom.m3_2048_hashed(hash);
                for &topic in log.topics() {
                    let hash = topics.entry(topic).or_insert_with(|| keccak256(topic));
                    logs_bloom.m3_2048_hashed(hash);
                }
            }
            ReceiptWithBloom {
                receipt,
                logs_bloom,
            }
        })
        .collect();
    let root = calculate_receipt_root(&receipts);
    let bloom = receipts
        .iter()
        .fold(Bloom::ZERO, |bloom, r| bloom | r.logs_bloom);
    (root, bloom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::TxType;
    use alloy_primitives::Log;

    #[test]
    fn receipt_root_bloom_matches_direct_hashing() {
        let mut seed = 0x4e7c_2351_a009_eb62u64;
        let mut receipts = Vec::new();
        let mut pool = Vec::new();
        for _ in 0..128 {
            let mut bytes = [0u8; 32];
            for byte in &mut bytes {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *byte = seed as u8;
            }
            pool.push(B256::from(bytes));
        }
        for i in 0..96 {
            receipts.push(EthereumReceipt {
                tx_type: if i % 2 == 0 {
                    TxType::Legacy
                } else {
                    TxType::Eip1559
                },
                success: i % 3 != 0,
                cumulative_gas_used: 21_000 * (i as u64 + 1),
                logs: (0..i % 5)
                    .map(|j| {
                        Log::new_unchecked(
                            Address::from_slice(&pool[(i + j) % pool.len()][..20]),
                            (0..j).map(|k| pool[(i + k) % pool.len()]).collect(),
                            Bytes::copy_from_slice(&pool[j][..i % 32]),
                        )
                    })
                    .collect(),
            });
        }
        for len in [0, 1, 32, 96] {
            let receipts = &receipts[..len];
            let direct: Vec<_> = receipts.iter().map(TxReceipt::with_bloom_ref).collect();
            let expected = (
                calculate_receipt_root(&direct),
                direct
                    .iter()
                    .fold(Bloom::ZERO, |bloom, r| bloom | r.logs_bloom),
            );
            assert_eq!(receipt_root_bloom(receipts), expected);
        }
    }
}
