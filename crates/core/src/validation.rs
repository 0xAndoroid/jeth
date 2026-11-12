//! Stateless validation with an expanded transaction loop.
//!
//! Vendored from `stateless::validation::stateless_validation_recovered_with_trie`
//! @ 6e55612 (Apache-2.0/MIT, Paradigm) with `Executor::execute` expanded into the
//! underlying `BlockExecutor` phases so jeth can:
//!
//! 1. emit a cycle marker around every transaction (`pertx-markers` feature) —
//!    the host `jeth txprofile` command parses the tracer's marker output into a
//!    per-transaction cycle table;
//! 2. defer bytecode analysis to first execution (`lazy-analysis` feature):
//!    only a subset of the witness codes ever runs.
//!
//! Behavior is otherwise identical to upstream: same consensus checks, same
//! `WitnessDatabase` semantics (vendored below because upstream's is
//! `pub(crate)`), same post-execution checks and state-root comparison. The
//! native gate (`jeth run-native`) still runs the *upstream* path, so every
//! bench cross-checks this loop bit-for-bit against stateless 6e55612.

use alloc::{collections::btree_map::BTreeMap, format, string::ToString, sync::Arc, vec::Vec};
#[cfg(test)]
use alloy_consensus::proofs::calculate_receipt_root;
use alloy_consensus::{BlockHeader, Header, ReceiptWithBloom, TxReceipt};
use alloy_primitives::{
    keccak256,
    map::{B256IndexMap, B256Map},
    Address, Bloom, Bytes, B256, U256,
};
#[cfg(feature = "lazy-analysis")]
use core::cell::RefCell;
use reth_consensus::{Consensus, HeaderValidator};
use reth_ethereum_consensus::{validate_block_post_execution, EthBeaconConsensus};
use reth_ethereum_primitives::{Block, EthereumReceipt};
use reth_evm::{block::BlockExecutorFactory, execute::BlockExecutor, ConfigureEvm, Evm};
use reth_primitives_traits::{RecoveredBlock, SealedHeader};
use revm_bytecode::Bytecode;
use revm_database_interface::{Database, DatabaseCommit};
use revm_state::AccountInfo;
use stateless::{validation::StatelessValidationError, ExecutionWitness, StatelessTrie};
use tries::WitnessDbError;

/// BLOCKHASH ancestor lookup window limit per EVM.
pub(crate) const BLOCKHASH_ANCESTOR_LIMIT: usize = 256;

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
#[expect(
    clippy::unused_enumerate_index,
    reason = "The transaction index is consumed only by guest instrumentation."
)]
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
    let mut state = crate::block_overlay::BlockOverlay::new(db, witness.state.len());
    let evm = evm_config
        .evm_for_block(&mut state, current_block.header())
        .map_err(|e| StatelessValidationError::StatelessExecutionFailed(e.to_string()))?;
    let context = evm_config
        .context_for_block(current_block.sealed_block())
        .map_err(|e| StatelessValidationError::StatelessExecutionFailed(e.to_string()))?;
    let mut executor = evm_config
        .block_executor_factory()
        .create_executor(evm, context);

    // Reserve the actual block-wide call buffer without exposing any bytes.
    // Expansion gas and zero initialization still occur in SharedMemory.
    executor
        .evm_mut()
        .ctx()
        .local
        .shared_memory_buffer
        .borrow_mut()
        .reserve(1024 * 1024);

    executor
        .apply_pre_execution_changes()
        .map_err(|e| StatelessValidationError::StatelessExecutionFailed(e.to_string()))?;

    // This fixed receipt builder uses only execution results; no state hook is installed.
    executor.evm_mut().retain_transactions();

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

    // Apply the retained final values before withdrawals and post-block calls.
    // The overlay owns block originals, so it consumes all present slots.
    let evm = executor.evm_mut();
    let changes = evm.take_retained_state();
    evm.db_mut().commit(changes);

    let result = executor
        .apply_post_execution_changes()
        .map_err(|e| StatelessValidationError::StatelessExecutionFailed(e.to_string()))?;

    let accounts = core::mem::take(&mut state.accounts);
    // Single-shot process: leak the block cache instead of tearing it down.
    core::mem::forget(state);

    let root_bloom = receipt_root_bloom(&result.receipts, |address| trie.hashed_address(address));
    validate_block_post_execution(&current_block, &chain_spec, &result, Some(root_bloom))
        .map_err(StatelessValidationError::ConsensusValidationFailed)?;

    let hashed_state = trie.hashed_post_state(
        accounts
            .iter()
            .filter(|(_, account)| crate::block_overlay::is_changed(account)),
    );
    let state_root = trie.calculate_state_root(hashed_state)?;
    if state_root != current_block.state_root {
        return Err(StatelessValidationError::PostStateRootMismatch {
            got: state_root,
            expected: current_block.state_root,
        });
    }

    let validated = ValidatedBlock {
        block_hash: current_block.hash_slow(),
        gas_used: result.gas_used,
        receipts: result.receipts,
    };
    core::mem::forget(trie);
    core::mem::forget(accounts);
    core::mem::forget(witness);
    core::mem::forget(current_block);
    Ok(validated)
}

pub(crate) fn validate_block_consensus(
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

pub(crate) fn compute_ancestor_hashes(
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
        if let Some(code) = crate::code_library::lookup(code_hash).map_err(|error| {
            WitnessDbError::TrieWitness(format!("invalid code library: {error:?}"))
        })? {
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

#[derive(Default)]
struct WordBloom([u64; 32]);

impl WordBloom {
    #[inline]
    fn accrue_hash(&mut self, hash: &B256) {
        for i in [0, 2, 4] {
            let bit = usize::from(u16::from_be_bytes([hash[i], hash[i + 1]])) & 2047;
            let offset = (bit & 63)
                ^ if cfg!(target_endian = "little") {
                    56
                } else {
                    0
                };
            self.0[31 - bit / 64] |= 1 << offset;
        }
    }

    fn accrue_bloom(&mut self, other: &Self) {
        for (dst, src) in self.0.iter_mut().zip(&other.0) {
            *dst |= *src;
        }
    }

    fn into_bloom(self) -> Bloom {
        // SAFETY: Both arrays occupy 256 bytes with no padding or invalid bit patterns.
        // accrue_hash places bits in the bloom's byte order on either endianness.
        Bloom::from(unsafe { core::mem::transmute::<[u64; 32], [u8; 256]>(self.0) })
    }
}

/// Receipt root + block bloom; `hash_address` supplies `keccak256(address)`
/// for log emitters (the trie's execution-time memo), topics are memoized here.
pub(crate) fn receipt_root_bloom(
    receipts: &[EthereumReceipt],
    mut hash_address: impl FnMut(Address) -> B256,
) -> (B256, Bloom) {
    // Distinct topics <= sum of topics over all logs: presize the memo.
    let topic_count: usize = receipts
        .iter()
        .flat_map(|receipt| receipt.logs())
        .map(|log| log.topics().len())
        .sum();
    let mut topics = B256Map::with_capacity_and_hasher(topic_count, Default::default());
    let mut bloom = WordBloom::default();
    let receipts: Vec<_> = receipts
        .iter()
        .map(|receipt| {
            let mut logs_bloom = WordBloom::default();
            for log in receipt.logs() {
                logs_bloom.accrue_hash(&hash_address(log.address));
                for &topic in log.topics() {
                    let hash = topics.entry(topic).or_insert_with(|| keccak256(topic));
                    logs_bloom.accrue_hash(hash);
                }
            }
            bloom.accrue_bloom(&logs_bloom);
            ReceiptWithBloom {
                receipt,
                logs_bloom: logs_bloom.into_bloom(),
            }
        })
        .collect();
    let root = alloy_trie::root::ordered_trie_root_with_encoder(&receipts, encode_receipt_prepared);
    (root, bloom.into_bloom())
}

/// The caller supplies 256 readable aligned source bytes and 256 writable
/// destination bytes; LEAD is in 0..8 and dst + LEAD is word aligned. The
/// regions do not overlap. Each instantiation initializes the same 256 bytes.
#[inline(always)]
unsafe fn write_receipt_bloom_at<const LEAD: usize>(dst: *mut u8, src: *const u64) {
    use core::ptr::{read_volatile, write_volatile};
    // SAFETY: the caller establishes the readable and writable ranges,
    // non-overlap and the source/destination word alignment documented above.
    unsafe {
        if LEAD == 0 {
            macro_rules! word {
                ($i:expr) => {
                    write_volatile(dst.cast::<u64>().add($i), read_volatile(src.add($i)));
                };
            }
            word!(0);
            word!(1);
            word!(2);
            word!(3);
            word!(4);
            word!(5);
            word!(6);
            word!(7);
            word!(8);
            word!(9);
            word!(10);
            word!(11);
            word!(12);
            word!(13);
            word!(14);
            word!(15);
            word!(16);
            word!(17);
            word!(18);
            word!(19);
            word!(20);
            word!(21);
            word!(22);
            word!(23);
            word!(24);
            word!(25);
            word!(26);
            word!(27);
            word!(28);
            word!(29);
            word!(30);
            word!(31);
        } else {
            let mut previous = read_volatile(src);
            for i in 0..LEAD {
                dst.add(i).write((previous >> (8 * i)) as u8);
            }
            let words = dst.add(LEAD).cast::<u64>();
            let shift = 8 * LEAD;
            macro_rules! word {
                ($i:expr) => {
                    let next = read_volatile(src.add($i));
                    write_volatile(
                        words.add($i - 1),
                        (previous >> shift) | (next << (64 - shift)),
                    );
                    previous = next;
                };
            }
            word!(1);
            word!(2);
            word!(3);
            word!(4);
            word!(5);
            word!(6);
            word!(7);
            word!(8);
            word!(9);
            word!(10);
            word!(11);
            word!(12);
            word!(13);
            word!(14);
            word!(15);
            word!(16);
            word!(17);
            word!(18);
            word!(19);
            word!(20);
            word!(21);
            word!(22);
            word!(23);
            word!(24);
            word!(25);
            word!(26);
            word!(27);
            word!(28);
            word!(29);
            word!(30);
            word!(31);
            for i in LEAD..8 {
                dst.add(248 + i).write((previous >> (8 * i)) as u8);
            }
        }
    }
}

/// Copy one bloom into the final receipt buffer. An aligned source permits
/// bounded word reads and aligned destination stores after a short byte head.
/// Unaligned sources retain the library copy, including on native test hosts.
fn append_receipt_bloom(out: &mut Vec<u8>, bloom: &[u8]) {
    assert_eq!(bloom.len(), 256);
    if !cfg!(target_endian = "little") || bloom.as_ptr() as usize & 7 != 0 {
        out.extend_from_slice(bloom);
        return;
    }
    out.reserve(256);
    let old_len = out.len();
    // SAFETY: reserve provides 256 writable spare bytes, and the immutable
    // source cannot alias the exclusive vector borrow. Every word read stays
    // within the 256-byte source and has checked alignment. Every word store
    // is aligned and stays within the reserved destination. The byte head and
    // tail complete the initialization before set_len exposes these bytes.
    unsafe {
        let src = bloom.as_ptr().cast::<u64>();
        let dst = out.as_mut_ptr().add(old_len);
        let lead = (8 - (dst as usize & 7)) & 7;
        match lead {
            0 => write_receipt_bloom_at::<0>(dst, src),
            1 => write_receipt_bloom_at::<1>(dst, src),
            2 => write_receipt_bloom_at::<2>(dst, src),
            3 => write_receipt_bloom_at::<3>(dst, src),
            4 => write_receipt_bloom_at::<4>(dst, src),
            5 => write_receipt_bloom_at::<5>(dst, src),
            6 => write_receipt_bloom_at::<6>(dst, src),
            7 => write_receipt_bloom_at::<7>(dst, src),
            _ => unreachable!(),
        }
        out.set_len(old_len + 256);
    }
}

/// Encode the canonical receipt into the root builder's reusable vector.
/// Retain the logs payload length for its list header instead of scanning the
/// logs again after computing the outer receipt length.
fn encode_receipt_prepared(value: &ReceiptWithBloom<&EthereumReceipt>, out: &mut Vec<u8>) {
    use alloy_eips::eip2718::Typed2718;
    use alloy_rlp::{Encodable, Header as RlpHeader};
    let receipt = value.receipt;
    let logs_header = RlpHeader {
        list: true,
        payload_length: receipt.logs.iter().map(Encodable::length).sum(),
    };
    let header = RlpHeader {
        list: true,
        payload_length: receipt.success.length()
            + receipt.cumulative_gas_used.length()
            + 259
            + logs_header.length_with_payload(),
    };
    let typed = !receipt.tx_type.is_legacy();
    out.reserve(header.length_with_payload() + usize::from(typed));
    if typed {
        out.push(receipt.tx_type.ty());
    }
    header.encode(out);
    receipt.success.encode(out);
    receipt.cumulative_gas_used.encode(out);
    // A 256-byte bloom has the fixed canonical RLP string header b9 01 00.
    out.extend_from_slice(&[0xb9, 0x01, 0x00]);
    append_receipt_bloom(out, value.logs_bloom.as_slice());
    logs_header.encode(out);
    for log in &receipt.logs {
        log.encode(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::TxType;
    use alloy_primitives::Log;

    #[test]
    fn receipt_bloom_copy_matches_all_alignments() {
        #[repr(align(8))]
        struct Aligned([u8; 264]);
        let mut source = Aligned([0; 264]);
        let mut seed = 0xab71_2849_ce63_d50fu64;
        for _ in 0..32 {
            for b in &mut source.0 {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
            for source_offset in 0..8 {
                for destination_offset in 0..8 {
                    let mut actual = Vec::with_capacity(272);
                    let prefix = (destination_offset + 8 - (actual.as_ptr() as usize & 7)) & 7;
                    actual.resize(prefix, 0xa5);
                    assert_eq!(
                        (actual.as_ptr() as usize + actual.len()) & 7,
                        destination_offset
                    );
                    let mut expected = actual.clone();
                    let bloom = &source.0[source_offset..source_offset + 256];
                    expected.extend_from_slice(bloom);
                    append_receipt_bloom(&mut actual, bloom);
                    assert_eq!(actual, expected);
                    assert_eq!(keccak256(&actual), keccak256(&expected));
                    actual.push(0xc0);
                    expected.push(0xc0);
                    assert_eq!(actual, expected);
                }
            }
        }
        let mut growing = alloc::vec![0x7f];
        let mut expected = growing.clone();
        expected.extend_from_slice(&source.0[..256]);
        append_receipt_bloom(&mut growing, &source.0[..256]);
        assert_eq!(growing, expected);
    }

    #[test]
    fn prepared_receipt_encoding_matches_reference() {
        use alloy_eips::eip2718::Encodable2718;
        let mut seed = 0x67b4_a21c_09e3_d85fu64;
        let mut random = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut receipts = Vec::new();
        for i in 0..192usize {
            let mut logs = Vec::new();
            for j in 0..i % 6 {
                let mut address = [0u8; 20];
                for b in &mut address {
                    *b = random() as u8;
                }
                let mut topics = Vec::new();
                for _ in 0..j % 5 {
                    let mut topic = [0u8; 32];
                    for b in &mut topic {
                        *b = random() as u8;
                    }
                    topics.push(B256::from(topic));
                }
                let len = [0, 1, 55, 56, 255, 256, 511][(i + j) % 7];
                let data: Vec<u8> = (0..len).map(|_| random() as u8).collect();
                logs.push(Log::new_unchecked(
                    Address::from(address),
                    topics,
                    data.into(),
                ));
            }
            receipts.push(EthereumReceipt {
                tx_type: [
                    TxType::Legacy,
                    TxType::Eip2930,
                    TxType::Eip1559,
                    TxType::Eip4844,
                    TxType::Eip7702,
                ][i % 5],
                success: random() & 1 == 0,
                cumulative_gas_used: random(),
                logs,
            });
        }
        let prepared: Vec<_> = receipts.iter().map(TxReceipt::with_bloom_ref).collect();
        let mut actual = Vec::new();
        let mut reference = Vec::new();
        for receipt in &prepared {
            actual.clear();
            reference.clear();
            encode_receipt_prepared(receipt, &mut actual);
            receipt.encode_2718(&mut reference);
            assert_eq!(actual, reference);
            assert_eq!(keccak256(&actual), keccak256(&reference));
        }
        for n in [0, 1, 127, 128, 192] {
            assert_eq!(
                alloy_trie::root::ordered_trie_root_with_encoder(
                    &prepared[..n],
                    encode_receipt_prepared
                ),
                calculate_receipt_root(&prepared[..n])
            );
        }
    }

    #[test]
    fn word_bloom_sets_each_protocol_bit() {
        for bit in 0..2048u16 {
            let pair = bit.to_be_bytes();
            let mut hash = B256::ZERO;
            for i in [0, 2, 4] {
                hash[i..i + 2].copy_from_slice(&pair);
            }
            let mut bloom = WordBloom::default();
            bloom.accrue_hash(&hash);
            let mut expected = Bloom::ZERO;
            expected[255 - usize::from(bit / 8)] = 1 << (bit % 8);
            assert_eq!(bloom.into_bloom(), expected);
        }
    }

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
            assert_eq!(receipt_root_bloom(receipts, keccak256), expected);
        }
    }
}
