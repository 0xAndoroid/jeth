//! Keccak memos for the sparse state: flat open-addressing tables from address
//! / slot words to digest words, the aligned `B256` they hand out, and the
//! one-entry last-read chain `SparseState` keeps in front of them.

use crate::resolver::b256_from_le_words;
use alloc::vec::Vec;
use alloy_primitives::{keccak256, Address, B256, U256};
use core::cell::RefCell;
use reth_evm::revm::database::BundleAccount;
use reth_trie_common::{HashedPostState, HashedStorage};

pub(crate) type AddressMemo = KeccakMemo<3>;
pub(crate) type SlotMemo = KeccakMemo<4>;

/// Flat open-addressing keccak memo: `K` key words → digest words. A
/// hashbrown probe costs ≈300 rows on Jolt (byte-wise control-group scan,
/// sub-word stores, a four-word hash fold, a second probe on insert); a linear
/// probe over whole-word entries costs ≈25. `live` marks occupancy, so a zero
/// key is an ordinary key.
#[derive(Debug, Clone)]
pub(crate) struct KeccakMemo<const K: usize> {
    entries: Vec<MemoEntry<K>>,
    len: usize,
    /// `64 - log2(entries.len())`: the slot is the top bits of the hash.
    shift: u32,
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
struct MemoEntry<const K: usize> {
    live: u64,
    key: [u64; K],
    digest: [u64; 4],
}

impl<const K: usize> MemoEntry<K> {
    const EMPTY: Self = Self {
        live: 0,
        key: [0; K],
        digest: [0; 4],
    };
}

impl<const K: usize> KeccakMemo<K> {
    /// Sized for about `expected` keys; the table doubles past a 0.7 load.
    pub(crate) fn with_capacity(expected: usize) -> Self {
        Self::with_slots(expected.next_power_of_two().max(64))
    }

    fn with_slots(slots: usize) -> Self {
        Self {
            entries: alloc::vec![MemoEntry::EMPTY; slots],
            len: 0,
            shift: 64 - slots.trailing_zeros(),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.len
    }

    /// Fibonacci hash of the XOR-folded key words.
    #[inline(always)]
    fn slot(&self, key: &[u64; K]) -> usize {
        let folded = key.iter().fold(0u64, |acc, word| acc ^ word);
        (folded.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> self.shift) as usize
    }

    /// The digest memoized for `key`, or `digest()` recorded for it.
    #[inline(always)]
    fn get_or_insert_with(&mut self, key: [u64; K], digest: impl FnOnce() -> [u64; 4]) -> [u64; 4] {
        let mask = self.entries.len() - 1;
        let mut i = self.slot(&key);
        loop {
            let entry = &self.entries[i];
            if entry.live == 0 {
                return self.insert_at(i, key, digest);
            }
            let mut diff = 0;
            for (have, want) in entry.key.iter().zip(&key) {
                diff |= have ^ want;
            }
            if diff == 0 {
                return entry.digest;
            }
            i = (i + 1) & mask;
        }
    }

    /// Miss path, kept out of line so the hit path above stays a few
    /// instructions with no frame of its own.
    #[cold]
    #[inline(never)]
    fn insert_at(
        &mut self,
        i: usize,
        key: [u64; K],
        digest: impl FnOnce() -> [u64; 4],
    ) -> [u64; 4] {
        let digest = digest();
        self.entries[i] = MemoEntry {
            live: 1,
            key,
            digest,
        };
        self.len += 1;
        if 10 * self.len > 7 * self.entries.len() {
            self.grow();
        }
        digest
    }

    fn grow(&mut self) {
        let mut grown = Self::with_slots(2 * self.entries.len());
        let mask = grown.entries.len() - 1;
        for entry in self.entries.iter().filter(|entry| entry.live != 0) {
            let mut i = grown.slot(&entry.key);
            while grown.entries[i].live != 0 {
                i = (i + 1) & mask;
            }
            grown.entries[i] = *entry;
        }
        grown.len = self.len;
        *self = grown;
    }
}

/// A `B256` at an 8-byte boundary. A bare `B256` is align 1, so materializing
/// one from words stores its 32 bytes one at a time (≈220 rows); into an
/// aligned slot it is four whole-word stores.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
pub(crate) struct AlignedB256(pub(crate) B256);

impl AlignedB256 {
    #[inline(always)]
    pub(crate) fn from_le_words(words: [u64; 4]) -> Self {
        Self(b256_from_le_words(words))
    }

    /// The four little-endian words (whole-word loads: the bytes are 8-aligned).
    #[inline(always)]
    pub(crate) fn words(&self) -> [u64; 4] {
        let bytes = &self.0 .0;
        core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
    }
}

/// The 20 address bytes as three little-endian words (word 2 holds bytes
/// 16..20). `Address` is align 1, so this is 20 byte loads; it stays
/// in-bounds and free of pointer-to-integer casts so that every caller passing
/// the address by value hands over its own copy — LLVM elides that copy only
/// for callees it can prove read-only and non-capturing, and a gather from the
/// containing aligned words (cheaper here) made each caller repack the address
/// byte-wise before the call instead.
#[inline(always)]
pub(crate) fn address_words(address: &Address) -> [u64; 3] {
    let bytes = &address.0 .0;
    [
        u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u32::from_le_bytes(bytes[16..].try_into().unwrap()) as u64,
    ]
}

/// One-entry memo of the address → (hashed address, storage root) chain.
/// Pre-state storage roots are immutable during execution, so an entry never
/// goes stale. Invariant: `last_read ≡ storage_roots[hashed(address)]` — the
/// pre-state trie mutates only in `calculate_state_root`, which never reads
/// the memo. Everything is held as words: an `Address`/`B256` field is
/// compared and copied byte-wise (`memcmp`/`memcpy` calls), words in
/// registers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LastRead {
    pub(crate) root: [u64; 4],
    pub(crate) hashed: [u64; 4],
    pub(crate) address: [u64; 3],
}

impl LastRead {
    /// Matches no address: word 2 of a real address ([`address_words`]) is
    /// below 2^32.
    pub(crate) const NONE: Self = Self {
        root: [0; 4],
        hashed: [0; 4],
        address: [u64::MAX; 3],
    };
}

pub(crate) fn hash_address(address: &Address, memo: &RefCell<AddressMemo>) -> AlignedB256 {
    let digest = hash_address_words(address_words(address), memo);
    #[cfg(test)]
    debug_assert_eq!(digest.0, keccak256(address));
    digest
}

/// [`hash_address`] from the address words alone: the miss path rebuilds the
/// 20 bytes in an 8-aligned buffer (three word stores) for the keccak instead
/// of borrowing the caller's `Address` — a reference escaping into the
/// out-of-line miss path would make every caller up the chain copy its
/// by-value `Address` byte-wise before the call.
pub(crate) fn hash_address_words(words: [u64; 3], memo: &RefCell<AddressMemo>) -> AlignedB256 {
    #[repr(C, align(8))]
    struct Buffer([[u8; 8]; 3]);
    let digest = memo.borrow_mut().get_or_insert_with(words, || {
        let buffer = Buffer(words.map(u64::to_le_bytes));
        zeth_mpt::le_words_32(keccak256(&buffer.0.as_flattened()[..20]).as_slice())
    });
    AlignedB256::from_le_words(digest)
}

pub(crate) fn hashed_post_state<'a>(
    state: impl IntoIterator<Item = (&'a Address, &'a BundleAccount)>,
    address_hashes: &RefCell<AddressMemo>,
    slot_hashes: &RefCell<SlotMemo>,
) -> HashedPostState {
    state
        .into_iter()
        .map(|(address, account)| {
            let hashed_address = hash_address(address, address_hashes).0;
            let hashed_account = account.info.as_ref().map(Into::into);
            let hashed_storage = HashedStorage::from_iter(
                account.status.was_destroyed(),
                account
                    .storage
                    .iter()
                    .map(|(slot, value)| (hash_slot(*slot, slot_hashes).0, value.present_value)),
            );
            (
                hashed_address,
                hashed_account,
                (!hashed_storage.is_empty()).then_some(hashed_storage),
            )
        })
        .collect()
}

pub(crate) fn hash_slot(slot: U256, memo: &RefCell<SlotMemo>) -> AlignedB256 {
    let digest = memo.borrow_mut().get_or_insert_with(*slot.as_limbs(), || {
        zeth_mpt::le_words_32(keccak256(B256::from(slot)).as_slice())
    });
    let digest = AlignedB256::from_le_words(digest);
    #[cfg(test)]
    debug_assert_eq!(digest.0, keccak256(B256::from(slot)));
    digest
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::KECCAK256_EMPTY;

    #[test]
    fn address_memo_matches_direct_hashes() {
        let memo = RefCell::new(AddressMemo::with_capacity(0));
        let mut rng = 0x9432_1735_abc0_ef89u64;
        let addresses: Vec<_> = (0..1024)
            .map(|_| {
                let mut bytes = [0u8; 20];
                for byte in &mut bytes {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    *byte = rng as u8;
                }
                Address::from(bytes)
            })
            .collect();
        for _ in 0..2 {
            for &address in &addresses {
                let expected = keccak256(address);
                assert_eq!(hash_address(&address, &memo).0, expected);
            }
        }
        assert_eq!(memo.borrow().len(), addresses.len());
    }

    /// Ten thousand random keys through both memos, from the minimum table
    /// size (several doublings): every digest is the keccak, repeats hit.
    #[test]
    fn memos_match_keccak_across_growth() {
        let mut rng = 0x2545_f491_4f6c_dd1du64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let mut addresses = Vec::new();
        let mut slots = Vec::new();
        for i in 0..10_000u64 {
            let mut bytes = [0u8; 20];
            bytes[..8].copy_from_slice(&next().to_le_bytes());
            bytes[8..16].copy_from_slice(&next().to_le_bytes());
            bytes[16..].copy_from_slice(&(next() as u32).to_le_bytes());
            addresses.push(Address::from(bytes));
            // half small slot numbers, half hash-like
            slots.push(if i % 2 == 0 {
                U256::from(i)
            } else {
                U256::from_limbs([next(), next(), next(), next()])
            });
        }
        let address_memo = RefCell::new(AddressMemo::with_capacity(0));
        let slot_memo = RefCell::new(SlotMemo::with_capacity(0));
        for _ in 0..2 {
            for (address, slot) in addresses.iter().zip(&slots) {
                assert_eq!(hash_address(address, &address_memo).0, keccak256(address));
                assert_eq!(hash_slot(*slot, &slot_memo).0, keccak256(B256::from(*slot)));
            }
            assert_eq!(address_memo.borrow().len(), addresses.len());
            assert_eq!(slot_memo.borrow().len(), slots.len());
        }
        assert!(address_memo.borrow().entries.len() >= 16_384);
        assert_eq!(core::mem::align_of::<AlignedB256>(), 8);
        // every source alignment of the address bytes gathers the same words
        let mut buffer = [0u8; 28];
        for offset in 0..8 {
            buffer[offset..offset + 20].copy_from_slice(addresses[0].as_slice());
            let address = Address::from_slice(&buffer[offset..offset + 20]);
            assert_eq!(
                address_words(&address),
                address_words(&addresses[0]),
                "offset={offset}"
            );
            let mut expected = [0u8; 24];
            expected[..20].copy_from_slice(addresses[0].as_slice());
            let words = address_words(&address);
            assert_eq!(words[0].to_le_bytes(), expected[..8]);
            assert_eq!(words[1].to_le_bytes(), expected[8..16]);
            assert_eq!(words[2].to_le_bytes(), expected[16..]);
        }
    }

    #[test]
    fn slot_memo_matches_direct_hashes() {
        let memo = RefCell::new(SlotMemo::with_capacity(0));
        let slots: Vec<_> = (0u64..64)
            .flat_map(|i| {
                [
                    U256::from(i),
                    U256::from_be_bytes(keccak256(i.to_be_bytes()).0),
                ]
            })
            .collect();
        for _ in 0..2 {
            for &slot in &slots {
                assert_eq!(hash_slot(slot, &memo).0, keccak256(B256::from(slot)));
            }
        }
        assert_eq!(memo.borrow().len(), slots.len());
    }

    #[test]
    fn memo_post_state_matches_from_bundle_state() {
        use reth_evm::revm::database::{states::StorageSlot, AccountStatus};
        use reth_trie_common::KeccakKeyHasher;
        use revm_state::AccountInfo;

        let address = |i: u8| Address::repeat_byte(i);
        let info = |nonce: u64| AccountInfo {
            nonce,
            balance: U256::from(nonce) * U256::from(1_000_000_007u64),
            code_hash: if nonce.is_multiple_of(2) {
                KECCAK256_EMPTY
            } else {
                keccak256([nonce as u8])
            },
            ..Default::default()
        };
        let mapping_slot = U256::from_be_bytes(keccak256(b"mapping").0);
        let storage = |slots: &[(U256, u64, u64)]| {
            slots
                .iter()
                .map(|&(slot, old, new)| {
                    (
                        slot,
                        StorageSlot::new_changed(U256::from(old), U256::from(new)),
                    )
                })
                .collect()
        };
        let accounts = [
            // changed account: read slots 0/7, plus slot 9 written without a read
            (
                address(1),
                BundleAccount::new(
                    Some(info(1)),
                    Some(info(2)),
                    storage(&[
                        (U256::ZERO, 1, 2),
                        (U256::from(7), 3, 0),
                        (U256::from(9), 0, 4),
                    ]),
                    AccountStatus::Changed,
                ),
            ),
            // created (never in the pre-state): slots never read; shares slot 0
            (
                address(2),
                BundleAccount::new(
                    None,
                    Some(info(3)),
                    storage(&[(U256::ZERO, 0, 5), (mapping_slot, 0, 6)]),
                    AccountStatus::InMemoryChange,
                ),
            ),
            // destroyed: wiped storage, no slots
            (
                address(3),
                BundleAccount::new(
                    Some(info(4)),
                    None,
                    Default::default(),
                    AccountStatus::Destroyed,
                ),
            ),
            // destroyed and recreated in the same block
            (
                address(4),
                BundleAccount::new(
                    Some(info(5)),
                    Some(info(6)),
                    storage(&[(mapping_slot, 0, 8)]),
                    AccountStatus::DestroyedChanged,
                ),
            ),
            // balance-only change
            (
                address(5),
                BundleAccount::new(
                    Some(info(7)),
                    Some(info(8)),
                    Default::default(),
                    AccountStatus::Changed,
                ),
            ),
            // touched but non-existent
            (
                address(6),
                BundleAccount::new(
                    None,
                    None,
                    Default::default(),
                    AccountStatus::LoadedNotExisting,
                ),
            ),
        ];

        // execution-time reads: every account but the created one was loaded,
        // slots 0/7 of address(1) and the mapping slot of address(4) were read
        let address_hashes = RefCell::new(AddressMemo::with_capacity(0));
        let slot_hashes = RefCell::new(SlotMemo::with_capacity(0));
        for i in [1, 3, 4, 5, 6] {
            hash_address(&address(i), &address_hashes);
        }
        for slot in [U256::ZERO, U256::from(7), mapping_slot] {
            hash_slot(slot, &slot_hashes);
        }
        assert_eq!(
            (address_hashes.borrow().len(), slot_hashes.borrow().len()),
            (5, 3)
        );

        let expected = HashedPostState::from_bundle_state::<KeccakKeyHasher>(
            accounts.iter().map(|(address, account)| (address, account)),
        );
        let got = hashed_post_state(
            accounts.iter().map(|(address, account)| (address, account)),
            &address_hashes,
            &slot_hashes,
        );
        assert_eq!(got, expected);
        assert_eq!(got.accounts.len(), 6);
        assert_eq!(got.storages.len(), 4);
        assert!(got.storages[&keccak256(address(3))].wiped);
        assert!(got.storages[&keccak256(address(4))].wiped);
        // misses were filled in: address(2) and slot 9; repeats (slot 0, the
        // mapping slot) hit the existing entries
        assert_eq!(
            (address_hashes.borrow().len(), slot_hashes.borrow().len()),
            (6, 4)
        );
    }
}
