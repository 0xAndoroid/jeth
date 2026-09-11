//! Advice-indexed digest resolution.
//!
//! Instead of hashing all witness nodes up front and probing a map per digest
//! (miss-dominated: most probes are boundary siblings), the prover advises the
//! witness slot index and the guest verifies the claim locally:
//!
//! - miss (`hint == 0`, boundary sibling / absent): one `ADVICE_LD` and a
//!   branch — the digest stub stays in place (panic-or-identical-output).
//! - hit: bounds check via the slice index (a lying hint panics the tracer ⇒
//!   no proof), then `keccak256(witness[i]) == digest` — the keccak is memoized
//!   per witness entry, so total reveal-class perms stay ≤ witness count
//!   (hashing is *relocated* from build time to first resolve, never
//!   multiplied).
//!
//! Advice's entire power here is selection (indices into witness order,
//! pass-stable): point at the right bytes (verified), wrong bytes (assert
//! panic), or claim absence (stub semantics). It cannot forge content.

use crate::advice::{advice_assert_eq, advice_u64};
use crate::walk::{self, NodeKind, Step};
use alloc::vec::Vec;
use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_trie::EMPTY_ROOT_HASH;
use zeth_mpt::{le_words_32, DigestResolver};

/// Digests travel as four little-endian words (`[u64; 4]`, word `i` = bytes
/// `8i..8i+8`) between the walk, the resolver memo and the storage-root
/// anchors: `B256` is align 1, so every limb extraction from it byte-expands
/// on riscv64imac; words are gathered once ([`le_words_32`]) and compared /
/// copied as whole registers.
/// Word-wise equality: a derived `[u64; N] == [u64; N]` is a `memcmp` call on
/// riscv64imac (≈70 rows for four words); this is `2N + 1` ALU ops.
#[inline(always)]
pub(crate) fn words_eq<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    let mut diff = 0;
    for i in 0..N {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub(crate) fn b256_from_le_words(words: [u64; 4]) -> B256 {
    // SAFETY: `[[u8; 8]; 4]` and `[u8; 32]` have identical layout.
    B256::new(unsafe {
        core::mem::transmute::<[[u8; 8]; 4], [u8; 32]>(words.map(u64::to_le_bytes))
    })
}

const fn le_words_const(bytes: [u8; 32]) -> [u64; 4] {
    let mut words = [0u64; 4];
    let mut i = 0;
    while i < 4 {
        let mut chunk = [0u8; 8];
        let mut j = 0;
        while j < 8 {
            chunk[j] = bytes[8 * i + j];
            j += 1;
        }
        words[i] = u64::from_le_bytes(chunk);
        i += 1;
    }
    words
}

/// [`EMPTY_ROOT_HASH`] as words.
pub(crate) const EMPTY_ROOT_WORDS: [u64; 4] = le_words_const(EMPTY_ROOT_HASH.0);

/// keccak(witness[i]) memo: 8-aligned `[u64; 4]` entries + presence bitmap —
/// NOT `Vec<Option<B256>>` (no niche ⇒ 33-byte stride, align 1 ⇒ every limb
/// load byte-expands 5–10× under Jolt's sub-word lowering).
#[derive(Debug, Clone)]
pub struct WitnessResolver {
    /// Witness state entries in witness order (refcounted `Bytes` views).
    witness: Vec<Bytes>,
    verified: Vec<[u64; 4]>,
    verified_set: Vec<u64>,
    /// Node-kind memo: 2-bit [`NodeKind`] per entry (0 = not yet validated).
    /// Walked entries get a full `Node::decode`-parity scan exactly once.
    kinds: Vec<u64>,
    /// Pass-1 / native digest→slot index. `BTreeMap` by the seed-chain rule:
    /// a pass-1-only foldhash map would perturb the global per-hasher seed
    /// chain relative to the proven ELF. Never built in the proven ELF.
    #[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
    index: alloc::collections::BTreeMap<B256, u32>,
}

impl WitnessResolver {
    /// `trusted_digests`: pre-computed witness-node keccaks delivered as Jolt
    /// TRUSTED ADVICE (the `--trusted-digests` variant). Seeds the memo up
    /// front — first-resolve hashing becomes a 4-limb compare, and the resolve
    /// path is otherwise identical to the self-verifying mode.
    pub fn new(witness_state: &[Bytes], trusted_digests: Option<&[[u8; 32]]>) -> Self {
        let n = witness_state.len();
        let mut verified = Vec::with_capacity(n);
        let mut verified_set = alloc::vec![0u64; n.div_ceil(64)];
        match trusted_digests {
            Some(digests) => {
                // One contiguous 32n-byte copy → aligned memo (word-RMW memcpy
                // override); presence = all set. Trust contract unchanged:
                // digests are verifier-attested, wrong ones panic or substitute
                // content exactly as granted. Limb byte order matches
                // `le_words_32` (little-endian words) on both sides.
                assert_eq!(digests.len(), n, "trusted digest count");
                verified.resize(n, [0u64; 4]);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        digests.as_ptr().cast::<u8>(),
                        verified.as_mut_ptr().cast::<u8>(),
                        n * 32,
                    );
                }
                verified_set.fill(u64::MAX);
            }
            None => verified.resize(n, [0u64; 4]),
        }
        Self {
            witness: witness_state.to_vec(),
            verified,
            verified_set,
            kinds: alloc::vec![0u64; n.div_ceil(32)],
            #[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
            index: witness_state
                .iter()
                .enumerate()
                .map(|(i, rlp)| (keccak256(rlp), i as u32))
                .collect(),
        }
    }

    /// Pass-1 / native body: digest → slot+1, or 0 = "not in witness".
    #[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
    #[inline]
    fn slot_impl(&self, digest: &B256) -> u64 {
        match self.index.get(digest) {
            Some(&i) => i as u64 + 1,
            None => 0,
        }
    }

    #[inline(always)]
    fn is_verified(&self, i: usize) -> bool {
        self.verified_set[i >> 6] & (1 << (i & 63)) != 0
    }

    /// Authenticate witness entry `i` as the node with digest `want` (words).
    /// Memo hit: 4 aligned loads; miss: one keccak (relocated reveal hash) +
    /// memo store. Then 4 × 1-row `VirtualAssertEQ` against the wanted words.
    #[inline(always)]
    fn verify_slot(&mut self, i: usize, want: [u64; 4]) {
        let have = if self.is_verified(i) {
            self.verified[i]
        } else {
            let digest = keccak256(&self.witness[i]);
            let limbs = le_words_32(digest.as_slice());
            self.verified[i] = limbs;
            self.verified_set[i >> 6] |= 1 << (i & 63);
            limbs
        };
        advice_assert_eq!(have[0], want[0]);
        advice_assert_eq!(have[1], want[1]);
        advice_assert_eq!(have[2], want[2]);
        advice_assert_eq!(have[3], want[3]);
    }
}

impl WitnessResolver {
    #[inline(always)]
    fn kind(&self, i: usize) -> NodeKind {
        NodeKind::from_bits(self.kinds[i >> 5] >> ((i & 31) * 2))
    }

    #[inline(always)]
    fn set_kind(&mut self, i: usize, kind: NodeKind) {
        self.kinds[i >> 5] |= (kind as u64) << ((i & 31) * 2);
    }

    /// Authenticate the witness entry advised for `digest` and ensure it has
    /// passed the well-formedness scan. Returns the entry index.
    /// Panics on a resolver miss — a walk the execution needs must resolve
    /// (same witness-incompleteness contract as the eager build) —
    /// and on malformed entries (refusal; see walk module docs).
    #[inline]
    fn authenticate_walk(&mut self, digest: [u64; 4]) -> usize {
        let hint = advice_u64!(self.slot_impl(&b256_from_le_words(digest)));
        assert!(hint != 0, "MPT: unresolved node access");
        let i = (hint - 1) as usize;
        self.verify_slot(i, digest);
        if self.kind(i) == NodeKind::Unvalidated {
            let kind = walk::validate_entry(&self.witness[i]).expect("MPT: invalid witness node");
            self.set_kind(i, kind);
        }
        i
    }

    /// Byte-walk storage read: `key` = keccak(slot), anchored at the
    /// account's `storage_root`. Returns the decoded slot value; `Ok(None)` is
    /// authenticated absence. Never materializes or mutates — the only side
    /// effect is memoization.
    pub(crate) fn walk_storage(
        &mut self,
        root: [u64; 4],
        key: &B256,
    ) -> alloy_rlp::Result<Option<U256>> {
        if words_eq(&root, &EMPTY_ROOT_WORDS) {
            // Empty trie — no advice call (from_digest parity; keccak(0x80)
            // is never a witness entry, so walking it would panic).
            return Ok(None);
        }
        let mut digest = root;
        let mut depth = 0usize;
        loop {
            let i = self.authenticate_walk(digest);
            match walk::walk_entry(&self.witness[i], self.kind(i), key, &mut depth) {
                Step::Digest(d) => digest = d,
                Step::Absent => return Ok(None),
                Step::Value(range) => {
                    return alloy_rlp::decode_exact(&self.witness[i][range]).map(Some);
                }
            }
        }
    }
}

impl DigestResolver for WitnessResolver {
    /// A miss (`hint == 0`: boundary sibling, absent) is the common answer —
    /// 9 of 10 probes on mainnet blocks — and is decided here, inlined into
    /// the caller's loop: one `ADVICE_LD` and a branch, no frame. Hits go out
    /// of line ([`Self::resolve_hit`]).
    #[inline(always)]
    fn resolve(&mut self, digest: &B256) -> Option<&Bytes> {
        let hint = advice_u64!(self.slot_impl(digest));
        if hint == 0 {
            return None;
        }
        Some(self.resolve_hit(hint, digest))
    }
}

impl WitnessResolver {
    /// [`DigestResolver::resolve`] hit: hands out a borrow of the witness
    /// entry (the decoder takes its leaf-value views with `slice_ref`); the
    /// digest words are gathered from the trie's 8-aligned stub (4 `ld`).
    #[cold]
    #[inline(never)]
    fn resolve_hit(&mut self, hint: u64, digest: &B256) -> &Bytes {
        // Slice indexing bounds-panics on a lying hint (tracer refuses ⇒ no
        // proof) — the explicit spec check_advice!(i < len) is subsumed.
        let i = (hint - 1) as usize;
        self.verify_slot(i, le_words_32(digest.as_slice()));
        &self.witness[i]
    }
}
