//! Advice-indexed digest resolution (advice-trie Phase 1a).
//!
//! Replaces the `rlp_by_digest` map: instead of hashing all witness nodes up
//! front and probing a foldhash `IndexMap` per digest (~90–320 rows/probe,
//! 9:1 miss-dominated, plus the map build), the prover advises the witness
//! slot index and the guest verifies the claim locally:
//!
//! - miss (`hint == 0`, boundary sibling / absent): 1-row `ADVICE_LD` + a
//!   branch — the digest stub stays in place (L3: panic-or-identical-output).
//! - hit: bounds check via the slice index (a lying hint panics the tracer ⇒
//!   no proof), then `keccak256(witness[i]) == digest` — the keccak is memoized
//!   per witness entry, so total reveal-class perms stay ≤ witness count (L1:
//!   hashing is *relocated* build-time → first-resolve, never multiplied).
//!
//! Advice's entire power here is selection (L4: indices into witness order,
//! pass-stable): point at the right bytes (verified), wrong bytes (assert
//! panic), or claim absence (stub semantics). It cannot forge content.

use crate::advice::{advice_assert_eq, advice_u64};
use crate::walk::{self, NodeKind, Step};
use alloc::vec::Vec;
use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_trie::EMPTY_ROOT_HASH;
use zeth_mpt::DigestResolver;

/// keccak(witness[i]) memo: 8-aligned `[u64; 4]` entries + presence bitmap —
/// NOT `Vec<Option<B256>>` (no niche ⇒ 33-byte stride, align 1 ⇒ every limb
/// load byte-expands 5–10× under Jolt's sub-word lowering).
#[derive(Debug, Clone)]
pub struct WitnessResolver {
    /// Witness state entries in witness order (refcounted `Bytes` views).
    witness: Vec<Bytes>,
    verified: Vec<[u64; 4]>,
    verified_set: Vec<u64>,
    /// INV-W6 memo: 2-bit [`NodeKind`] per entry (0 = not yet validated).
    /// Walked entries get a full `Node::decode`-parity scan exactly once.
    kinds: Vec<u64>,
    /// Pass-1 / native digest→slot index. `BTreeMap` by the L5 seed-chain rule:
    /// a pass-1-only foldhash map would perturb the global per-hasher seed
    /// chain relative to the proven ELF. Never built in the proven ELF.
    #[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
    index: alloc::collections::BTreeMap<B256, u32>,
}

#[inline(always)]
fn limbs_of(digest: &B256) -> [u64; 4] {
    // `B256` is align-1; unaligned u64 extraction byte-expands on riscv64imac.
    // Only paid on hits (~10% of probes) — misses never touch the digest.
    let p = digest.as_ptr().cast::<u64>();
    unsafe {
        [
            p.read_unaligned(),
            p.add(1).read_unaligned(),
            p.add(2).read_unaligned(),
            p.add(3).read_unaligned(),
        ]
    }
}

impl WitnessResolver {
    /// `trusted_digests`: pre-computed witness-node keccaks delivered as Jolt
    /// TRUSTED ADVICE (the `--trusted-digests` variant). Seeds the memo up
    /// front — first-resolve hashing becomes a 4-limb compare, and the resolve
    /// path is otherwise identical to the self-verifying mode (§7).
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
                // `limbs_of` (raw LE reads) on both sides.
                debug_assert_eq!(digests.len(), n);
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

    /// Authenticate witness entry `i` as the node with digest `want`.
    /// Memo hit: 4 aligned loads; miss: one keccak (relocated reveal hash) +
    /// memo store. Then 4 × 1-row `VirtualAssertEQ` against the wanted limbs.
    #[inline(always)]
    fn verify_slot(&mut self, i: usize, want: &B256) {
        let have = if self.is_verified(i) {
            self.verified[i]
        } else {
            let digest = keccak256(&self.witness[i]);
            let limbs = limbs_of(&digest);
            self.verified[i] = limbs;
            self.verified_set[i >> 6] |= 1 << (i & 63);
            limbs
        };
        let want = limbs_of(want);
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
    /// passed the INV-W6 well-formedness scan. Returns the entry index.
    /// Panics on a resolver miss — a walk the execution needs must resolve
    /// (INV-W3, same witness-incompleteness contract as the eager build) —
    /// and on malformed entries (refusal; see walk module docs).
    #[inline]
    fn authenticate_walk(&mut self, digest: &B256) -> usize {
        let hint = advice_u64!(self.slot_impl(digest));
        assert!(hint != 0, "MPT: unresolved node access");
        let i = (hint - 1) as usize;
        self.verify_slot(i, digest);
        if self.kind(i) == NodeKind::Unvalidated {
            let kind = walk::validate_entry(&self.witness[i]).expect("MPT: invalid witness node");
            self.set_kind(i, kind);
        }
        i
    }

    /// §4.2 byte-walk storage read: `key` = keccak(slot), anchored at the
    /// account's `storage_root`. Returns the decoded slot value; `Ok(None)` is
    /// authenticated absence. Never materializes or mutates — the only side
    /// effect is memoization.
    pub(crate) fn walk_storage(
        &mut self,
        root: &B256,
        key: &B256,
    ) -> alloy_rlp::Result<Option<U256>> {
        if *root == EMPTY_ROOT_HASH {
            // Empty trie — no advice call (from_digest parity; keccak(0x80)
            // is never a witness entry, so walking it would panic).
            return Ok(None);
        }
        let mut digest = *root;
        let mut depth = 0usize;
        loop {
            let i = self.authenticate_walk(&digest);
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
    fn resolve(&mut self, digest: &B256) -> Option<Bytes> {
        let hint = advice_u64!(self.slot_impl(digest));
        if hint == 0 {
            return None;
        }
        // Slice indexing bounds-panics on a lying hint (tracer refuses ⇒ no
        // proof) — the explicit spec check_advice!(i < len) is subsumed.
        let i = (hint - 1) as usize;
        self.verify_slot(i, digest);
        Some(self.witness[i].clone())
    }
}
