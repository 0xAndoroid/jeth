//! Feature-gated (`premeasure`) counters for the advice-trie spec's §8.1
//! pre-measurements — native runs only, never enabled in guest builds.
//!
//! Counts: digest-map probes/hits during `resolve_digests[_zc]` (witness-entry
//! consumption), decoded map hits, and nodes re-encoded inside `memoize()`
//! (= dirty nodes at post-root, since every resolved witness node is born with
//! its cache set from the digest and only mutation clears/creates uncached
//! nodes).

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub static PROBES: AtomicU64 = AtomicU64::new(0);
pub static HITS: AtomicU64 = AtomicU64::new(0);
pub static DECODES: AtomicU64 = AtomicU64::new(0);
pub static MEMO_ENCODES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, Default)]
pub struct Snapshot {
    pub probes: u64,
    pub hits: u64,
    pub decodes: u64,
    pub memo_encodes: u64,
}

pub fn snapshot() -> Snapshot {
    Snapshot {
        probes: PROBES.load(Relaxed),
        hits: HITS.load(Relaxed),
        decodes: DECODES.load(Relaxed),
        memo_encodes: MEMO_ENCODES.load(Relaxed),
    }
}

#[inline]
pub(super) fn count(counter: &AtomicU64) {
    counter.fetch_add(1, Relaxed);
}
