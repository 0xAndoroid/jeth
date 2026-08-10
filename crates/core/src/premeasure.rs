//! §8.1 pre-measurement snapshots (feature `premeasure`, native runs only).
//!
//! zeth-mpt counts digest-map probes/hits/decodes and memoize re-encodes;
//! [`crate::zeth_trie`] records a snapshot at each validation phase boundary
//! so the host can print per-phase deltas after `run-native`.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

pub struct SnapCell([AtomicU64; 4]);

impl SnapCell {
    const fn new() -> Self {
        Self([
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
        ])
    }

    pub(crate) fn record(&self) {
        let s = zeth_mpt::premeasure::snapshot();
        self.0[0].store(s.probes, Relaxed);
        self.0[1].store(s.hits, Relaxed);
        self.0[2].store(s.decodes, Relaxed);
        self.0[3].store(s.memo_encodes, Relaxed);
    }

    /// `[probes, hits, decodes, memo_encodes]` at this snapshot point.
    pub fn get(&self) -> [u64; 4] {
        [
            self.0[0].load(Relaxed),
            self.0[1].load(Relaxed),
            self.0[2].load(Relaxed),
            self.0[3].load(Relaxed),
        ]
    }
}

/// After the state trie is built from the witness (reveal done).
pub static STATE_BUILD: SnapCell = SnapCell::new();
/// At `calculate_state_root` entry (execution done; exec-phase storage builds included).
pub static EXEC_END: SnapCell = SnapCell::new();
/// After all storage tries are hashed, before the state trie hash.
pub static PRE_STATE_HASH: SnapCell = SnapCell::new();
/// After the post-state root is computed.
pub static POST_ROOT: SnapCell = SnapCell::new();
