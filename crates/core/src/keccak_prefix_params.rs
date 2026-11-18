//! Parameters shared by the guest cache and its native hint planner.
pub const RATE: usize = 136;
pub const MAX_DEPTH: usize = 3;
pub const MAX_ENTRIES: usize = 65_536;
pub const MAX_INPUT_LEN: usize = 4 * RATE;
