// These constants may end up unused depending on platform support.
#[allow(unused)]
use crate::{ARBITRARY1, ARBITRARY5};

use super::{
    folded_multiply, ARBITRARY10, ARBITRARY11, ARBITRARY2, ARBITRARY6, ARBITRARY7, ARBITRARY8,
    ARBITRARY9,
};

/// Used for FixedState, and RandomState if atomics for dynamic init are unavailable.
const FIXED_GLOBAL_SEED: SharedSeed = SharedSeed {
    seeds: [
        ARBITRARY6,
        ARBITRARY7,
        ARBITRARY8,
        ARBITRARY9,
        ARBITRARY10,
        ARBITRARY11,
    ],
};

pub(crate) fn gen_per_hasher_seed() -> u64 {
    // jeth patch (advice-trie L5): fixed seed — no stack addresses, no global
    // nondeterminism chain. hashbrown iteration order must be identical across
    // the compute_advice / proven ELF pair; foldhash's address-derived seeds
    // differ between two different ELFs, and the per-hasher chain diverges as
    // soon as one pass creates a map the other doesn't. HashDoS resistance is
    // irrelevant in-guest (the adversary already controls the full input).
    folded_multiply(ARBITRARY1, ARBITRARY2)
}

/// A random seed intended to be shared by many different foldhash instances.
///
/// This seed is consumed by [`FoldHasher::with_seed`](crate::fast::FoldHasher::with_seed),
/// and [`SeedableRandomState::with_seed`](crate::fast::SeedableRandomState::with_seed).
#[derive(Clone, Debug)]
pub struct SharedSeed {
    pub(crate) seeds: [u64; 6],
}

impl SharedSeed {
    /// Returns the globally shared randomly initialized [`SharedSeed`] as used
    /// by [`RandomState`](crate::fast::RandomState).
    #[inline(always)]
    pub fn global_random() -> &'static SharedSeed {
        global::GlobalSeed::new().get()
    }

    /// Returns the globally shared fixed [`SharedSeed`] as used
    /// by [`FixedState`](crate::fast::FixedState).
    #[inline(always)]
    pub const fn global_fixed() -> &'static SharedSeed {
        &FIXED_GLOBAL_SEED
    }

    /// Generates a new [`SharedSeed`] from a single 64-bit seed.
    ///
    /// Note that this is somewhat expensive so it is suggested to re-use the
    /// [`SharedSeed`] as much as possible, using the per-hasher seed to
    /// differentiate between hash instances.
    pub const fn from_u64(seed: u64) -> Self {
        macro_rules! mix {
            ($x: expr) => {
                folded_multiply($x, ARBITRARY5)
            };
        }

        let seed_a = mix!(mix!(mix!(seed)));
        let seed_b = mix!(mix!(mix!(seed_a)));
        let seed_c = mix!(mix!(mix!(seed_b)));
        let seed_d = mix!(mix!(mix!(seed_c)));
        let seed_e = mix!(mix!(mix!(seed_d)));
        let seed_f = mix!(mix!(mix!(seed_e)));

        // Zeroes form a weak-point for the multiply-mix, and zeroes tend to be
        // a common input. So we want our global seeds that are XOR'ed with the
        // input to always be non-zero. To also ensure there is always a good spread
        // of bits, we give up 3 bits of entropy and simply force some bits on.
        const FORCED_ONES: u64 = (1 << 63) | (1 << 31) | 1;
        Self {
            seeds: [
                seed_a | FORCED_ONES,
                seed_b | FORCED_ONES,
                seed_c | FORCED_ONES,
                seed_d | FORCED_ONES,
                seed_e | FORCED_ONES,
                seed_f | FORCED_ONES,
            ],
        }
    }
}

#[cfg(target_has_atomic = "8")]
mod global {
    use super::*;
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicU8, Ordering};

    fn generate_global_seed() -> SharedSeed {
        // jeth patch (advice-trie L5): fixed global seed (upstream mixes stack/
        // fn/static addresses + time — all divergent across the two-pass ELFs).
        SharedSeed::from_u64(ARBITRARY1)
    }

    // Now all the below code purely exists to cache the above seed as
    // efficiently as possible. Even if we weren't a no_std crate and had access to
    // OnceLock, we don't want to check whether the global is set each time we
    // hash an object, so we hand-roll a global storage where type safety allows us
    // to assume the storage is initialized after construction.
    struct GlobalSeedStorage {
        state: AtomicU8,
        seed: UnsafeCell<SharedSeed>,
    }

    const UNINIT: u8 = 0;
    const LOCKED: u8 = 1;
    const INIT: u8 = 2;

    // SAFETY: we only mutate the UnsafeCells when state is in the thread-exclusive
    // LOCKED state, and only read the UnsafeCells when state is in the
    // once-achieved-eternally-preserved state INIT.
    unsafe impl Sync for GlobalSeedStorage {}

    static GLOBAL_SEED_STORAGE: GlobalSeedStorage = GlobalSeedStorage {
        state: AtomicU8::new(UNINIT),
        seed: UnsafeCell::new(SharedSeed { seeds: [0; 6] }),
    };

    /// An object representing an initialized global seed.
    ///
    /// Does not actually store the seed inside itself, it is a zero-sized type.
    /// This prevents inflating the RandomState size and in turn HashMap's size.
    #[derive(Copy, Clone, Debug)]
    pub struct GlobalSeed {
        // So we can't accidentally type GlobalSeed { } within this crate.
        _no_accidental_unsafe_init: (),
    }

    impl GlobalSeed {
        #[inline(always)]
        pub fn new() -> Self {
            if GLOBAL_SEED_STORAGE.state.load(Ordering::Acquire) != INIT {
                Self::init_slow()
            }
            Self {
                _no_accidental_unsafe_init: (),
            }
        }

        #[cold]
        #[inline(never)]
        fn init_slow() {
            // Generate seed outside of critical section.
            let seed = generate_global_seed();

            loop {
                match GLOBAL_SEED_STORAGE.state.compare_exchange_weak(
                    UNINIT,
                    LOCKED,
                    Ordering::Acquire,
                    Ordering::Acquire,
                ) {
                    Ok(_) => unsafe {
                        // SAFETY: we just acquired an exclusive lock.
                        *GLOBAL_SEED_STORAGE.seed.get() = seed;
                        GLOBAL_SEED_STORAGE.state.store(INIT, Ordering::Release);
                        return;
                    },

                    Err(INIT) => return,

                    // Yes, it's a spin loop. We need to support no_std (so no easy
                    // access to proper locks), this is a one-time-per-program
                    // initialization, and the critical section is only a few
                    // store instructions, so it'll be fine.
                    _ => core::hint::spin_loop(),
                }
            }
        }

        #[inline(always)]
        pub fn get(self) -> &'static SharedSeed {
            // SAFETY: our constructor ensured we are in the INIT state and thus
            // this raw read does not race with any write.
            unsafe { &*GLOBAL_SEED_STORAGE.seed.get() }
        }
    }
}

#[cfg(not(target_has_atomic = "8"))]
mod global {
    use super::*;

    #[derive(Copy, Clone, Debug)]
    pub struct GlobalSeed {}

    impl GlobalSeed {
        #[inline(always)]
        pub fn new() -> Self {
            Self {}
        }

        #[inline(always)]
        pub fn get(self) -> &'static SharedSeed {
            &super::FIXED_GLOBAL_SEED
        }
    }
}

pub(crate) use global::GlobalSeed;
