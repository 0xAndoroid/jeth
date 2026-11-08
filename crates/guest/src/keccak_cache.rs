//! Cache short Keccak inputs using word-aligned keys. Every hit checks the full
//! input; the inexpensive index hash affects eviction, never the returned digest.

use core::hash::{BuildHasherDefault, Hash, Hasher};
use fixed_cache::{Bucket, Cache, CacheConfig};

const ENTRIES: usize = 64;

#[derive(Clone, Copy)]
struct Key {
    words: [u64; 8],
    len: u64,
}

impl Key {
    fn new(input: &[u8]) -> Self {
        debug_assert!(input.len() == 32 || input.len() == 64);
        let mut key = Self {
            words: [0; 8],
            len: input.len() as u64,
        };
        if input.as_ptr() as usize & 7 == 0 {
            for (i, word) in key.words[..input.len() / 8].iter_mut().enumerate() {
                // SAFETY: the branch checks alignment and each load is within input.
                *word = unsafe { input.as_ptr().add(i * 8).cast::<u64>().read() };
            }
        } else {
            for (i, word) in key.words[..input.len() / 8].iter_mut().enumerate() {
                // SAFETY: each complete word is within input; alignment is not required.
                *word = unsafe { input.as_ptr().add(i * 8).cast::<u64>().read_unaligned() };
            }
        }
        key
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        let mut difference = self.len ^ other.len;
        for i in 0..8 {
            difference |= self.words[i] ^ other.words[i];
        }
        difference == 0
    }
}
impl Eq for Key {}
impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut folded = self.len;
        for word in self.words {
            folded ^= word;
        }
        state.write_u64(folded);
    }
}

#[derive(Default)]
struct IndexHasher(u64);
impl Hasher for IndexHasher {
    fn finish(&self) -> u64 {
        self.0.wrapping_mul(0x9e3779b97f4a7c15).rotate_left(6)
    }
    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
    fn write(&mut self, _: &[u8]) {
        unreachable!("Key hashes one u64");
    }
}

struct Config;
impl CacheConfig for Config {
    const STATS: bool = false;
    const EPOCHS: bool = false;
}
type SmallCache = Cache<Key, [u64; 4], BuildHasherDefault<IndexHasher>, Config>;
static BUCKETS: [Bucket<(Key, [u64; 4])>; ENTRIES] = [const { Bucket::new() }; ENTRIES];
static CACHE: SmallCache = SmallCache::new_static(&BUCKETS, BuildHasherDefault::new());

pub fn compute(input: &[u8], direct: impl FnOnce(&[u8]) -> [u64; 4]) -> [u64; 4] {
    compute_with(&CACHE, input, direct)
}

fn compute_with(
    cache: &SmallCache,
    input: &[u8],
    direct: impl FnOnce(&[u8]) -> [u64; 4],
) -> [u64; 4] {
    if input.len() != 32 && input.len() != 64 {
        return direct(input);
    }
    let key = Key::new(input);
    cache.get_or_insert_with_ref(&key, |_| direct(input), |key| *key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::hash::BuildHasher;
    use sha3::{Digest, Keccak256};
    fn hash(input: &[u8]) -> [u64; 4] {
        let digest: [u8; 32] = Keccak256::digest(input).into();
        // Keep the digest's byte representation, with word alignment for the cache.
        unsafe { core::mem::transmute::<[u8; 32], [u64; 4]>(digest) }
    }
    fn cache() -> SmallCache {
        let buckets = Box::leak(Box::new([const { Bucket::new() }; ENTRIES]));
        SmallCache::new_static(buckets, BuildHasherDefault::new())
    }
    #[test]
    fn all_lengths_alignments_and_repeated_inputs_match_keccak() {
        let cache = cache();
        for len in 0..=160 {
            for offset in 0..8 {
                let mut allocation = vec![0u8; len + offset];
                for (i, byte) in allocation.iter_mut().enumerate() {
                    *byte = (i * 71 + len * 13) as u8;
                }
                let input = &allocation[offset..];
                let expected = hash(input);
                assert_eq!(compute_with(&cache, input, hash), expected);
                assert_eq!(compute_with(&cache, input, hash), expected);
            }
        }
    }
    #[test]
    fn full_hash_collisions_evict_instead_of_returning_another_digest() {
        let cache = cache();
        let mut a = [0u8; 64];
        let mut b = a;
        a[..8].copy_from_slice(&1u64.to_ne_bytes());
        b[8..16].copy_from_slice(&1u64.to_ne_bytes());
        assert_eq!(
            BuildHasherDefault::<IndexHasher>::new().hash_one(Key::new(&a)),
            BuildHasherDefault::<IndexHasher>::new().hash_one(Key::new(&b))
        );
        assert_ne!(hash(&a), hash(&b));
        for input in [&a[..], &b[..], &a[..], &a[..], &b[..]] {
            assert_eq!(compute_with(&cache, input, hash), hash(input));
        }
    }
    #[test]
    fn lengths_are_part_of_the_key_and_zero_tag_is_safe() {
        let cache = cache();
        let zeros = [0u8; 64];
        for input in [&zeros[..32], &zeros[..64], &zeros[..32]] {
            assert_eq!(compute_with(&cache, input, hash), hash(input));
        }
        for len in [32, 64] {
            let mut input = vec![0u8; len];
            input[..8].copy_from_slice(&(len as u64).to_ne_bytes());
            assert_eq!(
                BuildHasherDefault::<IndexHasher>::new().hash_one(Key::new(&input)),
                0
            );
            assert_eq!(compute_with(&cache, &input, hash), hash(&input));
        }
    }
    #[test]
    fn repeated_hit_computes_only_once() {
        let cache = cache();
        let a = [19u8; 32];
        let mut count = 0;
        for _ in 0..3 {
            assert_eq!(
                compute_with(&cache, &a, |x| {
                    count += 1;
                    hash(x)
                }),
                hash(&a)
            );
        }
        assert_eq!(count, 1);
    }
}
