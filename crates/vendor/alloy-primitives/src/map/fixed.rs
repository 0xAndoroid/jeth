// jeth patch (vendored alloy-primitives 1.6.1, guest only): `write_bytes_unrolled` reads its
// 8-/4-byte key chunks with a riscv64 containing-word gather instead of `from_ne_bytes` on an
// align-1 array (8 `lbu` + shifts per word on the Jolt guest); see `gather` at the bottom.
use super::*;
use crate::{Address, B256, FixedBytes, Selector, U256};
use cfg_if::cfg_if;
use core::{
    fmt,
    hash::{BuildHasher, Hasher},
};

/// [`HashMap`] optimized for hashing [fixed-size byte arrays](FixedBytes).
pub type FbMap<const N: usize, V> = HashMap<FixedBytes<N>, V, FbBuildHasher<N>>;
#[doc(hidden)]
pub type FbHashMap<const N: usize, V> = FbMap<N, V>;
/// [`HashSet`] optimized for hashing [fixed-size byte arrays](FixedBytes).
pub type FbSet<const N: usize> = HashSet<FixedBytes<N>, FbBuildHasher<N>>;
#[doc(hidden)]
pub type FbHashSet<const N: usize> = FbSet<N>;

cfg_if! {
    if #[cfg(feature = "map-indexmap")] {
        /// [`IndexMap`] optimized for hashing [fixed-size byte arrays](FixedBytes).
        pub type FbIndexMap<const N: usize, V> =
            indexmap::IndexMap<FixedBytes<N>, V, FbBuildHasher<N>>;
        /// [`IndexSet`] optimized for hashing [fixed-size byte arrays](FixedBytes).
        pub type FbIndexSet<const N: usize> =
            indexmap::IndexSet<FixedBytes<N>, FbBuildHasher<N>>;
    }
}

macro_rules! fb_alias_maps {
    ($($ty:ident < $n:literal >),* $(,)?) => { paste::paste! {
        $(
            #[doc = concat!("[`HashMap`] optimized for hashing [`", stringify!($ty), "`].")]
            pub type [<$ty Map>]<V> = HashMap<$ty, V, FbBuildHasher<$n>>;
            #[doc(hidden)]
            pub type [<$ty HashMap>]<V> = [<$ty Map>]<V>;
            #[doc = concat!("[`HashSet`] optimized for hashing [`", stringify!($ty), "`].")]
            pub type [<$ty Set>] = HashSet<$ty, FbBuildHasher<$n>>;
            #[doc(hidden)]
            pub type [<$ty HashSet>] = [<$ty Set>];

            cfg_if! {
                if #[cfg(feature = "map-indexmap")] {
                    #[doc = concat!("[`IndexMap`] optimized for hashing [`", stringify!($ty), "`].")]
                    pub type [<$ty IndexMap>]<V> = IndexMap<$ty, V, FbBuildHasher<$n>>;
                    #[doc = concat!("[`IndexSet`] optimized for hashing [`", stringify!($ty), "`].")]
                    pub type [<$ty IndexSet>] = IndexSet<$ty, FbBuildHasher<$n>>;
                }
            }
        )*
    } };
}

fb_alias_maps!(Selector<4>, Address<20>, B256<32>, U256<32>);

type FbBuildHasherInner = foldhash::fast::RandomState;
type FbHasherInner = foldhash::fast::FoldHasher<'static>;

/// [`BuildHasher`] optimized for hashing [fixed-size byte arrays](FixedBytes).
///
/// **NOTE:** this hasher accepts only `N`-length byte arrays! It is invalid to hash anything else.
#[derive(Clone, Default)]
pub struct FbBuildHasher<const N: usize> {
    inner: FbBuildHasherInner,
    _marker: core::marker::PhantomData<[(); N]>,
}

impl<const N: usize> fmt::Debug for FbBuildHasher<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FbBuildHasher").finish_non_exhaustive()
    }
}

impl<const N: usize> BuildHasher for FbBuildHasher<N> {
    type Hasher = FbHasher<N>;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        FbHasher { inner: self.inner.build_hasher(), _marker: core::marker::PhantomData }
    }
}

/// [`Hasher`] optimized for hashing [fixed-size byte arrays](FixedBytes).
///
/// **NOTE:** this hasher accepts only `N`-length byte arrays! It is invalid to hash anything else.
#[derive(Clone)]
pub struct FbHasher<const N: usize> {
    inner: FbHasherInner,
    _marker: core::marker::PhantomData<[(); N]>,
}

impl<const N: usize> Default for FbHasher<N> {
    #[inline]
    fn default() -> Self {
        Self {
            inner: FbBuildHasherInner::default().build_hasher(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<const N: usize> fmt::Debug for FbHasher<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FbHasher").finish_non_exhaustive()
    }
}

impl<const N: usize> Hasher for FbHasher<N> {
    #[inline]
    fn finish(&self) -> u64 {
        self.inner.finish()
    }

    // jeth patch: `inline(always)` (upstream `inline`) — with the gather below the body
    // grew past LLVM's threshold and `FbHasher<32>::write` went out of line (+1.7M rows on
    // block 25905781); inlined, known-aligned callers fold the gather to plain `ld`s.
    #[inline(always)]
    fn write(&mut self, bytes: &[u8]) {
        // SAFETY: Precondition.
        unsafe { core::hint::assert_unchecked(bytes.len() == N) };
        // Avoid slice overhead for short fixed-size inputs.
        if N > 32 {
            self.inner.write(bytes);
        } else {
            write_bytes_unrolled(&mut self.inner, bytes);
        }
    }

    // We can just skip hashing the length prefix entirely since we know it's always `<=N`.
    // Not always `=N`, because arrays like `[T; M]` are hashed as `[u8; N=M*size_of::<T>()]` for a
    // few primitive `T` types, like integers.

    // `write_length_prefix` calls `write_usize` by default.
    #[cfg(not(feature = "nightly"))]
    #[inline]
    fn write_usize(&mut self, i: usize) {
        debug_assert!(i <= N, "{i} > {N}")
    }

    #[cfg(feature = "nightly")]
    #[inline]
    fn write_length_prefix(&mut self, len: usize) {
        debug_assert!(len <= N, "{len} > {N}")
    }
}

#[inline(always)]
fn write_bytes_unrolled(hasher: &mut FbHasherInner, mut bytes: &[u8]) {
    // jeth patch: gather only keys of at least one word (see `gather`).
    let gather = bytes.len() >= 8;
    while let Some((chunk, rest)) = bytes.split_first_chunk() {
        hasher.write_usize(read_ne_usize(chunk));
        bytes = rest;
    }
    if usize::BITS > 64 {
        if let Some((chunk, rest)) = bytes.split_first_chunk() {
            hasher.write_u64(u64::from_ne_bytes(*chunk));
            bytes = rest;
        }
    }
    if usize::BITS > 32 {
        if let Some((chunk, rest)) = bytes.split_first_chunk() {
            hasher.write_u32(if gather { read_ne_u32(chunk) } else { u32::from_ne_bytes(*chunk) });
            bytes = rest;
        }
    }
    if usize::BITS > 16 {
        if let Some((chunk, rest)) = bytes.split_first_chunk() {
            hasher.write_u16(u16::from_ne_bytes(*chunk));
            bytes = rest;
        }
    }
    if usize::BITS > 8 {
        if let Some((chunk, rest)) = bytes.split_first_chunk() {
            hasher.write_u8(u8::from_ne_bytes(*chunk));
            bytes = rest;
        }
    }

    debug_assert!(bytes.is_empty());
}

/// `usize::from_ne_bytes(*chunk)`, read through the containing-word gather on the guest.
// Not `const`: the riscv64 branch is a volatile load (crate lint `missing_const_for_fn`).
#[allow(clippy::missing_const_for_fn)]
#[inline(always)]
fn read_ne_usize(chunk: &[u8; core::mem::size_of::<usize>()]) -> usize {
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: `chunk` is a live 8-byte array (usize is 8 bytes on riscv64).
        unsafe { gather::load_le(chunk.as_ptr(), 8) as usize }
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        usize::from_ne_bytes(*chunk)
    }
}

/// `u32::from_ne_bytes(*chunk)`, read through the containing-word gather on the guest.
// Not `const`: the riscv64 branch is a volatile load (crate lint `missing_const_for_fn`).
#[allow(clippy::missing_const_for_fn)]
#[inline(always)]
fn read_ne_u32(chunk: &[u8; 4]) -> u32 {
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: `chunk` is a live 4-byte array.
        unsafe { gather::load_le(chunk.as_ptr(), 4) as u32 }
    }
    #[cfg(not(target_arch = "riscv64"))]
    {
        u32::from_ne_bytes(*chunk)
    }
}

/// jeth patch: containing-word loads for the riscv64 Jolt guest (same helper as the
/// vendored foldhash's `gather`).
///
/// `from_ne_bytes` on an align-1 `[u8; 8]` lowers to 8 `lbu` + 14 shift/or on riscv64imac
/// (no unaligned loads), and Jolt expands every `lbu` into a multi-row virtual sequence:
/// about 46 trace rows per 8-byte word of key material. Gathering the bytes from the one
/// or two aligned words that contain them costs 1-2 `ld` + 3 ALU ops instead, and yields
/// exactly the bytes the byte-wise read would (native = little endian on the guest).
///
/// Soundness of the over-read: see the module comment of the guest's
/// `crates/guest/src/mem.rs`. Jolt guest RAM is one flat, word-granular address space
/// whose regions all start 8-aligned, so the aligned word holding a live byte is always
/// inside mapped memory, and only words containing at least one live byte of the caller's
/// range are loaded. The loads are volatile, but once inlined LLVM still sees the key's
/// allocation and assumes an 8-byte access never touches an object smaller than 8 bytes: it
/// deletes the stores filling such a key (`FbHasher<4>` on a stack key hashed stale stack,
/// rustc 1.95 riscv64), so `write_bytes_unrolled` gathers only keys of >= 8 bytes. Compiled
/// for the guest target and for the host unit test only; native builds keep the upstream
/// reads.
#[cfg(any(target_arch = "riscv64", test))]
mod gather {
    /// Read the `n` (4 or 8) bytes at `p` into the low bytes of a `u64`, little-endian,
    /// using only aligned word loads of words that contain live bytes of `p..p + n`.
    /// Bits above `8 * n` are unspecified.
    ///
    /// # Safety
    /// `p..p + n` must be readable, and the aligned words containing that range must be
    /// mapped (true on the Jolt guest, see the module comment; the host test provides an
    /// aligned buffer around the range). The allocation holding `p..p + n` must be at least
    /// 8 bytes (see the module comment).
    #[inline(always)]
    pub(super) unsafe fn load_le(p: *const u8, n: usize) -> u64 {
        debug_assert!(n == 4 || n == 8);
        let addr = p as usize;
        let k = addr & 7;
        let a = (addr & !7) as *const u64;
        // SAFETY: `a` is the aligned word containing byte `p`, a live byte of the caller's
        // range (precondition), hence mapped.
        let w0 = unsafe { core::ptr::read_volatile(a) };
        let s = (k * 8) as u32;
        if k + n <= 8 {
            return w0 >> s;
        }
        // SAFETY: k + n > 8, so `p..p + n` spills into the next aligned word, which
        // therefore holds live bytes of the range and is mapped.
        let w1 = unsafe { core::ptr::read_volatile(a.add(1)) };
        (w0 >> s) | (w1 << (64 - s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_zero<const N: usize>() -> u64 {
        FbBuildHasher::<N>::default().hash_one(&FixedBytes::<N>::ZERO)
    }

    /// jeth patch: the gather must reproduce the byte-wise read for every source
    /// alignment (8- and 4-byte reads at all 8 offsets inside an aligned 32-byte window).
    #[test]
    fn gather_matches_from_ne_bytes() {
        #[repr(align(8))]
        struct Aligned([u8; 32]);
        let mut buf = Aligned([0; 32]);
        for (i, b) in buf.0.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x9d) ^ 0x5a;
        }
        for base in [0usize, 8, 16] {
            for off in 0..8 {
                let at = base + off;
                let p = unsafe { buf.0.as_ptr().add(at) };
                let want8 = u64::from_ne_bytes(buf.0[at..at + 8].try_into().unwrap());
                let want4 = u32::from_ne_bytes(buf.0[at..at + 4].try_into().unwrap());
                assert_eq!(unsafe { gather::load_le(p, 8) }, want8, "u64 at {at}");
                assert_eq!(unsafe { gather::load_le(p, 4) } as u32, want4, "u32 at {at}");
            }
        }
    }

    #[test]
    fn fb_hasher() {
        // Just by running it once we test that it compiles and that debug assertions are correct.
        ruint::const_for!(N in [ 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
                                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                                32, 47, 48, 49, 63, 64, 127, 128, 256, 512, 1024, 2048, 4096] {
            let _ = hash_zero::<N>();
        });
    }

    #[test]
    fn map() {
        let mut map = AddressHashMap::<bool>::default();
        map.insert(Address::ZERO, true);
        assert_eq!(map.get(&Address::ZERO), Some(&true));
        assert_eq!(map.get(&Address::with_last_byte(1)), None);

        let map2 = map.clone();
        assert_eq!(map.len(), map2.len());
        assert_eq!(map.len(), 1);
        assert_eq!(map2.get(&Address::ZERO), Some(&true));
        assert_eq!(map2.get(&Address::with_last_byte(1)), None);
    }

    #[test]
    fn u256_map() {
        let mut map = U256Map::default();
        map.insert(U256::ZERO, true);
        assert_eq!(map.get(&U256::ZERO), Some(&true));
        assert_eq!(map.get(&U256::ONE), None);

        let map2 = map.clone();
        assert_eq!(map.len(), map2.len());
        assert_eq!(map.len(), 1);
        assert_eq!(map2.get(&U256::ZERO), Some(&true));
        assert_eq!(map2.get(&U256::ONE), None);
    }
}
