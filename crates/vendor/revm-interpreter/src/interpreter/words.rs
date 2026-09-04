//! Word-wise big-endian 32-byte transfers on byte buffers.
//!
//! On the Jolt RV64IMAC target every byte load expands to a 4-row virtual
//! sequence and every byte store to an 8-row one, while naturally aligned
//! `LD`/`SD` are single rows. `U256::try_from_be_slice` / `to_be_bytes` on
//! unaligned EVM memory therefore degrade to per-byte loops (~150+ rows per
//! 32-byte word). These helpers move whole doublewords instead: aligned
//! pointers use four `LD`/`SD` + `swap_bytes`, unaligned ones read/write the
//! five covering aligned doublewords with shift-combine.

use primitives::U256;

/// Reads the 32-byte big-endian word at `data[offset..offset + 32]` using
/// aligned u64 loads. Returns `None` when the five covering doublewords are
/// not fully inside `data` (caller falls back to the byte-slice path).
///
/// # Panics
///
/// Debug-asserts `offset + 32 <= data.len()`.
#[inline]
pub(crate) fn read_u256_be(data: &[u8], offset: usize) -> Option<U256> {
    debug_assert!(offset + 32 <= data.len());
    let p = data[offset..].as_ptr();
    let s = p as usize & 7;
    if s == 0 {
        // SAFETY: p is 8-aligned and bytes [offset, offset+32) are in bounds.
        let limbs = unsafe {
            let w = p.cast::<u64>();
            [
                (*w.add(3)).swap_bytes(),
                (*w.add(2)).swap_bytes(),
                (*w.add(1)).swap_bytes(),
                (*w).swap_bytes(),
            ]
        };
        return Some(U256::from_limbs(limbs));
    }
    // Five aligned doublewords cover [offset - s, offset - s + 40); all their
    // bytes must be inside `data`.
    if offset < s || offset + 40 - s > data.len() {
        return None;
    }
    let sh = (s * 8) as u32;
    let inv = 64 - sh;
    // SAFETY: `a` is 8-aligned, `offset >= s` keeps it inside `data`, and the
    // bounds check above keeps all five doublewords inside `data`.
    unsafe {
        let a = p.sub(s).cast::<u64>();
        let w0 = *a;
        let w1 = *a.add(1);
        let w2 = *a.add(2);
        let w3 = *a.add(3);
        let w4 = *a.add(4);
        // Little-endian target: `l0` is the LE u64 of bytes [p, p+8), i.e. the
        // most significant 8 big-endian bytes.
        let l0 = (w0 >> sh) | (w1 << inv);
        let l1 = (w1 >> sh) | (w2 << inv);
        let l2 = (w2 >> sh) | (w3 << inv);
        let l3 = (w3 >> sh) | (w4 << inv);
        Some(U256::from_limbs([
            l3.swap_bytes(),
            l2.swap_bytes(),
            l1.swap_bytes(),
            l0.swap_bytes(),
        ]))
    }
}

/// Writes `value` as a 32-byte big-endian word at `data[offset..offset + 32]`
/// using aligned u64 stores. Returns `false` when the five covering
/// doublewords are not fully inside `data` (caller falls back to the
/// byte-slice path).
///
/// # Panics
///
/// Debug-asserts `offset + 32 <= data.len()`.
#[inline]
pub(crate) fn write_u256_be(data: &mut [u8], offset: usize, value: &U256) -> bool {
    debug_assert!(offset + 32 <= data.len());
    let p = unsafe { data.as_mut_ptr().add(offset) };
    let s = p as usize & 7;
    let limbs = value.as_limbs();
    // `v0` holds the most significant 8 big-endian bytes as the LE u64 to be
    // stored at the lowest address.
    let v0 = limbs[3].swap_bytes();
    let v1 = limbs[2].swap_bytes();
    let v2 = limbs[1].swap_bytes();
    let v3 = limbs[0].swap_bytes();
    if s == 0 {
        // SAFETY: p is 8-aligned and bytes [offset, offset+32) are in bounds.
        unsafe {
            let w = p.cast::<u64>();
            *w = v0;
            *w.add(1) = v1;
            *w.add(2) = v2;
            *w.add(3) = v3;
        }
        return true;
    }
    if offset < s || offset + 40 - s > data.len() {
        return false;
    }
    let sh = (s * 8) as u32;
    let inv = 64 - sh;
    let keep = (1u64 << sh) - 1;
    // SAFETY: as in `read_u256_be`; the first and last doublewords are
    // read-modify-written to preserve their out-of-range bytes.
    unsafe {
        let a = p.sub(s).cast::<u64>();
        *a = (*a & keep) | (v0 << sh);
        *a.add(1) = (v0 >> inv) | (v1 << sh);
        *a.add(2) = (v1 >> inv) | (v2 << sh);
        *a.add(3) = (v2 >> inv) | (v3 << sh);
        *a.add(4) = (*a.add(4) & !keep) | (v3 >> inv);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_write_all_alignments() {
        let value = U256::from_be_bytes::<32>(core::array::from_fn(|i| (i as u8) * 7 + 1));
        for pad in 0..8usize {
            let mut buf = vec![0xAAu8; 64];
            if write_u256_be(&mut buf, pad + 8, &value) {
                assert_eq!(&buf[pad + 8..pad + 40], &value.to_be_bytes::<32>());
                // Neighbours untouched.
                assert!(buf[..pad + 8].iter().all(|&b| b == 0xAA));
                assert!(buf[pad + 40..].iter().all(|&b| b == 0xAA));
            }
            buf.fill(0xAA);
            buf[pad + 8..pad + 40].copy_from_slice(&value.to_be_bytes::<32>());
            if let Some(read) = read_u256_be(&buf, pad + 8) {
                assert_eq!(read, value);
            }
        }
    }

    #[test]
    fn read_write_slice_edges() {
        let value = U256::from_be_bytes::<32>(core::array::from_fn(|i| 255 - i as u8));
        let mut buf = vec![0u8; 32];
        if write_u256_be(&mut buf, 0, &value) {
            assert_eq!(&buf[..], &value.to_be_bytes::<32>());
        }
        buf.copy_from_slice(&value.to_be_bytes::<32>());
        if let Some(read) = read_u256_be(&buf, 0) {
            assert_eq!(read, value);
        }
    }
}
