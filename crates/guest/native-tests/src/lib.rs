//! Compiles the guest shims natively so their differential tests run.
//! See `Cargo.toml` for the command.
#![allow(dead_code)]

#[path = "../../src/keccak.rs"]
mod keccak;
#[path = "../../src/mem.rs"]
mod mem;

#[path = "../../src/keccak_cache.rs"]
mod keccak_cache;

#[cfg(test)]
mod integration_tests {
    use super::{keccak, keccak_cache};
    use sha3::{Digest, Keccak256};

    #[test]
    fn cached_driver_preserves_digest_and_surrounding_bytes_at_every_alignment() {
        for len in [32usize, 64] {
            for input_offset in 0..8 {
                let mut input = [0u64; 10];
                let bytes =
                    unsafe { core::slice::from_raw_parts_mut(input.as_mut_ptr().cast::<u8>(), 80) };
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = (i * 71 + input_offset * 13 + len) as u8;
                }
                let input = &bytes[8 + input_offset..8 + input_offset + len];
                let expected: [u8; 32] = Keccak256::digest(input).into();
                for output_offset in 0..8 {
                    for _ in 0..2 {
                        let mut output = [0xa5a5a5a5a5a5a5a5u64; 7];
                        let start = 8 + output_offset;
                        let digest = keccak_cache::compute(input, |input| {
                            let mut digest = [0u64; 4];
                            unsafe {
                                keccak::keccak256_into(
                                    input.as_ptr(),
                                    input.len(),
                                    digest.as_mut_ptr().cast(),
                                );
                            }
                            digest
                        });
                        unsafe {
                            keccak::store_digest(
                                digest.as_ptr(),
                                output.as_mut_ptr().cast::<u8>().add(start),
                            );
                        }
                        let actual = unsafe {
                            core::slice::from_raw_parts(output.as_ptr().cast::<u8>(), 56)
                        };
                        assert_eq!(&actual[start..start + 32], &expected);
                        assert!(actual[..start]
                            .iter()
                            .chain(&actual[start + 32..])
                            .all(|b| *b == 0xa5));
                    }
                }
            }
        }
    }
    #[test]
    fn cached_driver_allows_output_to_overlap_input() {
        for len in [32usize, 64] {
            for output_offset in 0..72 {
                for _ in 0..2 {
                    let mut storage = [0u64; 14];
                    let bytes = unsafe {
                        core::slice::from_raw_parts_mut(storage.as_mut_ptr().cast::<u8>(), 112)
                    };
                    for (i, b) in bytes.iter_mut().enumerate() {
                        *b = (i * 29 + len) as u8;
                    }
                    let before = bytes.to_vec();
                    let input = &bytes[16..16 + len];
                    let expected: [u8; 32] = Keccak256::digest(input).into();
                    let digest = keccak_cache::compute(input, |input| {
                        let mut digest = [0u64; 4];
                        unsafe {
                            keccak::keccak256_into(
                                input.as_ptr(),
                                input.len(),
                                digest.as_mut_ptr().cast(),
                            );
                        }
                        digest
                    });
                    unsafe {
                        keccak::store_digest(
                            digest.as_ptr(),
                            bytes.as_mut_ptr().add(output_offset),
                        );
                    }
                    assert_eq!(&bytes[output_offset..output_offset + 32], &expected);
                    assert_eq!(&bytes[..output_offset], &before[..output_offset]);
                    assert_eq!(&bytes[output_offset + 32..], &before[output_offset + 32..]);
                }
            }
        }
    }
}
