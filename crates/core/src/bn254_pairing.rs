//! Exact reuse of validated BN254 G2 points and their Miller-loop preparation.

use alloc::vec::Vec;
use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{BigInt, One, PrimeField, Zero};
use reth_evm::revm::precompile::PrecompileHalt;

#[path = "bn254_pairing/generator.rs"]
mod generator;

type Prepared = <Bn254 as Pairing>::G2Prepared;
const CAPACITY: usize = 8;

struct Entry {
    bytes: [u8; 128],
    prepared: Prepared,
}

#[derive(Default)]
struct Cache {
    entries: Vec<Entry>,
    next: usize,
}

#[cfg(not(target_arch = "riscv64"))]
extern crate std;
#[cfg(not(target_arch = "riscv64"))]
std::thread_local! {
    static CACHE: core::cell::RefCell<Cache> = core::cell::RefCell::default();
}
#[cfg(target_arch = "riscv64")]
static mut CACHE: Cache = Cache {
    entries: Vec::new(),
    next: 0,
};

fn with_cache<T>(f: impl FnOnce(&mut Cache) -> T) -> T {
    #[cfg(not(target_arch = "riscv64"))]
    {
        CACHE.with_borrow_mut(f)
    }
    #[cfg(target_arch = "riscv64")]
    // SAFETY: the guest has one hart, no interrupts, and no reentrant cache access.
    unsafe {
        f(&mut *core::ptr::addr_of_mut!(CACHE))
    }
}

#[expect(
    clippy::unwrap_used,
    reason = "each field limb slice contains exactly eight bytes"
)]
fn read_fq(bytes: &[u8]) -> Result<Fq, PrecompileHalt> {
    let limbs = core::array::from_fn(|i| {
        u64::from_be_bytes(bytes[24 - 8 * i..32 - 8 * i].try_into().unwrap())
    });
    Fq::from_bigint(BigInt::new(limbs)).ok_or(PrecompileHalt::Bn254FieldPointNotAMember)
}

fn read_g1(bytes: &[u8]) -> Result<G1Affine, PrecompileHalt> {
    let x = read_fq(&bytes[..32])?;
    let y = read_fq(&bytes[32..64])?;
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::identity());
    }
    let p = G1Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
    }
    Ok(p)
}

fn read_g2(bytes: &[u8]) -> Result<G2Affine, PrecompileHalt> {
    // EIP-197 puts each Fq2 imaginary component before its real component.
    let xi = read_fq(&bytes[..32])?;
    let xr = read_fq(&bytes[32..64])?;
    let yi = read_fq(&bytes[64..96])?;
    let yr = read_fq(&bytes[96..128])?;
    let (x, y) = (Fq2::new(xr, xi), Fq2::new(yr, yi));
    if x.is_zero() && y.is_zero() {
        return Ok(G2Affine::identity());
    }
    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() || !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(PrecompileHalt::Bn254AffineGFailedToCreate);
    }
    Ok(p)
}

impl Cache {
    #[expect(clippy::expect_used, reason = "the G2 prefix is exactly 128 bytes")]
    fn prepare(&mut self, bytes: &[u8], needed: bool) -> Result<Option<Prepared>, PrecompileHalt> {
        let bytes: &[u8; 128] = bytes[..128].try_into().expect("EIP-197 G2 encoding");
        if bytes == &generator::ENCODING {
            return Ok(needed.then(generator::prepared));
        }
        if let Some(entry) = self.entries.iter().find(|entry| &entry.bytes == bytes) {
            return Ok(needed.then(|| entry.prepared.clone()));
        }
        // Validate even when the associated G1 point is infinity. Such a pair
        // may contribute nothing to the product but can still be invalid.
        let point = read_g2(bytes)?;
        if !needed || point.is_zero() {
            return Ok(None);
        }
        let prepared = Prepared::from(point);
        let entry = Entry {
            bytes: *bytes,
            prepared: prepared.clone(),
        };
        if self.entries.len() < CAPACITY {
            self.entries.push(entry);
        } else {
            self.entries[self.next] = entry;
            self.next = (self.next + 1) % CAPACITY;
        }
        Ok(Some(prepared))
    }

    fn check(&mut self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
        let mut g1 = Vec::with_capacity(pairs.len());
        let mut g2 = Vec::with_capacity(pairs.len());
        for (a, b) in pairs {
            let point = read_g1(a)?;
            if let Some(prepared) = self.prepare(b, !point.is_zero())? {
                g1.push(point);
                g2.push(prepared);
            }
        }
        if g1.is_empty() {
            return Ok(true);
        }
        Ok(Bn254::multi_pairing(g1, g2).0.is_one())
    }
}

pub(crate) fn pairing_check(pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileHalt> {
    with_cache(|cache| cache.check(pairs))
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests assert successful decoding and fail explicitly when a fixture cannot be constructed"
)]
mod tests {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_ff::{BigInteger, Field};
    use reth_evm::revm::precompile::{Crypto, DefaultCrypto};

    fn fq(value: Fq) -> [u8; 32] {
        value.into_bigint().to_bytes_be().try_into().unwrap()
    }
    fn g1(p: G1Affine) -> [u8; 64] {
        if p.is_zero() {
            return [0; 64];
        }
        let mut out = [0; 64];
        out[..32].copy_from_slice(&fq(p.x));
        out[32..].copy_from_slice(&fq(p.y));
        out
    }
    fn g2(p: G2Affine) -> [u8; 128] {
        if p.is_zero() {
            return [0; 128];
        }
        let mut out = [0; 128];
        for (chunk, value) in out
            .chunks_exact_mut(32)
            .zip([p.x.c1, p.x.c0, p.y.c1, p.y.c0])
        {
            chunk.copy_from_slice(&fq(value));
        }
        out
    }
    fn compare(cache: &mut Cache, pairs: &[(&[u8], &[u8])]) {
        assert_eq!(
            format_result(cache.check(pairs)),
            format_result(DefaultCrypto.bn254_pairing_check(pairs))
        );
    }
    fn format_result(result: Result<bool, PrecompileHalt>) -> alloc::string::String {
        alloc::format!("{result:?}")
    }

    #[test]
    fn matches_reference_with_reuse_and_eviction() {
        let mut cache = Cache::default();
        compare(&mut cache, &[]);
        assert!(pairing_check(&[]).unwrap());
        for i in 1..=24u64 {
            let a = G1Affine::generator().mul_bigint([i]).into_affine();
            let b = G2Affine::generator().mul_bigint([i]).into_affine();
            let (a, neg_a, b) = (g1(a), g1(-a), g2(b));
            compare(&mut cache, &[(&a, &b)]);
            compare(&mut cache, &[(&a, &b), (&neg_a, &b)]);
            assert!(cache.check(&[(&a, &b), (&neg_a, &b)]).unwrap());
            assert!(cache.entries.len() <= CAPACITY);
            let retained_bytes = cache.entries.capacity() * core::mem::size_of::<Entry>()
                + cache
                    .entries
                    .iter()
                    .map(|entry| {
                        entry.prepared.ell_coeffs.capacity()
                            * core::mem::size_of::<ark_ec::bn::g2::EllCoeff<ark_bn254::Config>>()
                    })
                    .sum::<usize>();
            assert!(retained_bytes <= 160 * 1024);
        }
    }

    #[test]
    fn infinity_does_not_bypass_validation() {
        let mut cache = Cache::default();
        let (a, b) = (g1(G1Affine::generator()), g2(G2Affine::generator()));
        let (zero1, zero2) = ([0u8; 64], [0u8; 128]);
        compare(&mut cache, &[(&zero1, &b)]);
        compare(&mut cache, &[(&a, &zero2)]);
        compare(&mut cache, &[(&zero1, &zero2)]);
        compare(&mut cache, &[(&a, &b)]); // Populate a valid entry.
        let mut bad = b;
        bad[127] ^= 1;
        compare(&mut cache, &[(&zero1, &bad)]);
        assert!(cache.check(&[(&zero1, &bad)]).is_err());
        bad[..32].fill(255);
        compare(&mut cache, &[(&zero1, &bad)]);
        let mut bad1 = a;
        bad1[..32].fill(255);
        compare(&mut cache, &[(&bad1, &zero2)]);
    }

    #[test]
    fn rejects_on_curve_g2_outside_subgroup() {
        let mut cache = Cache::default();
        for i in 1..100u64 {
            let x = Fq2::new(Fq::from(i), Fq::from(1u64));
            let Some(y) = (x.square() * x
                + <ark_bn254::g2::Config as ark_ec::short_weierstrass::SWCurveConfig>::COEFF_B)
                .sqrt()
            else {
                continue;
            };
            let p = G2Affine::new_unchecked(x, y);
            if p.is_in_correct_subgroup_assuming_on_curve() {
                continue;
            }
            let encoded_g2 = g2(p);
            let encoded_g1 = g1(G1Affine::generator());
            compare(&mut cache, &[(&encoded_g1, &encoded_g2)]);
            compare(&mut cache, &[(&[0u8; 64], &encoded_g2)]);
            assert!(cache.check(&[(&encoded_g1, &encoded_g2)]).is_err());
            assert!(cache.entries.is_empty());
            return;
        }
        panic!("failed to construct non-subgroup test point");
    }
}
