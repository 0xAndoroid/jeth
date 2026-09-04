//! Deferred recovery equations; no validation output may precede `verify`.

use crate::advice::advice_u64;
use crate::crypto::{prepare_recovery, N};
use alloc::vec::Vec;
use alloy_primitives::{keccak256, Address, Signature, B256, U256};
use jolt_inlines_secp256k1::{Secp256k1Fr, Secp256k1Point, Secp256k1PointExt};

#[derive(Clone)]
pub(crate) struct Equation {
    pub(crate) nonce: Secp256k1Point,
    pub(crate) message: [u8; 32],
    pub(crate) r: Secp256k1Fr,
    pub(crate) s: Secp256k1Fr,
    pub(crate) key: Secp256k1Point,
}

#[derive(Default)]
struct Batch {
    equations: Vec<Equation>,
}

#[cfg(not(target_arch = "riscv64"))]
extern crate std;
#[cfg(not(target_arch = "riscv64"))]
std::thread_local! {
    static BATCH: core::cell::RefCell<Batch> = core::cell::RefCell::default();
}
#[cfg(target_arch = "riscv64")]
static mut BATCH: Batch = Batch {
    equations: Vec::new(),
};

fn with_batch<T>(f: impl FnOnce(&mut Batch) -> T) -> T {
    #[cfg(not(target_arch = "riscv64"))]
    {
        BATCH.with_borrow_mut(f)
    }
    #[cfg(target_arch = "riscv64")]
    // SAFETY: the guest has one hart, no interrupts, and no reentrant batch access.
    unsafe {
        f(&mut *core::ptr::addr_of_mut!(BATCH))
    }
}

pub(crate) fn scalar(bytes: [u8; 32]) -> Secp256k1Fr {
    let mut value = U256::from_be_bytes(bytes);
    if value >= N {
        value -= N;
    }
    Secp256k1Fr::from_u64_arr(value.as_limbs()).unwrap()
}

fn address(key: &Secp256k1Point) -> Option<[u8; 32]> {
    if key.is_infinity() {
        return None;
    }
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&U256::from_limbs(key.x().e()).to_be_bytes::<32>());
    bytes[32..].copy_from_slice(&U256::from_limbs(key.y().e()).to_be_bytes::<32>());
    let mut hash = keccak256(bytes).0;
    hash[..12].fill(0);
    Some(hash)
}

pub(crate) fn recover(sig: &[u8; 64], recid: u8, message: &[u8; 32]) -> Option<[u8; 32]> {
    let mut equation = prepare_recovery(sig, recid, message)?;
    #[cfg(any(feature = "compute_advice", not(target_arch = "riscv64")))]
    let limbs = crate::crypto::recover_point(&equation).to_u64_arr();
    let mut advised = [0; 8];
    for (i, limb) in advised.iter_mut().enumerate() {
        *limb = advice_u64!(limbs[i]);
        let _ = i;
    }
    // (0,0) is the unique failure sentinel; its equation is checked too.
    equation.key = Secp256k1Point::from_u64_arr(&advised).expect("recovery advice on curve");
    let result = address(&equation.key);
    with_batch(|batch| batch.equations.push(equation));
    result
}

pub(crate) fn verify_pubkey(vk: &[u8; 65], sig: &Signature, message: B256) -> Option<Address> {
    if vk[0] != 4 {
        return None;
    }
    let mut limbs = [0; 8];
    limbs[..4].copy_from_slice(U256::from_be_slice(&vk[1..33]).as_limbs());
    limbs[4..].copy_from_slice(U256::from_be_slice(&vk[33..]).as_limbs());
    let key = Secp256k1Point::from_u64_arr(&limbs).ok()?;
    if key.is_infinity() {
        return None;
    }
    let mut sig_bytes = [0; 64];
    sig_bytes[..32].copy_from_slice(&sig.r().to_be_bytes::<32>());
    sig_bytes[32..].copy_from_slice(&sig.s().to_be_bytes::<32>());
    let mut equation = prepare_recovery(&sig_bytes, u8::from(sig.v()), &message.0)?;
    equation.key = key;
    let sender = Address::from_slice(&keccak256(&vk[1..])[12..]);
    with_batch(|batch| batch.equations.push(equation));
    Some(sender)
}

/// Checks every deferred recovery before a successful validation result exists.
/// A panic, including a forged failure claim, cannot produce a proof.
pub fn verify() {
    #[cfg(target_arch = "riscv64")]
    jolt::start_cycle_tracking("recovery_batch");
    with_batch(|batch| {
        batch.verify();
        batch.equations.clear();
    });
    #[cfg(target_arch = "riscv64")]
    jolt::end_cycle_tracking("recovery_batch");
}

impl Batch {
    fn transcript(&self) -> B256 {
        const DOMAIN: &[u8] = b"jeth/recovery-batch/v1/tuples";
        // One-shot keccak uses the guest inline; alloy's streaming hasher does not.
        let mut bytes = Vec::with_capacity(DOMAIN.len() + 8 + 224 * self.equations.len());
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&(self.equations.len() as u64).to_le_bytes());
        for equation in &self.equations {
            for limb in equation.nonce.to_u64_arr() {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
            bytes.extend_from_slice(&equation.message);
            for limb in equation.r.e() {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
            for limb in equation.s.e() {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
            for limb in equation.key.to_u64_arr() {
                bytes.extend_from_slice(&limb.to_le_bytes());
            }
        }
        keccak256(bytes)
    }

    fn verify(&self) {
        if self.equations.is_empty() {
            return;
        }
        let digest = self.transcript();
        let mut terms = Vec::with_capacity(2 * self.equations.len() + 1);
        let mut generator_scalar = Secp256k1Fr::zero();
        for (index, equation) in self.equations.iter().enumerate() {
            let lambda = challenge(digest, index);
            terms.push((lambda.mul(&equation.s), equation.nonce.clone()));
            terms.push((lambda.mul(&equation.r).neg(), equation.key.clone()));
            generator_scalar = generator_scalar.sub(&lambda.mul(&scalar(equation.message)));
        }
        terms.push((generator_scalar, Secp256k1Point::generator()));
        #[cfg(target_arch = "riscv64")]
        jolt::start_cycle_tracking("recovery_msm");
        assert!(pippenger(&terms).is_infinity(), "invalid recovery batch");
        #[cfg(target_arch = "riscv64")]
        jolt::end_cycle_tracking("recovery_msm");
    }
}

fn challenge(digest: B256, index: usize) -> Secp256k1Fr {
    const DOMAIN: &[u8] = b"jeth/recovery-batch/v1/challenge";
    let mut bytes = [0; DOMAIN.len() + 40];
    bytes[..DOMAIN.len()].copy_from_slice(DOMAIN);
    bytes[DOMAIN.len()..DOMAIN.len() + 32].copy_from_slice(digest.as_slice());
    bytes[DOMAIN.len() + 32..].copy_from_slice(&(index as u64).to_le_bytes());
    scalar(keccak256(bytes).0)
}

fn pippenger(terms: &[(Secp256k1Fr, Secp256k1Point)]) -> Secp256k1Point {
    let terms: Vec<_> = terms
        .iter()
        .flat_map(|(scalar, point)| {
            let split = scalar.glv_decompose();
            let points = [point.clone(), point.endomorphism()];
            split
                .into_iter()
                .zip(points)
                .map(|((negative, scalar), point)| {
                    (scalar, if negative { point.neg() } else { point })
                })
        })
        .collect();
    let width = if terms.len() < 1024 { 7 } else { 8 };
    let mut buckets = alloc::vec![Secp256k1Point::infinity(); 1 << width];
    let mut result = Secp256k1Point::infinity();
    for window in (0..128usize.div_ceil(width)).rev() {
        for _ in 0..width {
            result = result.double();
        }
        buckets.fill(Secp256k1Point::infinity());
        let bit = window * width;
        for (scalar, point) in &terms {
            let digit = scalar >> bit;
            let digit = digit as usize & ((1 << width) - 1);
            if digit != 0 {
                buckets[digit] = buckets[digit].add(point);
            }
        }
        let mut sum = Secp256k1Point::infinity();
        for bucket in buckets[1..].iter().rev() {
            sum = sum.add(bucket);
            result = result.add(&sum);
        }
    }
    result
}

#[cfg(test)]
mod tests;
