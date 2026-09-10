use ark_bn254::Fq;
use ark_ff::{BigInt, Field};
use jolt_inlines_sdk::{InlineReference, InlineSpec};
use rand::{RngCore, SeedableRng};
use tracer::utils::inline_test_harness::{InlineMemoryLayout, InlineTestHarness};

use crate::exec;
use crate::sequence_builder::{Bn254Fp2MulQ, Bn254MulQ, Bn254SopQ2};
use crate::BN254_MODULUS;

pub type Limbs = [u64; 4];
pub type Pair = [u64; 8];

pub fn geq_modulus(x: &Limbs) -> bool {
    for i in (0..4).rev() {
        if x[i] != BN254_MODULUS[i] {
            return x[i] > BN254_MODULUS[i];
        }
    }
    true
}

/// Uniform element of [0, q).
pub fn random_element(rng: &mut impl RngCore) -> Limbs {
    loop {
        let mut x: Limbs = core::array::from_fn(|_| rng.next_u64());
        x[3] &= (1 << 62) - 1;
        if !geq_modulus(&x) {
            return x;
        }
    }
}

pub fn random_pair(rng: &mut impl RngCore) -> Pair {
    concat(random_element(rng), random_element(rng))
}

pub fn concat(lo: Limbs, hi: Limbs) -> Pair {
    let mut out = [0u64; 8];
    out[..4].copy_from_slice(&lo);
    out[4..].copy_from_slice(&hi);
    out
}

pub fn fq(x: &Limbs) -> Fq {
    Fq::new_unchecked(BigInt(*x))
}

pub fn limbs(x: Fq) -> Limbs {
    (x.0).0
}

/// Reduces a REDC result from [0, 2q) to [0, q).
pub fn canonical(t: &Limbs) -> Limbs {
    if !geq_modulus(t) {
        return *t;
    }
    let mut out = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, b1) = t[i].overflowing_sub(BN254_MODULUS[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        out[i] = d;
        borrow = u64::from(b1 | b2);
    }
    assert_eq!(borrow, 0, "value below q after one subtraction");
    out
}

/// Field elements at the corners of the domain: 0, integer 1 (= R⁻¹), R (= Fq::ONE), R², q − 1,
/// (q − 1)² in Montgomery form, all-ones low limbs, single saturated limbs.
pub fn edge_elements() -> Vec<Limbs> {
    let q = BN254_MODULUS;
    let q_minus_1 = [q[0] - 1, q[1], q[2], q[3]];
    vec![
        [0; 4],
        [1, 0, 0, 0],
        limbs(Fq::ONE),
        Fq::R2.0,
        q_minus_1,
        limbs(fq(&q_minus_1) * fq(&q_minus_1)),
        [u64::MAX, u64::MAX, u64::MAX, q[3] - 1],
        [u64::MAX, 0, 0, 0],
        [0, u64::MAX, u64::MAX, 0],
        [0, 0, 0, q[3]],
        [q[0] - 1, q[1], q[2] - 1, q[3]],
        [1 << 63, 1 << 63, 1 << 63, 1 << 61],
    ]
}

/// Operand pairs whose reduction lands in [q, 2q) (the caller's conditional subtraction fires).
pub fn pairs_forcing_subtraction(count: usize, seed: u64) -> Vec<(Limbs, Limbs)> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut out = Vec::new();
    while out.len() < count {
        let (a, b) = (random_element(&mut rng), random_element(&mut rng));
        if geq_modulus(&exec::mulq(&a, &b)) {
            out.push((a, b));
        }
    }
    out
}

pub fn sop_pairs_forcing_subtraction(count: usize, seed: u64) -> Vec<(Pair, Pair)> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut out = Vec::new();
    while out.len() < count {
        let (a, b) = (random_pair(&mut rng), random_pair(&mut rng));
        if geq_modulus(&exec::sopq2(&a, &b)) {
            out.push((a, b));
        }
    }
    out
}

impl InlineReference for Bn254MulQ {
    type Input = (Limbs, Limbs);
    type Output = Limbs;

    fn reference((a, b): &Self::Input) -> Self::Output {
        exec::mulq(a, b)
    }
}

impl InlineSpec for Bn254MulQ {
    fn edge_cases() -> impl IntoIterator<Item = Self::Input> {
        let edges = edge_elements();
        let mut cases: Vec<Self::Input> = Vec::new();
        for a in &edges {
            for b in &edges {
                cases.push((*a, *b));
            }
        }
        cases.extend(pairs_forcing_subtraction(8, 0xb254_0e01));
        cases
    }

    fn random(rng: &mut impl RngCore) -> Self::Input {
        (random_element(rng), random_element(rng))
    }

    fn harness() -> InlineTestHarness {
        InlineTestHarness::new(InlineMemoryLayout::two_inputs(32, 32, 32))
    }

    fn load(harness: &mut InlineTestHarness, (a, b): &Self::Input) {
        harness.load_input64(a);
        harness.load_input2_64(b);
    }

    fn read(harness: &mut InlineTestHarness) -> Self::Output {
        harness.read_output64(4).try_into().unwrap()
    }
}

impl InlineReference for Bn254SopQ2 {
    type Input = (Pair, Pair);
    type Output = Limbs;

    fn reference((a, b): &Self::Input) -> Self::Output {
        exec::sopq2(a, b)
    }
}

impl InlineSpec for Bn254SopQ2 {
    fn edge_cases() -> impl IntoIterator<Item = Self::Input> {
        let edges = edge_elements();
        let zero = [0u64; 4];
        let mut cases: Vec<Self::Input> = Vec::new();
        for a in &edges {
            for b in &edges {
                cases.push((concat(*a, *a), concat(*b, *b)));
                cases.push((concat(*a, zero), concat(*b, zero)));
                cases.push((concat(zero, *a), concat(zero, *b)));
                cases.push((concat(*a, *b), concat(*b, *a)));
            }
        }
        cases.extend(sop_pairs_forcing_subtraction(8, 0xb254_0e02));
        cases
    }

    fn random(rng: &mut impl RngCore) -> Self::Input {
        (random_pair(rng), random_pair(rng))
    }

    fn harness() -> InlineTestHarness {
        InlineTestHarness::new(InlineMemoryLayout::two_inputs(64, 64, 32))
    }

    fn load(harness: &mut InlineTestHarness, (a, b): &Self::Input) {
        harness.load_input64(a);
        harness.load_input2_64(b);
    }

    fn read(harness: &mut InlineTestHarness) -> Self::Output {
        harness.read_output64(4).try_into().unwrap()
    }
}

impl InlineReference for Bn254Fp2MulQ {
    type Input = (Pair, Pair);
    type Output = Pair;

    fn reference((a, b): &Self::Input) -> Self::Output {
        exec::fp2mulq(a, b)
    }
}

impl InlineSpec for Bn254Fp2MulQ {
    fn edge_cases() -> impl IntoIterator<Item = Self::Input> {
        let edges = edge_elements();
        let zero = [0u64; 4];
        let mut cases: Vec<Self::Input> = Vec::new();
        for a in &edges {
            for b in &edges {
                cases.push((concat(*a, *a), concat(*b, *b)));
                cases.push((concat(*a, *b), concat(*b, zero)));
                cases.push((concat(zero, *a), concat(zero, *b)));
                cases.push((concat(*a, *b), concat(*a, *b)));
            }
        }
        cases.extend(sop_pairs_forcing_subtraction(8, 0xb254_0e03));
        cases
    }

    fn random(rng: &mut impl RngCore) -> Self::Input {
        (random_pair(rng), random_pair(rng))
    }

    fn harness() -> InlineTestHarness {
        InlineTestHarness::new(InlineMemoryLayout::two_inputs(64, 64, 64))
    }

    fn load(harness: &mut InlineTestHarness, (a, b): &Self::Input) {
        harness.load_input64(a);
        harness.load_input2_64(b);
    }

    fn read(harness: &mut InlineTestHarness) -> Self::Output {
        harness.read_output64(8).try_into().unwrap()
    }
}
