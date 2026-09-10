use jolt_inlines_sdk::host::NBigUint;
use jolt_inlines_sdk::{InlineReference, InlineSpec};
use rand::RngCore;
use tracer::utils::inline_test_harness::{InlineMemoryLayout, InlineTestHarness};

use crate::exec::{self, Element};
use crate::sequence_builder::{Fp2Mul, Mulp, Sopp2};
use crate::{LIMBS as N, MODULUS};

const MAX: u64 = u64::MAX;
const P5: u64 = MODULUS[N - 1];

fn sub_small(x: &Element, k: u64) -> Element {
    let mut bytes =
        NBigUint::from_bytes_le(&x.iter().flat_map(|l| l.to_le_bytes()).collect::<Vec<u8>>());
    bytes -= k;
    let mut out = bytes.to_bytes_le();
    out.resize(8 * N, 0);
    core::array::from_fn(|i| u64::from_le_bytes(out[8 * i..8 * i + 8].try_into().unwrap()))
}

/// Canonical (`< p`) corner values: 0, 1, R mod p, p − 1, p − 2, (p − 1)/2, limb extremes.
pub fn canonical_edges() -> Vec<Element> {
    let half: Element = core::array::from_fn(|i| {
        (MODULUS[i] >> 1) | if i + 1 < N { MODULUS[i + 1] << 63 } else { 0 }
    });
    vec![
        [0; N],
        [1, 0, 0, 0, 0, 0],
        exec::mulp(&[1, 0, 0, 0, 0, 0], &R2_LIMBS),
        sub_small(&MODULUS, 1),
        sub_small(&MODULUS, 2),
        half,
        [MAX, 0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 1],
        [MAX, MAX, MAX, MAX, MAX, P5 - 1],
        [0, 0, 0, 0, 0, P5],
        [MAX, MAX, MAX, MAX, MAX, 0],
        [1, 1, 1, 1, 1, 1],
        [0x4800_0000_0000_0000, 0, 0, 0, 0, 0x0800_0000_0000_0000],
    ]
}

/// R² mod p, so that `mulp(x, R2) = x · R mod p` (Montgomery form of `x`); R mod p = mulp(1, R2).
pub const R2_LIMBS: Element = [
    0xf4df_1f34_1c34_1746,
    0x0a76_e6a6_09d1_04f1,
    0x8de5_476c_4c95_b6d5,
    0x67eb_88a9_939d_83c0,
    0x9a79_3e85_b519_952d,
    0x1198_8fe5_92ca_e3aa,
];

/// Values `≥ p` (never produced by the field, tolerated as one MULP operand).
pub fn non_canonical_edges() -> Vec<Element> {
    let mut p_plus_1 = MODULUS;
    p_plus_1[0] += 1;
    vec![
        MODULUS,
        p_plus_1,
        [MAX; N],
        [0, 0, 0, 0, 0, 0x8000_0000_0000_0000],
        [0, 0, 0, 0, 0, MAX],
    ]
}

pub fn random_element(rng: &mut impl RngCore) -> Element {
    let p = NBigUint::from_bytes_le(
        &MODULUS
            .iter()
            .flat_map(|l| l.to_le_bytes())
            .collect::<Vec<u8>>(),
    );
    let x: Element = core::array::from_fn(|_| rng.next_u64());
    let x =
        NBigUint::from_bytes_le(&x.iter().flat_map(|l| l.to_le_bytes()).collect::<Vec<u8>>()) % p;
    let mut out = x.to_bytes_le();
    out.resize(8 * N, 0);
    core::array::from_fn(|i| u64::from_le_bytes(out[8 * i..8 * i + 8].try_into().unwrap()))
}

fn pairs() -> Vec<([Element; 2], [Element; 2])> {
    let c = canonical_edges();
    let mut out = Vec::new();
    for (i, a0) in c.iter().enumerate() {
        for (j, b0) in c.iter().enumerate() {
            let a1 = c[(i + j) % c.len()];
            let b1 = c[(i * 7 + j * 3) % c.len()];
            out.push(([*a0, a1], [*b0, b1]));
        }
    }
    out
}

fn flat(x: &[Element; 2]) -> [u64; 2 * N] {
    core::array::from_fn(|i| x[i / N][i % N])
}

impl InlineReference for Mulp {
    type Input = (Element, Element);
    type Output = Element;

    fn reference((a, b): &Self::Input) -> Self::Output {
        exec::mulp(a, b)
    }
}

impl InlineSpec for Mulp {
    fn edge_cases() -> impl IntoIterator<Item = Self::Input> {
        let c = canonical_edges();
        let all: Vec<Element> = c.iter().chain(&non_canonical_edges()).copied().collect();
        let mut out = Vec::new();
        for a in &c {
            for b in &all {
                out.push((*a, *b));
                out.push((*b, *a));
            }
        }
        out
    }

    fn random(rng: &mut impl RngCore) -> Self::Input {
        (random_element(rng), random_element(rng))
    }

    fn harness() -> InlineTestHarness {
        InlineTestHarness::new(InlineMemoryLayout::two_inputs(8 * N, 8 * N, 8 * N))
    }

    fn load(harness: &mut InlineTestHarness, (a, b): &Self::Input) {
        harness.load_input64(a);
        harness.load_input2_64(b);
    }

    fn read(harness: &mut InlineTestHarness) -> Self::Output {
        harness.read_output64(N).try_into().unwrap()
    }
}

impl InlineReference for Sopp2 {
    type Input = ([Element; 2], [Element; 2]);
    type Output = Element;

    fn reference((a, b): &Self::Input) -> Self::Output {
        exec::sopp2(a, b)
    }
}

impl InlineSpec for Sopp2 {
    fn edge_cases() -> impl IntoIterator<Item = Self::Input> {
        pairs()
    }

    fn random(rng: &mut impl RngCore) -> Self::Input {
        (
            [random_element(rng), random_element(rng)],
            [random_element(rng), random_element(rng)],
        )
    }

    fn harness() -> InlineTestHarness {
        InlineTestHarness::new(InlineMemoryLayout::two_inputs(16 * N, 16 * N, 8 * N))
    }

    fn load(harness: &mut InlineTestHarness, (a, b): &Self::Input) {
        harness.load_input64(&flat(a));
        harness.load_input2_64(&flat(b));
    }

    fn read(harness: &mut InlineTestHarness) -> Self::Output {
        harness.read_output64(N).try_into().unwrap()
    }
}

impl InlineReference for Fp2Mul {
    type Input = ([Element; 2], [Element; 2]);
    type Output = [Element; 2];

    fn reference((a, b): &Self::Input) -> Self::Output {
        exec::fp2mul(a, b)
    }
}

impl InlineSpec for Fp2Mul {
    fn edge_cases() -> impl IntoIterator<Item = Self::Input> {
        pairs()
    }

    fn random(rng: &mut impl RngCore) -> Self::Input {
        Sopp2::random(rng)
    }

    fn harness() -> InlineTestHarness {
        InlineTestHarness::new(InlineMemoryLayout::two_inputs(16 * N, 16 * N, 16 * N))
    }

    fn load(harness: &mut InlineTestHarness, input: &Self::Input) {
        Sopp2::load(harness, input)
    }

    fn read(harness: &mut InlineTestHarness) -> Self::Output {
        let out = harness.read_output64(2 * N);
        [out[..N].try_into().unwrap(), out[N..].try_into().unwrap()]
    }
}
