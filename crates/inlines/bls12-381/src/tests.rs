use ark_ff::{Field, Fp2Config, MontConfig};
use jolt_inlines_sdk::{
    assert_edge_cases_match_reference, assert_random_cases_match_reference, InlineSpec,
};
use rand::SeedableRng;
use tracer::instruction::RISCVTrace;
use tracer::utils::inline_test_harness::{InlineTestHarness, INLINE_RS1, INLINE_RS2, INLINE_RS3};

use crate::exec::{self, Element};
use crate::sequence_builder::{Fp2Mul, Mulp, Sopp2};
use crate::spec::random_element;
use crate::{
    FP2MUL_FUNCT3, FUNCT7, INLINE_OPCODE, INV, LIMBS as N, MINUS_ONE, MODULUS, MULP_FUNCT3,
    SOPP2_FUNCT3,
};

const MULP_ROWS: usize = 647;
const SOPP2_ROWS: usize = 957;
const FP2MUL_ROWS: usize = 1875;

fn rows<S: InlineSpec>(seed: u64) -> usize {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut harness = S::harness();
    harness.setup_registers();
    S::load(&mut harness, &S::random(&mut rng));
    let mut cycles = Vec::new();
    S::instruction().trace(&mut harness.cpu, Some(&mut cycles));
    cycles.len()
}

#[test]
fn golden_rows() {
    for seed in [1, 2] {
        assert_eq!(rows::<Mulp>(seed), MULP_ROWS);
        assert_eq!(rows::<Sopp2>(seed), SOPP2_ROWS);
        assert_eq!(rows::<Fp2Mul>(seed), FP2MUL_ROWS);
    }
}

#[test]
fn constants_match_arkworks() {
    assert_eq!(MODULUS, ark_bls12_381::FqConfig::MODULUS.0);
    assert_eq!(INV, ark_bls12_381::FqConfig::INV);
    assert_eq!(
        exec::mulp(&[1, 0, 0, 0, 0, 0], &crate::spec::R2_LIMBS),
        ark_bls12_381::FqConfig::R.0
    );
    assert_eq!(crate::spec::R2_LIMBS, ark_bls12_381::FqConfig::R2.0);
    assert_eq!(MINUS_ONE, (-ark_bls12_381::Fq::ONE).0 .0);
    assert_eq!(
        MINUS_ONE,
        (ark_bls12_381::Fq2Config::NONRESIDUE).0 .0,
        "Fq2 nonresidue is -1"
    );
    // Layout the ark-ff hook relies on: an element is exactly its six limbs, Fq2 is [c0, c1].
    assert_eq!(core::mem::size_of::<ark_bls12_381::Fq>(), 8 * N);
    assert_eq!(core::mem::offset_of!(ark_bls12_381::Fq, 0), 0);
    assert_eq!(core::mem::size_of::<ark_bls12_381::Fq2>(), 16 * N);
    assert_eq!(core::mem::offset_of!(ark_bls12_381::Fq2, c0), 0);
    assert_eq!(core::mem::offset_of!(ark_bls12_381::Fq2, c1), 8 * N);
    assert_eq!(INLINE_OPCODE, 0x2B);
    assert_eq!(FUNCT7, 0x01);
    assert_eq!([MULP_FUNCT3, SOPP2_FUNCT3, FP2MUL_FUNCT3], [0, 1, 2]);
    assert_eq!(N, 6);
}

#[test]
fn mulp_matches_arkworks() {
    use ark_ff::BigInt;
    let mut rng = rand::rngs::StdRng::seed_from_u64(7);
    for _ in 0..1000 {
        let (a, b) = (random_element(&mut rng), random_element(&mut rng));
        let fa = ark_bls12_381::Fq::new_unchecked(BigInt(a));
        let fb = ark_bls12_381::Fq::new_unchecked(BigInt(b));
        assert_eq!(exec::mulp(&a, &b), (fa * fb).0 .0);
    }
}

#[test]
fn mulp_random() {
    assert_random_cases_match_reference::<Mulp>(0xB15_0001, 10_000);
}

#[test]
fn mulp_edge_cases() {
    assert_edge_cases_match_reference::<Mulp>();
}

#[test]
fn sopp2_random() {
    assert_random_cases_match_reference::<Sopp2>(0xB15_0002, 10_000);
}

#[test]
fn sopp2_edge_cases() {
    assert_edge_cases_match_reference::<Sopp2>();
}

#[test]
fn fp2mul_random() {
    assert_random_cases_match_reference::<Fp2Mul>(0xB15_0003, 10_000);
}

#[test]
fn fp2mul_edge_cases() {
    assert_edge_cases_match_reference::<Fp2Mul>();
}

fn read(harness: &mut InlineTestHarness, reg: u8, words: usize) -> Vec<u64> {
    let base = harness.cpu.x[reg as usize] as u64;
    (0..words)
        .map(|i| {
            harness
                .cpu
                .mmu
                .load_doubleword(base + 8 * i as u64)
                .unwrap()
                .0
        })
        .collect()
}

/// The output may overwrite either input (rd == rs1, rd == rs2) and both inputs may be the same
/// buffer (rs1 == rs2).
#[test]
fn aliasing() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(11);
    for _ in 0..50 {
        let (a, b) = Mulp::random(&mut rng);
        for (rs1, rs2, rs3) in [
            (INLINE_RS1, INLINE_RS2, INLINE_RS1),
            (INLINE_RS1, INLINE_RS2, INLINE_RS2),
            (INLINE_RS1, INLINE_RS1, INLINE_RS3),
            (INLINE_RS1, INLINE_RS1, INLINE_RS1),
        ] {
            let mut harness = Mulp::harness();
            harness.setup_registers();
            Mulp::load(&mut harness, &(a, b));
            let instruction = InlineTestHarness::create_instruction(
                INLINE_OPCODE,
                MULP_FUNCT3,
                FUNCT7,
                rs1,
                rs2,
                rs3,
            );
            harness.execute_inline(instruction);
            let rhs = if rs2 == INLINE_RS1 { a } else { b };
            let out: Element = read(&mut harness, rs3, N).try_into().unwrap();
            assert_eq!(out, exec::mulp(&a, &rhs));
        }
        let (a2, b2) = Fp2Mul::random(&mut rng);
        for rs3 in [INLINE_RS1, INLINE_RS2] {
            let mut harness = Fp2Mul::harness();
            harness.setup_registers();
            Fp2Mul::load(&mut harness, &(a2, b2));
            let instruction = InlineTestHarness::create_instruction(
                INLINE_OPCODE,
                FP2MUL_FUNCT3,
                FUNCT7,
                INLINE_RS1,
                INLINE_RS2,
                rs3,
            );
            harness.execute_inline(instruction);
            let out = read(&mut harness, rs3, 2 * N);
            let expected = exec::fp2mul(&a2, &b2);
            assert_eq!(out[..N], expected[0]);
            assert_eq!(out[N..], expected[1]);
        }
    }
}
