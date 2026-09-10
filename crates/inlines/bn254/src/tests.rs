use ark_bn254::{Fq, Fq2, FqConfig};
use ark_ff::{Field, Fp2Config, MontConfig, PrimeField};
use jolt_inlines_sdk::host::InlineOp;
use jolt_inlines_sdk::{assert_edge_cases_match_reference, assert_random_cases_match_reference};
use rand::SeedableRng;
use tracer::emulator::mmu::DRAM_BASE;
use tracer::instruction::format::format_inline::FormatInline;
use tracer::instruction::inline::INLINE;
use tracer::utils::inline_test_harness::{InlineMemoryLayout, InlineTestHarness, RegisterMapping};
use tracer::utils::virtual_registers::VirtualRegisterAllocator;

use crate::exec;
use crate::sequence_builder::{Bn254Fp2MulQ, Bn254MulQ, Bn254SopQ2};
use crate::spec::{canonical, concat, fq, geq_modulus, limbs, random_element, random_pair, Limbs};
use crate::{BN254_INV, BN254_MINUS_ONE, BN254_MODULUS};

fn row_count<Op: InlineOp>() -> usize {
    let inline = INLINE {
        opcode: Op::OPCODE,
        funct3: Op::FUNCT3,
        funct7: Op::FUNCT7,
        address: 0x8000_0000,
        operands: FormatInline {
            rs1: 10,
            rs2: 11,
            rs3: 12,
        },
        virtual_sequence_remaining: None,
        is_first_in_sequence: false,
        is_compressed: false,
    };
    inline
        .inline_sequence(&VirtualRegisterAllocator::default())
        .len()
}

#[test]
fn golden_row_counts() {
    assert_eq!(row_count::<Bn254MulQ>(), 273);
    assert_eq!(row_count::<Bn254SopQ2>(), 415);
    assert_eq!(row_count::<Bn254Fp2MulQ>(), 797);
}

#[test]
fn constants_match_ark() {
    assert_eq!(BN254_MODULUS, Fq::MODULUS.0);
    assert_eq!(BN254_INV, <FqConfig as MontConfig<4>>::INV);
    assert_eq!(BN254_INV.wrapping_mul(BN254_MODULUS[0]), u64::MAX);
    assert_eq!(BN254_MINUS_ONE, limbs(-Fq::ONE));
    assert_eq!(BN254_MINUS_ONE, limbs(ark_bn254::Fq2Config::NONRESIDUE));
    // 2q < 2^256: one conditional subtraction canonicalizes, column 7 never carries out.
    assert!(BN254_MODULUS[3] < 1 << 63);
    assert_eq!(core::mem::size_of::<Fq>(), 32);
    assert_eq!(core::mem::size_of::<Fq2>(), 64);
    assert_eq!(core::mem::size_of::<[Fq; 2]>(), 64);
}

#[test]
fn mulq_matches_model_on_random_inputs() {
    assert_random_cases_match_reference::<Bn254MulQ>(0xb254_0001, 10_000);
}

#[test]
fn mulq_matches_model_on_edge_cases() {
    assert_edge_cases_match_reference::<Bn254MulQ>();
}

#[test]
fn sopq2_matches_model_on_random_inputs() {
    assert_random_cases_match_reference::<Bn254SopQ2>(0xb254_0002, 10_000);
}

#[test]
fn sopq2_matches_model_on_edge_cases() {
    assert_edge_cases_match_reference::<Bn254SopQ2>();
}

#[test]
fn fp2mulq_matches_model_on_random_inputs() {
    assert_random_cases_match_reference::<Bn254Fp2MulQ>(0xb254_0003, 10_000);
}

#[test]
fn fp2mulq_matches_model_on_edge_cases() {
    assert_edge_cases_match_reference::<Bn254Fp2MulQ>();
}

fn below_2q(t: &Limbs) -> bool {
    !geq_modulus(t) || !geq_modulus(&canonical(t))
}

#[test]
fn model_matches_ark_field_arithmetic() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xb254_0004);
    let mut subtractions = 0;
    for _ in 0..20_000 {
        let (a, b) = (random_pair(&mut rng), random_pair(&mut rng));
        let (a0, a1): (Limbs, Limbs) = (a[..4].try_into().unwrap(), a[4..].try_into().unwrap());
        let (b0, b1): (Limbs, Limbs) = (b[..4].try_into().unwrap(), b[4..].try_into().unwrap());

        let t = exec::mulq(&a0, &b0);
        assert!(below_2q(&t));
        subtractions += usize::from(geq_modulus(&t));
        assert_eq!(canonical(&t), limbs(fq(&a0) * fq(&b0)));

        let t = exec::sopq2(&a, &b);
        assert!(below_2q(&t));
        let expected = Fq::sum_of_products(&[fq(&a0), fq(&a1)], &[fq(&b0), fq(&b1)]);
        assert_eq!(canonical(&t), limbs(expected));

        let c = exec::fp2mulq(&a, &b);
        let (c0, c1): (Limbs, Limbs) = (c[..4].try_into().unwrap(), c[4..].try_into().unwrap());
        assert!(below_2q(&c0) && below_2q(&c1));
        let expected = Fq2::new(fq(&a0), fq(&a1)) * Fq2::new(fq(&b0), fq(&b1));
        assert_eq!(canonical(&c0), limbs(expected.c0));
        assert_eq!(canonical(&c1), limbs(expected.c1));
    }
    // ≈ q / 2^258 of the products land in [q, 2q); the sample must exercise that path.
    assert!(subtractions > 100, "{subtractions}");
}

#[test]
fn negation_of_zero_is_q_and_of_one_is_q_minus_one() {
    assert_eq!(exec::negate(&[0; 4]), BN254_MODULUS);
    let q_minus_1 = [
        BN254_MODULUS[0] - 1,
        BN254_MODULUS[1],
        BN254_MODULUS[2],
        BN254_MODULUS[3],
    ];
    assert_eq!(exec::negate(&[1, 0, 0, 0]), q_minus_1);
    assert_eq!(exec::negate(&q_minus_1), [1, 0, 0, 0]);
}

fn run_aliased(rs2_mapping: RegisterMapping, a: &Limbs, b: &Limbs) -> Limbs {
    let layout = InlineMemoryLayout {
        input_base: DRAM_BASE,
        input_size: 32,
        input2_base: Some(DRAM_BASE + 32),
        input2_size: Some(32),
        output_base: DRAM_BASE,
        output_size: 32,
        rs1_mapping: RegisterMapping::Input,
        rs2_mapping,
        rs3_mapping: Some(RegisterMapping::Input),
    };
    let mut harness = InlineTestHarness::new(layout);
    harness.setup_registers();
    harness.load_input64(a);
    harness.load_input2_64(b);
    harness.execute_inline(InlineTestHarness::create_default_instruction(
        Bn254MulQ::OPCODE,
        Bn254MulQ::FUNCT3,
        Bn254MulQ::FUNCT7,
    ));
    harness.read_output64(4).try_into().unwrap()
}

#[test]
fn output_may_alias_inputs() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xb254_0005);
    for _ in 0..200 {
        let (a, b) = (random_element(&mut rng), random_element(&mut rng));
        // rd == rs1
        assert_eq!(
            run_aliased(RegisterMapping::Input2, &a, &b),
            exec::mulq(&a, &b)
        );
        // rd == rs1 == rs2 (squaring in place)
        assert_eq!(
            run_aliased(RegisterMapping::Input, &a, &b),
            exec::mulq(&a, &a)
        );
    }
}

#[test]
fn fp2mulq_in_place_matches_model() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xb254_0006);
    for _ in 0..200 {
        let (a, b) = (random_pair(&mut rng), random_pair(&mut rng));
        let layout = InlineMemoryLayout {
            input_base: DRAM_BASE,
            input_size: 64,
            input2_base: Some(DRAM_BASE + 64),
            input2_size: Some(64),
            output_base: DRAM_BASE,
            output_size: 64,
            rs1_mapping: RegisterMapping::Input,
            rs2_mapping: RegisterMapping::Input2,
            rs3_mapping: Some(RegisterMapping::Input),
        };
        let mut harness = InlineTestHarness::new(layout);
        harness.setup_registers();
        harness.load_input64(&a);
        harness.load_input2_64(&b);
        harness.execute_inline(InlineTestHarness::create_default_instruction(
            Bn254Fp2MulQ::OPCODE,
            Bn254Fp2MulQ::FUNCT3,
            Bn254Fp2MulQ::FUNCT7,
        ));
        let out: [u64; 8] = harness.read_output64(8).try_into().unwrap();
        assert_eq!(out, exec::fp2mulq(&a, &b));
    }
}

/// Outside the domain (limbs ≥ q) the sequence still equals the model: the REDC value truncated
/// to 256 bits. Never reachable from ark's canonical elements; pinned so the behavior is explicit.
#[test]
fn out_of_domain_inputs_match_model() {
    let mut rng = rand::rngs::StdRng::seed_from_u64(0xb254_0007);
    for _ in 0..500 {
        let a: Limbs = core::array::from_fn(|_| rand::RngCore::next_u64(&mut rng));
        let b: Limbs = core::array::from_fn(|_| rand::RngCore::next_u64(&mut rng));
        jolt_inlines_sdk::assert_reference_matches_harness::<Bn254MulQ>(&(a, b));
        jolt_inlines_sdk::assert_reference_matches_harness::<Bn254SopQ2>(&(
            concat(a, b),
            concat(b, a),
        ));
        jolt_inlines_sdk::assert_reference_matches_harness::<Bn254Fp2MulQ>(&(
            concat(a, b),
            concat(b, a),
        ));
    }
    assert_eq!(exec::mulq(&[u64::MAX; 4], &[u64::MAX; 4]).len(), 4);
}
