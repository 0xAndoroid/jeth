#![expect(clippy::unwrap_used, reason = "test fixtures and assertions")]
#![expect(clippy::many_single_char_names, reason = "KZG equation notation")]

use super::*;
use alloc::vec::Vec;
use ark_bls12_381::Fq;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;

fn hex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), 2 * N);
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

fn point_bytes(point: G1Affine) -> [u8; 48] {
    let mut bytes = Vec::new();
    point.serialize_compressed(&mut bytes).unwrap();
    bytes.try_into().unwrap()
}

fn scalar_bytes(value: Fr) -> [u8; 32] {
    value.into_bigint().to_bytes_be().try_into().unwrap()
}

fn check(c: &[u8; 48], z: &[u8; 32], y: &[u8; 32], p: &[u8; 48]) -> bool {
    let reference =
        reth_evm::revm::precompile::kzg_point_evaluation::arkworks::verify_kzg_proof(c, z, y, p);
    assert_eq!(verify(c, z, y, p), reference);
    reference
}

#[test]
fn nontrivial_valid_proofs_and_mutations_match_revm() {
    // c-kzg's verify_kzg_proof_case_correct_proof_4_4, also used by revm.
    let c = hex("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7");
    let z = hex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000");
    let y = hex("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9");
    let p = hex("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c");
    assert!(check(&c, &z, &y, &p));
    let c = G1Affine::deserialize_compressed(&c[..]).unwrap();
    let p = G1Affine::deserialize_compressed(&p[..]).unwrap();
    let y = scalar(&y).unwrap();
    let mut state = 0x1234_5678_9abc_def0_u64;
    for i in 0..32 {
        let bytes: [u8; 32] = core::array::from_fn(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        });
        let t = if i == 0 {
            Fr::zero()
        } else {
            Fr::from_be_bytes_mod_order(&bytes)
        };
        // Scaling commitment, evaluation and proof preserves a valid opening.
        let commitment = point_bytes(c.mul_bigint(t.into_bigint()).into_affine());
        let proof = point_bytes(p.mul_bigint(t.into_bigint()).into_affine());
        let evaluation = scalar_bytes(y * t);
        assert!(check(&commitment, &z, &evaluation, &proof));
        assert!(!check(
            &commitment,
            &z,
            &scalar_bytes(y * t + Fr::one()),
            &proof
        ));
        // Change the evaluation point as well: C' = C - delta*proof is a
        // valid commitment for the same y at z' = z + delta.
        let delta = Fr::from_be_bytes_mod_order(&bytes);
        let shifted_commitment =
            point_bytes(((c.into_group() - p.mul_bigint(delta.into_bigint())) * t).into_affine());
        assert!(check(
            &shifted_commitment,
            &scalar_bytes(scalar(&z).unwrap() + delta),
            &evaluation,
            &proof,
        ));
        check(
            &commitment,
            &scalar_bytes(Fr::from(i + 1u64)),
            &evaluation,
            &proof,
        );
    }
}

#[test]
fn constants_infinity_and_canonical_scalar_boundaries_match_revm() {
    let infinity = point_bytes(G1Affine::identity());
    for y in [Fr::zero(), Fr::one(), -Fr::one(), Fr::from(1_234_567u64)] {
        let c = point_bytes(
            G1Affine::generator()
                .mul_bigint(y.into_bigint())
                .into_affine(),
        );
        for z in [Fr::zero(), Fr::one(), -Fr::one()] {
            assert!(check(&c, &scalar_bytes(z), &scalar_bytes(y), &infinity));
        }
    }
    let modulus: [u8; 32] = Fr::MODULUS.to_bytes_be().try_into().unwrap();
    for invalid in [modulus, [0xff; 32]] {
        assert!(!check(&infinity, &invalid, &[0; 32], &infinity));
        assert!(!check(&infinity, &[0; 32], &invalid, &infinity));
    }
}

#[test]
fn malformed_points_and_wrong_subgroups_match_revm() {
    let infinity = point_bytes(G1Affine::identity());
    let mut bad_infinity = infinity;
    bad_infinity[47] = 1;
    for malformed in [[0xff; 48], [0; 48], bad_infinity] {
        assert!(!check(&malformed, &[0; 32], &[0; 32], &infinity));
        assert!(!check(&infinity, &[0; 32], &[0; 32], &malformed));
    }
    let mut checked = 0;
    for x in 0..64u64 {
        if let Some(p) = G1Affine::get_point_from_x_unchecked(Fq::from(x), false) {
            if p.is_in_correct_subgroup_assuming_on_curve() {
                continue;
            }
            let p = point_bytes(p);
            assert!(!check(&p, &[0; 32], &[0; 32], &infinity));
            assert!(!check(&infinity, &[0; 32], &[0; 32], &p));
            checked += 1;
        }
    }
    assert!(checked > 8);
}
