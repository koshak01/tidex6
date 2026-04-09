//! Equivalence tests for the in-circuit Poseidon gadget.
//!
//! The entire tidex6 shielded pool depends on one invariant: the
//! Poseidon hash computed offchain by
//! `tidex6_core::poseidon::hash_pair` must byte-for-byte match the
//! Poseidon hash computed inside a Groth16 circuit by
//! `tidex6_circuits::poseidon_gadget::poseidon_hash_pair_var`. If
//! this invariant ever breaks, every commitment produced offchain
//! will fail the in-circuit check, and every withdrawal proof will
//! be rejected.
//!
//! These tests exercise the gadget at the constraint-system level
//! without actually running a Groth16 proof: we allocate the
//! inputs as witnesses, run the gadget, and read the resulting
//! value out of the constraint system to compare with the offchain
//! hash.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::R1CSVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::ConstraintSystem;
use tidex6_circuits::poseidon_gadget::{poseidon_hash_n_var, poseidon_hash_pair_var};
use tidex6_core::poseidon;

/// Convert a `Fr` field element to its 32-byte big-endian
/// encoding. Used to cross-check against `tidex6_core::poseidon`
/// which exposes byte slices.
fn fr_to_be_bytes(value: Fr) -> [u8; 32] {
    let bigint = value.into_bigint();
    let mut bytes = bigint.to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.append(&mut bytes);
        bytes = padded;
    }
    bytes.try_into().expect("Fr always fits in 32 bytes")
}

/// Convert a 32-byte big-endian value that is guaranteed to be a
/// valid BN254 scalar into a `Fr`. Only used in tests where we
/// control the input.
fn fr_from_be_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// In-circuit `Poseidon(a, b)` on the canonical test vector
/// `([1u8; 32], [2u8; 32])` must match the canonical output
/// documented in both `light-poseidon` and `solana-poseidon`.
#[test]
fn pair_matches_canonical_vector() {
    let cs = ConstraintSystem::<Fr>::new_ref();

    let a_bytes = [1u8; 32];
    let b_bytes = [2u8; 32];

    let a_fr = fr_from_be_bytes(&a_bytes);
    let b_fr = fr_from_be_bytes(&b_bytes);

    let a_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(a_fr)).expect("alloc a");
    let b_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(b_fr)).expect("alloc b");

    let hash_var = poseidon_hash_pair_var(cs.clone(), &a_var, &b_var).expect("circuit hash");
    assert!(cs.is_satisfied().expect("cs satisfied check"));

    let circuit_bytes = fr_to_be_bytes(hash_var.value().expect("readout"));
    assert_eq!(
        circuit_bytes,
        [
            13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132,
            254, 156, 162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144
        ],
        "in-circuit Poseidon must produce the canonical upstream test vector",
    );
}

/// The gadget and the offchain `tidex6_core::poseidon::hash_pair`
/// must agree for arbitrary inputs within the BN254 scalar field.
#[test]
fn pair_matches_offchain_wrapper_random() {
    let test_pairs: [([u8; 32], [u8; 32]); 3] = [
        ([0x07; 32], [0x0A; 32]),
        (
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
            ],
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x02,
            ],
        ),
        ([0x11; 32], [0x22; 32]),
    ];

    for (a_bytes, b_bytes) in test_pairs {
        // Offchain ground truth.
        let offchain = poseidon::hash_pair(&a_bytes, &b_bytes).expect("offchain hash");

        // In-circuit computation.
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a_fr = fr_from_be_bytes(&a_bytes);
        let b_fr = fr_from_be_bytes(&b_bytes);
        let a_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(a_fr)).expect("alloc a");
        let b_var = FpVar::<Fr>::new_witness(cs.clone(), || Ok(b_fr)).expect("alloc b");
        let hash_var = poseidon_hash_pair_var(cs.clone(), &a_var, &b_var).expect("circuit hash");
        assert!(cs.is_satisfied().expect("cs satisfied check"));
        let circuit_bytes = fr_to_be_bytes(hash_var.value().expect("readout"));

        assert_eq!(
            offchain, circuit_bytes,
            "offchain and in-circuit Poseidon must agree on ({a_bytes:?}, {b_bytes:?})"
        );
    }
}

/// The n-ary form must match the offchain wrapper for widths 1, 3,
/// and 5. Catches width-specific constant indexing bugs that a pair
/// test would miss.
#[test]
fn n_ary_matches_offchain_wrapper() {
    let cases: &[&[[u8; 32]]] = &[
        &[[0x03; 32]],
        &[[0x01; 32], [0x02; 32], [0x03; 32]],
        &[[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32], [0x05; 32]],
    ];

    for case in cases {
        let offchain_inputs: Vec<&[u8; 32]> = case.iter().collect();
        let offchain = poseidon::hash(&offchain_inputs).expect("offchain hash");

        let cs = ConstraintSystem::<Fr>::new_ref();
        let input_vars: Vec<FpVar<Fr>> = case
            .iter()
            .enumerate()
            .map(|(i, bytes)| {
                FpVar::<Fr>::new_witness(cs.clone(), || Ok(fr_from_be_bytes(bytes)))
                    .unwrap_or_else(|_| panic!("alloc input {i}"))
            })
            .collect();

        let hash_var = poseidon_hash_n_var(cs.clone(), &input_vars).expect("circuit hash");
        assert!(cs.is_satisfied().expect("cs satisfied check"));

        let circuit_bytes = fr_to_be_bytes(hash_var.value().expect("readout"));
        assert_eq!(
            offchain,
            circuit_bytes,
            "offchain vs circuit disagree on {}-input hash",
            case.len()
        );
    }
}
