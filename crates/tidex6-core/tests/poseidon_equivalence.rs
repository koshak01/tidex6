//! Day-1 Validation Checklist — Test 1: Poseidon equivalence.
//!
//! This integration test enforces the first kill gate from
//! `docs/release/security.md` section 3: the offchain Poseidon wrapper
//! in `tidex6_core::poseidon` must produce byte-for-byte identical output
//! to the `solana-poseidon` reference implementation on the same inputs.
//!
//! On native targets, `solana-poseidon::hashv` is itself a thin wrapper
//! around `light-poseidon` with circom parameters, so this test confirms
//! that the plumbing in `tidex6_core::poseidon` is wired identically to
//! the canonical path. The further step — validating equivalence against
//! the real onchain `sol_poseidon` syscall — happens inside the verifier
//! program test harness once that crate exists, and is not in scope
//! here.
//!
//! The canonical test vector used below is documented in the public
//! docstrings of both `light_poseidon` and `solana_poseidon`. If any
//! upstream version silently changes round constants or parameter sets,
//! this test fails immediately.

use solana_poseidon::{Endianness, Parameters, hashv};
use tidex6_core::poseidon;

/// Canonical test vector from `light_poseidon` 0.4 and `solana_poseidon` 4.0
/// documentation: `Poseidon(Bn254X5, BigEndian, [[1u8; 32], [2u8; 32]])`.
const EXPECTED_HASH_ONES_TWOS_BE: [u8; 32] = [
    13, 84, 225, 147, 143, 138, 140, 28, 125, 235, 94, 3, 85, 242, 99, 25, 32, 123, 132, 254, 156,
    162, 206, 27, 38, 231, 53, 200, 41, 130, 25, 144,
];

/// The wrapper produces the canonical two-input hash that both upstream
/// crates document. This is the single most important invariant in the
/// project: if it breaks, every commitment computed offchain will diverge
/// from the onchain syscall result, and the entire shielded pool becomes
/// unusable.
#[test]
fn wrapper_matches_canonical_vector_ones_twos() {
    let left = [1u8; 32];
    let right = [2u8; 32];

    let result =
        poseidon::hash_pair(&left, &right).expect("hashing two valid field elements must succeed");

    assert_eq!(
        result, EXPECTED_HASH_ONES_TWOS_BE,
        "tidex6_core::poseidon::hash_pair diverges from the canonical vector. \
         Day-1 kill gate failed. See docs/release/security.md section 2.2."
    );
}

/// The wrapper matches `solana-poseidon::hashv` on the two-input case.
/// On native targets both libraries share the same code path, so this
/// test is a plumbing smoke test: it fails only if `tidex6_core::poseidon`
/// constructs the hasher with wrong parameters or passes inputs in the
/// wrong order.
#[test]
fn wrapper_matches_solana_poseidon_reference_two_inputs() {
    let left = [1u8; 32];
    let right = [2u8; 32];

    let ours = poseidon::hash_pair(&left, &right).expect("wrapper hash must succeed");
    let reference = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&left, &right])
        .expect("reference hash must succeed")
        .to_bytes();

    assert_eq!(
        ours, reference,
        "tidex6 wrapper diverges from solana-poseidon reference on two inputs"
    );
}

/// Matches the reference implementation for three inputs as well. This
/// guards against a plumbing bug that only shows up at wider hasher
/// configurations.
#[test]
fn wrapper_matches_solana_poseidon_reference_three_inputs() {
    let first = [1u8; 32];
    let second = [2u8; 32];
    let third = [3u8; 32];

    let ours = poseidon::hash(&[&first, &second, &third]).expect("wrapper hash must succeed");
    let reference = hashv(
        Parameters::Bn254X5,
        Endianness::BigEndian,
        &[&first, &second, &third],
    )
    .expect("reference hash must succeed")
    .to_bytes();

    assert_eq!(ours, reference, "tidex6 wrapper diverges on three inputs");
}

/// Matches the reference implementation at the maximum supported input
/// count (12). This is the widest configuration circom Poseidon supports
/// and therefore the one most likely to expose width-related plumbing
/// bugs.
#[test]
fn wrapper_matches_solana_poseidon_reference_max_inputs() {
    let block = [7u8; 32];
    let inputs: Vec<&[u8; 32]> = (0..12).map(|_| &block).collect();
    let reference_inputs: Vec<&[u8]> = inputs.iter().map(|slice| slice.as_slice()).collect();

    let ours = poseidon::hash(&inputs).expect("wrapper hash must succeed at max width");
    let reference = hashv(
        Parameters::Bn254X5,
        Endianness::BigEndian,
        &reference_inputs,
    )
    .expect("reference hash must succeed at max width")
    .to_bytes();

    assert_eq!(
        ours, reference,
        "tidex6 wrapper diverges from reference at 12 inputs (maximum width)"
    );
}

/// Zero inputs are rejected by the wrapper with a clear error, rather
/// than delegating to `light-poseidon` which would return a less
/// specific upstream error.
#[test]
fn rejects_empty_input() {
    let empty: &[&[u8; 32]] = &[];
    let result = poseidon::hash(empty);
    assert!(
        matches!(
            result,
            Err(poseidon::PoseidonError::UnsupportedInputCount(0))
        ),
        "empty input must be rejected with UnsupportedInputCount(0), got {result:?}"
    );
}

/// More than 12 inputs are rejected with `UnsupportedInputCount`.
#[test]
fn rejects_too_many_inputs() {
    let block = [9u8; 32];
    let inputs: Vec<&[u8; 32]> = (0..13).map(|_| &block).collect();

    let result = poseidon::hash(&inputs);
    assert!(
        matches!(
            result,
            Err(poseidon::PoseidonError::UnsupportedInputCount(13))
        ),
        "thirteen inputs must be rejected with UnsupportedInputCount(13), got {result:?}"
    );
}

/// An input byte slice whose big-endian value exceeds the BN254 scalar
/// field modulus must be rejected. We construct an "all ones" 32-byte
/// value, which is larger than the modulus.
#[test]
fn rejects_input_larger_than_modulus() {
    let over_modulus = [0xFFu8; 32];
    let small = [0x01u8; 32];

    let result = poseidon::hash_pair(&over_modulus, &small);
    assert!(
        matches!(result, Err(poseidon::PoseidonError::Hasher(_))),
        "input exceeding the BN254 modulus must be rejected, got {result:?}"
    );
}
