//! End-to-end test of the Day-6 pipeline:
//!
//! 1. Run a local Groth16 trusted setup for `SquareCircuit`.
//! 2. Generate a proof that x = 7, y = 49.
//! 3. Verify the proof with arkworks.
//! 4. Convert the proof and verifying key into groth16-solana byte
//!    layout.
//! 5. Verify the proof with `groth16_solana::Groth16Verifier`
//!    using the converted bytes, off-chain (no RPC).
//!
//! A successful run proves that our own code can produce a
//! verifying key and a proof that the onchain `tidex6-verifier`
//! program will accept, because the same crate
//! (`groth16-solana`) performs the verification in both cases
//! and uses the same `alt_bn128` syscalls onchain and offchain.

use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::square::{
    fr_to_be_bytes, prepare_verifying_key, prove_square, setup_square_circuit, square,
    verify_square_proof,
};

/// Produce a deterministic CryptoRng for tests. Arkworks' plain
/// `test_rng()` is only `Rng`, not `CryptoRng`, which our
/// signatures require so production callers have to pass a
/// cryptographically secure source.
fn deterministic_test_rng() -> StdRng {
    StdRng::seed_from_u64(0xdead_beef)
}

#[test]
fn end_to_end_square_pipeline() {
    // 1. Local Groth16 setup. Uses the deterministic test RNG so
    //    the test is reproducible across machines.
    let mut rng = deterministic_test_rng();
    let (pk, vk) = setup_square_circuit(&mut rng).expect("setup");

    // 2. Generate a proof for x = 7, y = 49.
    let (proof, y_fr) = prove_square(&pk, 7, &mut rng).expect("prove");
    assert_eq!(y_fr, square(7));

    // 3. Verify with arkworks (uses the raw VK on the prover side
    //    of the pipeline).
    let prepared = prepare_verifying_key(&vk);
    let ok = verify_square_proof(&prepared, &proof, y_fr).expect("verify arkworks");
    assert!(ok, "arkworks verifier must accept a valid proof");

    // 4. Convert everything to the groth16-solana byte layout.
    let solana_bytes = groth16_to_solana_bytes(&proof, &vk).expect("convert to solana bytes");
    let Groth16SolanaBytes {
        proof_a,
        proof_b,
        proof_c,
        vk_alpha_g1,
        vk_beta_g2,
        vk_gamma_g2,
        vk_delta_g2,
        vk_ic,
    } = &solana_bytes;

    // 5. Verify with the groth16-solana crate, offchain.
    //    Construct a Groth16Verifyingkey from our converted bytes
    //    and run the same verification path the onchain program
    //    will run.
    let vk_ic_slices: Vec<[u8; 64]> = vk_ic.clone();
    let groth_vk = Groth16Verifyingkey {
        nr_pubinputs: vk_ic_slices.len(),
        vk_alpha_g1: *vk_alpha_g1,
        vk_beta_g2: *vk_beta_g2,
        vk_gamme_g2: *vk_gamma_g2,
        vk_delta_g2: *vk_delta_g2,
        vk_ic: &vk_ic_slices,
    };

    let y_bytes = fr_to_be_bytes(y_fr);
    let public_inputs: [[u8; 32]; 1] = [y_bytes];

    let mut verifier =
        Groth16Verifier::<1>::new(proof_a, proof_b, proof_c, &public_inputs, &groth_vk)
            .expect("Groth16Verifier::new");

    verifier
        .verify()
        .expect("groth16-solana offchain verify must accept our proof");
}

/// A proof produced for one `y` must not verify against a
/// different `y`. Protects against trivial mis-wiring of the
/// public-input byte conversion.
#[test]
fn proof_does_not_verify_for_wrong_public_input() {
    let mut rng = deterministic_test_rng();
    let (pk, vk) = setup_square_circuit(&mut rng).expect("setup");

    let (proof, _y_fr) = prove_square(&pk, 7, &mut rng).expect("prove");

    let prepared = prepare_verifying_key(&vk);
    let wrong_y = square(8); // claim x = 8 while proof was for x = 7
    let ok = verify_square_proof(&prepared, &proof, wrong_y).expect("verify");
    assert!(!ok, "arkworks verifier must reject wrong public input");
}
