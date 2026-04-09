//! End-to-end test of the Day 7-8 `DepositCircuit` pipeline:
//!
//! 1. Generate a `(Secret, Nullifier)` offchain via `tidex6-core`.
//! 2. Derive the commitment via `Commitment::derive` (the same
//!    Poseidon hash the onchain Merkle tree uses).
//! 3. Run a local Groth16 Phase-2 setup for `DepositCircuit`.
//! 4. Produce a Groth16 proof of
//!    `Poseidon(secret, nullifier) == commitment`.
//! 5. Verify the proof with arkworks.
//! 6. Convert the proof and verifying key into the groth16-solana
//!    byte layout and verify again with `Groth16Verifier`, offchain.
//! 7. Negative case: a proof produced for one commitment must not
//!    verify against a different commitment.

use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use tidex6_circuits::deposit::{
    prepare_verifying_key, prove_deposit, setup_deposit_circuit, verify_deposit_proof,
};
use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::square::fr_to_be_bytes;
use tidex6_core::types::{Commitment, Nullifier, Secret};

/// Deterministic RNG so the test is reproducible across machines.
fn deterministic_test_rng() -> StdRng {
    StdRng::seed_from_u64(0xd61_0517)
}

#[test]
fn end_to_end_deposit_pipeline() {
    // 1. Generate secret / nullifier offchain.
    let secret = Secret::random().expect("secret");
    let nullifier = Nullifier::random().expect("nullifier");

    // 2. Commitment = Poseidon(secret, nullifier) — the offchain
    //    wrapper the onchain pool also uses.
    let commitment = Commitment::derive(&secret, &nullifier).expect("derive commitment");

    // 3. Local trusted setup (DEVELOPMENT ONLY).
    let mut rng = deterministic_test_rng();
    let (pk, vk) = setup_deposit_circuit(&mut rng).expect("setup");

    // 4. Prove `Poseidon(secret, nullifier) == commitment`.
    let (proof, commitment_fr) = prove_deposit(
        &pk,
        secret.as_bytes(),
        nullifier.as_bytes(),
        commitment.as_bytes(),
        &mut rng,
    )
    .expect("prove");

    // 5. Verify with arkworks.
    let prepared = prepare_verifying_key(&vk);
    let ok = verify_deposit_proof(&prepared, &proof, commitment_fr).expect("verify");
    assert!(ok, "arkworks verifier must accept the deposit proof");

    // 6. Verify with groth16-solana using the converted byte layout.
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

    let vk_ic_slices: Vec<[u8; 64]> = vk_ic.clone();
    let groth_vk = Groth16Verifyingkey {
        nr_pubinputs: vk_ic_slices.len(),
        vk_alpha_g1: *vk_alpha_g1,
        vk_beta_g2: *vk_beta_g2,
        vk_gamme_g2: *vk_gamma_g2,
        vk_delta_g2: *vk_delta_g2,
        vk_ic: &vk_ic_slices,
    };

    let commitment_bytes = fr_to_be_bytes(commitment_fr);
    let public_inputs: [[u8; 32]; 1] = [commitment_bytes];

    let mut verifier =
        Groth16Verifier::<1>::new(proof_a, proof_b, proof_c, &public_inputs, &groth_vk)
            .expect("Groth16Verifier::new");

    verifier
        .verify()
        .expect("groth16-solana offchain verify must accept our deposit proof");
}

/// Negative test: a proof for commitment A must not verify against
/// commitment B. Guards against public-input wiring mistakes.
#[test]
fn proof_rejects_wrong_commitment() {
    let secret = Secret::random().expect("secret");
    let nullifier = Nullifier::random().expect("nullifier");
    let commitment = Commitment::derive(&secret, &nullifier).expect("derive");

    let mut rng = deterministic_test_rng();
    let (pk, vk) = setup_deposit_circuit(&mut rng).expect("setup");

    let (proof, _commitment_fr) = prove_deposit(
        &pk,
        secret.as_bytes(),
        nullifier.as_bytes(),
        commitment.as_bytes(),
        &mut rng,
    )
    .expect("prove");

    // Craft a different, valid commitment from an unrelated pair.
    let other_secret = Secret::random().expect("other secret");
    let other_nullifier = Nullifier::random().expect("other nullifier");
    let wrong_commitment =
        Commitment::derive(&other_secret, &other_nullifier).expect("derive other");

    let wrong_fr =
        <ark_bn254::Fr as ark_ff::PrimeField>::from_be_bytes_mod_order(wrong_commitment.as_bytes());
    let prepared = prepare_verifying_key(&vk);
    let ok = verify_deposit_proof(&prepared, &proof, wrong_fr).expect("verify");
    assert!(!ok, "arkworks verifier must reject wrong commitment");
}

/// Negative test: witnesses that do not hash to the claimed
/// commitment must not produce a valid proof. arkworks 0.5 panics
/// inside `Groth16::prove` when the constraint system is not
/// satisfied (an internal `assert!(cs.is_satisfied())`), so we
/// catch the unwind and treat a panic as success.
#[test]
fn prove_fails_for_inconsistent_witnesses() {
    let secret = Secret::random().expect("secret");
    let nullifier = Nullifier::random().expect("nullifier");
    let real_commitment = Commitment::derive(&secret, &nullifier).expect("derive");

    // Use a commitment from a different pair — the witnesses cannot
    // satisfy `Poseidon(secret, nullifier) == wrong_commitment`.
    let other_secret = Secret::random().expect("other secret");
    let other_nullifier = Nullifier::random().expect("other nullifier");
    let wrong_commitment =
        Commitment::derive(&other_secret, &other_nullifier).expect("derive other");
    assert_ne!(real_commitment.as_bytes(), wrong_commitment.as_bytes());

    let mut rng = deterministic_test_rng();
    let (pk, _vk) = setup_deposit_circuit(&mut rng).expect("setup");

    // Silence the arkworks panic message so the test output stays
    // readable. We restore the default hook afterwards.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove_deposit(
            &pk,
            secret.as_bytes(),
            nullifier.as_bytes(),
            wrong_commitment.as_bytes(),
            &mut rng,
        )
    }));
    std::panic::set_hook(previous_hook);

    match attempt {
        // arkworks panicked — that's the "prover refuses" path.
        Err(_panic) => {}
        // If it didn't panic it must at least return an error.
        Ok(Err(_err)) => {}
        Ok(Ok(_)) => panic!("prover must refuse inconsistent witnesses"),
    }
}
