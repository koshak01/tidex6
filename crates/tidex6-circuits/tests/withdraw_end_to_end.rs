//! End-to-end test of the Day 9-10 `WithdrawCircuit`:
//!
//! 1. Build a small-depth Merkle tree offchain with several
//!    commitments, including our target `(secret, nullifier)` pair.
//! 2. Request an inclusion proof for the target leaf from the real
//!    `tidex6_core::merkle::MerkleTree`.
//! 3. Run a local trusted setup for `WithdrawCircuit<DEPTH>`.
//! 4. Turn the offchain Merkle proof into a `WithdrawWitness` and
//!    generate a Groth16 proof.
//! 5. Verify with arkworks and with `groth16-solana` (the same
//!    verifier the onchain program will use).
//! 6. Negative case: the proof must be rejected when any of the
//!    three public inputs is tampered with.

use ark_bn254::Fr;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::square::fr_to_be_bytes;
use tidex6_circuits::withdraw::{
    WithdrawWitness, prepare_verifying_key, prove_withdraw, recipient_fr_from_bytes,
    setup_withdraw_circuit, verify_withdraw_proof,
};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

/// Small depth so tests finish in a reasonable amount of time. The
/// production circuit uses depth 20; the gadget logic is identical,
/// only the number of constraints scales.
const TEST_DEPTH: usize = 4;

fn deterministic_test_rng() -> StdRng {
    StdRng::seed_from_u64(0x77_17_d3_a4)
}

/// Build a `TEST_DEPTH` Merkle tree, insert `n_leaves` real
/// commitments, and return the tree plus the `(secret, nullifier)`
/// pair at leaf index `target_leaf_index`.
fn build_tree_with_target(
    n_leaves: usize,
    target_leaf_index: usize,
) -> (MerkleTree, Secret, Nullifier, Commitment) {
    assert!(target_leaf_index < n_leaves);
    let mut tree = MerkleTree::new(TEST_DEPTH).expect("tree");
    let mut target = None;
    for i in 0..n_leaves {
        let secret = Secret::random().expect("secret");
        let nullifier = Nullifier::random().expect("nullifier");
        let commitment = Commitment::derive(&secret, &nullifier).expect("commitment");
        tree.insert(commitment).expect("insert");
        if i == target_leaf_index {
            target = Some((secret, nullifier, commitment));
        }
    }
    let (secret, nullifier, commitment) = target.expect("target");
    (tree, secret, nullifier, commitment)
}

/// Convert a 64-bit leaf index into `TEST_DEPTH` LSB-first bits.
fn leaf_index_bits(leaf_index: u64) -> [bool; TEST_DEPTH] {
    let mut bits = [false; TEST_DEPTH];
    for (i, bit) in bits.iter_mut().enumerate() {
        *bit = (leaf_index >> i) & 1 == 1;
    }
    bits
}

#[test]
fn end_to_end_withdraw_pipeline() {
    // 1-2. Build the tree and grab an inclusion proof.
    let (tree, secret, nullifier, commitment) = build_tree_with_target(5, 2);
    let merkle_proof = tree.proof(2).expect("merkle proof");
    let nullifier_hash = nullifier.derive_hash().expect("nullifier hash");
    let merkle_root = tree.root();

    // Sanity check: the offchain verify_proof must accept before we
    // even think about the circuit.
    let ok_offchain = tidex6_core::merkle::verify_proof(
        commitment,
        &merkle_proof,
        merkle_root,
        TEST_DEPTH,
    )
    .expect("offchain verify");
    assert!(ok_offchain, "offchain merkle verify must accept");

    // 3. Local trusted setup.
    let mut rng = deterministic_test_rng();
    let (pk, vk) = setup_withdraw_circuit::<TEST_DEPTH, _>(&mut rng).expect("setup");

    // 4. Build the witness. `recipient` is an arbitrary 32-byte
    //    identifier; in production this will be a Solana pubkey.
    let recipient_bytes: [u8; 32] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed,
        0xfe, 0x0f,
    ];

    let sibling_bytes: Vec<[u8; 32]> = merkle_proof
        .siblings
        .iter()
        .map(|commitment| *commitment.as_bytes())
        .collect();
    assert_eq!(sibling_bytes.len(), TEST_DEPTH);

    let siblings_refs: [&[u8; 32]; TEST_DEPTH] = [
        &sibling_bytes[0],
        &sibling_bytes[1],
        &sibling_bytes[2],
        &sibling_bytes[3],
    ];

    let witness = WithdrawWitness::<TEST_DEPTH> {
        secret: secret.as_bytes(),
        nullifier: nullifier.as_bytes(),
        path_siblings: siblings_refs,
        path_indices: leaf_index_bits(merkle_proof.leaf_index),
        merkle_root: merkle_root.as_bytes(),
        nullifier_hash: nullifier_hash.as_bytes(),
        recipient: &recipient_bytes,
    };

    let (proof, public_inputs) = prove_withdraw(&pk, witness, &mut rng).expect("prove");

    // 5a. Verify with arkworks.
    let prepared = prepare_verifying_key(&vk);
    let ok = verify_withdraw_proof(&prepared, &proof, &public_inputs).expect("verify");
    assert!(ok, "arkworks verifier must accept the withdraw proof");

    // 5b. Verify with groth16-solana using the converted byte layout.
    let solana_bytes = groth16_to_solana_bytes(&proof, &vk).expect("solana bytes");
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

    let solana_public_inputs: [[u8; 32]; 3] = [
        fr_to_be_bytes(public_inputs[0]),
        fr_to_be_bytes(public_inputs[1]),
        fr_to_be_bytes(public_inputs[2]),
    ];

    let mut verifier = Groth16Verifier::<3>::new(
        proof_a,
        proof_b,
        proof_c,
        &solana_public_inputs,
        &groth_vk,
    )
    .expect("Groth16Verifier::new");

    verifier
        .verify()
        .expect("groth16-solana verifier must accept the withdraw proof");
}

#[test]
fn withdraw_proof_rejects_tampered_public_inputs() {
    let (tree, secret, nullifier, commitment) = build_tree_with_target(4, 1);
    let merkle_proof = tree.proof(1).expect("merkle proof");
    let nullifier_hash = nullifier.derive_hash().expect("nullifier hash");
    let merkle_root = tree.root();
    assert!(
        tidex6_core::merkle::verify_proof(commitment, &merkle_proof, merkle_root, TEST_DEPTH)
            .expect("offchain"),
        "sanity"
    );

    let mut rng = deterministic_test_rng();
    let (pk, vk) = setup_withdraw_circuit::<TEST_DEPTH, _>(&mut rng).expect("setup");

    let recipient_bytes = [0x11u8; 32];
    let sibling_bytes: Vec<[u8; 32]> = merkle_proof
        .siblings
        .iter()
        .map(|c| *c.as_bytes())
        .collect();
    let siblings_refs: [&[u8; 32]; TEST_DEPTH] = [
        &sibling_bytes[0],
        &sibling_bytes[1],
        &sibling_bytes[2],
        &sibling_bytes[3],
    ];

    let witness = WithdrawWitness::<TEST_DEPTH> {
        secret: secret.as_bytes(),
        nullifier: nullifier.as_bytes(),
        path_siblings: siblings_refs,
        path_indices: leaf_index_bits(merkle_proof.leaf_index),
        merkle_root: merkle_root.as_bytes(),
        nullifier_hash: nullifier_hash.as_bytes(),
        recipient: &recipient_bytes,
    };

    let (proof, correct_public_inputs) = prove_withdraw(&pk, witness, &mut rng).expect("prove");

    let prepared = prepare_verifying_key(&vk);

    // Correct input — baseline.
    assert!(
        verify_withdraw_proof(&prepared, &proof, &correct_public_inputs).expect("verify"),
        "baseline must accept"
    );

    // Tamper with the Merkle root.
    let bad_root = [
        correct_public_inputs[0] + Fr::from(1u64),
        correct_public_inputs[1],
        correct_public_inputs[2],
    ];
    assert!(
        !verify_withdraw_proof(&prepared, &proof, &bad_root).expect("verify"),
        "must reject wrong root"
    );

    // Tamper with the nullifier hash.
    let bad_nullifier_hash = [
        correct_public_inputs[0],
        correct_public_inputs[1] + Fr::from(1u64),
        correct_public_inputs[2],
    ];
    assert!(
        !verify_withdraw_proof(&prepared, &proof, &bad_nullifier_hash).expect("verify"),
        "must reject wrong nullifier hash"
    );

    // Tamper with the recipient.
    let bad_recipient = [
        correct_public_inputs[0],
        correct_public_inputs[1],
        recipient_fr_from_bytes(&[0x22u8; 32]),
    ];
    assert!(
        !verify_withdraw_proof(&prepared, &proof, &bad_recipient).expect("verify"),
        "must reject wrong recipient"
    );
}

#[test]
fn withdraw_proof_rejects_wrong_leaf_index() {
    // The prover uses index bits that point to the wrong leaf
    // position — the Merkle path walks to the wrong root.
    let (tree, secret, nullifier, commitment) = build_tree_with_target(6, 3);
    let merkle_proof = tree.proof(3).expect("merkle proof");
    let nullifier_hash = nullifier.derive_hash().expect("nullifier hash");
    let merkle_root = tree.root();
    assert!(
        tidex6_core::merkle::verify_proof(commitment, &merkle_proof, merkle_root, TEST_DEPTH)
            .expect("offchain"),
        "sanity"
    );

    let mut rng = deterministic_test_rng();
    let (pk, _vk) = setup_withdraw_circuit::<TEST_DEPTH, _>(&mut rng).expect("setup");

    let recipient_bytes = [0x33u8; 32];
    let sibling_bytes: Vec<[u8; 32]> = merkle_proof
        .siblings
        .iter()
        .map(|c| *c.as_bytes())
        .collect();
    let siblings_refs: [&[u8; 32]; TEST_DEPTH] = [
        &sibling_bytes[0],
        &sibling_bytes[1],
        &sibling_bytes[2],
        &sibling_bytes[3],
    ];

    // Correct leaf index is 3 (bits [1, 1, 0, 0]); feed [0, 0, 0, 0]
    // instead — the circuit cannot be satisfied.
    let witness = WithdrawWitness::<TEST_DEPTH> {
        secret: secret.as_bytes(),
        nullifier: nullifier.as_bytes(),
        path_siblings: siblings_refs,
        path_indices: [false; TEST_DEPTH],
        merkle_root: merkle_root.as_bytes(),
        nullifier_hash: nullifier_hash.as_bytes(),
        recipient: &recipient_bytes,
    };

    // arkworks panics inside `prove` when the constraint system is
    // not satisfied (same pattern as `prove_fails_for_inconsistent_witnesses`
    // in `deposit_end_to_end.rs`). Catch it and treat a panic as
    // success.
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        prove_withdraw(&pk, witness, &mut rng)
    }));
    std::panic::set_hook(previous_hook);

    match attempt {
        Err(_panic) => {}
        Ok(Err(_err)) => {}
        Ok(Ok(_)) => panic!("prover must refuse inconsistent merkle path"),
    }
}

#[test]
fn withdraw_circuit_compiles_at_production_depth() {
    // Smoke test: confirm the production depth-20 circuit at least
    // synthesises (setup completes). Prove/verify at depth 20 is
    // covered separately in a slower ignored test if we decide to
    // benchmark it.
    let mut rng = deterministic_test_rng();
    let _ = setup_withdraw_circuit::<20, _>(&mut rng).expect("setup depth 20");
}
