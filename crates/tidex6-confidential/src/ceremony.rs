//! Self-test of a ceremony key for the hidden-amount withdraw circuit.
//!
//! Why this is a separate function rather than a flag on
//! `tidex6_circuits::ceremony`: the self-test builds a real witness and proves
//! with it — and the witness has a different shape for each circuit. The old
//! one proves five public inputs and a two-element commitment; this one proves
//! eight inputs and a three-element commitment. Shared code would branch at
//! every step, and any branch someone forgot would silently check the wrong
//! thing.
//!
//! What stays shared: `CircomReduction` (the key comes from snarkjs), the zkey
//! parser, and the `withdraw_vk.rs` renderer — all taken from the older crate
//! as they are.

use std::io::{Read, Seek};

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use thiserror::Error;
use tidex6_circuits::circom_qap::CircomReduction;
use tidex6_circuits::zkey::{ZkeyError, read_zkey_pk};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

use crate::bytes::{fr_from_u64, fr_to_be_bytes, split_pubkey};
use crate::withdraw::{
    POOL_TREE_DEPTH, WITHDRAW_NR_PUBLIC_INPUTS, WithdrawCircuit, note_commitment, nullifier_hash,
};

#[derive(Error, Debug)]
pub enum SelftestError {
    #[error("zkey parse: {0}")]
    Zkey(#[from] ZkeyError),
    #[error("core: {0}")]
    Core(String),
    #[error("prove: {0}")]
    Prove(String),
    #[error("verify: {0}")]
    Verify(String),
    #[error("proof rejected — key does not encode a working hidden-amount withdraw setup")]
    Rejected,
}

/// Read a zkey and prove that it encodes a working setup of **this** circuit.
pub fn selftest_zkey<R: Read + Seek>(
    reader: &mut R,
    seed: u64,
) -> Result<VerifyingKey<Bn254>, SelftestError> {
    let pk = read_zkey_pk(reader)?;
    selftest_pk(&pk, seed)
}

/// Like [`selftest_zkey`], but for an already parsed key — e.g. taken from a
/// `CeremonyState` after contributions.
///
/// `seed` fixes the prover RNG. This is a functional check, not a production
/// proof: zero-knowledge is not required here, reproducibility is — two people
/// running it on the same key must get the same result.
pub fn selftest_pk(
    pk: &ProvingKey<Bn254>,
    seed: u64,
) -> Result<VerifyingKey<Bn254>, SelftestError> {
    let core = |e: &dyn std::fmt::Display| SelftestError::Core(e.to_string());

    // A note with an amount: three-element commitment, as in the production circuit.
    let secret = Secret::random().map_err(|e| core(&e))?;
    let nullifier = Nullifier::random().map_err(|e| core(&e))?;
    let amount: u64 = 1_250_000; // 1.25 tokens in base units; any non-zero value works

    let secret_fr = Fr::from_be_bytes_mod_order(secret.as_bytes());
    let nullifier_fr = Fr::from_be_bytes_mod_order(nullifier.as_bytes());
    let amount_fr = fr_from_u64(amount);
    let commitment_fr = note_commitment(secret_fr, nullifier_fr, amount_fr);
    let nullifier_hash_fr = nullifier_hash(nullifier_fr);

    // Same tree core as on chain; the leaf is the bytes of the three-element commitment.
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH).map_err(|e| core(&e))?;
    tree.insert(Commitment::from_bytes(fr_to_be_bytes(commitment_fr)))
        .map_err(|e| core(&e))?;
    let merkle_proof = tree.proof(0).map_err(|e| core(&e))?;
    let merkle_root_fr = Fr::from_be_bytes_mod_order(tree.root().as_bytes());

    let mut siblings = [Fr::from(0u64); POOL_TREE_DEPTH];
    for (slot, sib) in siblings.iter_mut().zip(merkle_proof.siblings.iter()) {
        *slot = Fr::from_be_bytes_mod_order(sib.as_bytes());
    }
    let mut path_indices = [false; POOL_TREE_DEPTH];
    for (i, bit) in path_indices.iter_mut().enumerate() {
        *bit = (merkle_proof.leaf_index >> i) & 1 == 1;
    }

    // Recipient and relayer as full keys, two halves each.
    let (recipient_hi, recipient_lo) = split_pubkey(&[0x11u8; 32]);
    let (relayer_hi, relayer_lo) = split_pubkey(&[0x42u8; 32]);
    let fee_fr = fr_from_u64(0);

    let circuit = WithdrawCircuit {
        amount: Some(amount_fr),
        secret: Some(secret_fr),
        nullifier: Some(nullifier_fr),
        path_siblings: Some(siblings),
        path_indices: Some(path_indices),
        merkle_root: Some(merkle_root_fr),
        nullifier_hash: Some(nullifier_hash_fr),
        recipient_hi: Some(recipient_hi),
        recipient_lo: Some(recipient_lo),
        relayer_hi: Some(relayer_hi),
        relayer_lo: Some(relayer_lo),
        relayer_fee: Some(fee_fr),
        amount_public: Some(amount_fr),
    };

    let mut rng = StdRng::seed_from_u64(seed);
    let proof = Groth16::<Bn254, CircomReduction>::prove(pk, circuit, &mut rng)
        .map_err(|e| SelftestError::Prove(e.to_string()))?;

    let public: [Fr; WITHDRAW_NR_PUBLIC_INPUTS] = [
        merkle_root_fr,
        nullifier_hash_fr,
        recipient_hi,
        recipient_lo,
        relayer_hi,
        relayer_lo,
        fee_fr,
        amount_fr,
    ];
    let ok = Groth16::<Bn254>::verify(&pk.vk, &public, &proof)
        .map_err(|e| SelftestError::Verify(e.to_string()))?;
    if !ok {
        return Err(SelftestError::Rejected);
    }
    Ok(pk.vk.clone())
}
