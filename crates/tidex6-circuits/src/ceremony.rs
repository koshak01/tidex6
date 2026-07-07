//! Rust-native самопроверка церемониального zkey (Путь A) — используется
//! координатором вклада на сервере (без Node).
//!
//! `selftest_zkey` читает snarkjs zkey нашим парсером, строит валидный
//! withdraw-witness, прувит с `CircomReduction` и верифицирует. Если проходит —
//! zkey функционально корректен (задаёт рабочий Groth16-setup нашей схемы),
//! и возвращается его `VerifyingKey` (для сравнения delta / извлечения VK).

use std::io::{Read, Seek};

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use thiserror::Error;

use crate::circom_qap::CircomReduction;
use crate::withdraw::{WithdrawCircuit, WITHDRAW_TREE_DEPTH};
use crate::zkey::{read_zkey_pk, ZkeyError};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

const DEPTH: usize = WITHDRAW_TREE_DEPTH;

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
    #[error("proof rejected — zkey does not encode a working withdraw setup")]
    Rejected,
}

/// Прочитать zkey + доказать, что он задаёт рабочий Groth16-setup нашей схемы.
/// Возвращает `VerifyingKey` при успехе.
///
/// `seed` фиксирует RNG прувера — это ЛИШЬ функциональный self-test (не
/// production-proof), zero-knowledge здесь не требуется.
pub fn selftest_zkey<R: Read + Seek>(reader: &mut R, seed: u64) -> Result<VerifyingKey<Bn254>, SelftestError> {
    let pk = read_zkey_pk(reader)?;
    selftest_pk(&pk, seed)
}

/// Как [`selftest_zkey`], но принимает уже распарсенный `ProvingKey` (например,
/// после MPC-вклада, когда pk в памяти, а не в zkey-байтах).
pub fn selftest_pk(
    pk: &ark_groth16::ProvingKey<Bn254>,
    seed: u64,
) -> Result<VerifyingKey<Bn254>, SelftestError> {
    // Валидный depth-20 withdraw-witness.
    let secret = Secret::random().map_err(|e| SelftestError::Core(e.to_string()))?;
    let nullifier = Nullifier::random().map_err(|e| SelftestError::Core(e.to_string()))?;
    let commitment =
        Commitment::derive(&secret, &nullifier).map_err(|e| SelftestError::Core(e.to_string()))?;
    let nullifier_hash = nullifier
        .derive_hash()
        .map_err(|e| SelftestError::Core(e.to_string()))?;
    let mut tree = MerkleTree::new(DEPTH).map_err(|e| SelftestError::Core(e.to_string()))?;
    tree.insert(commitment).map_err(|e| SelftestError::Core(e.to_string()))?;
    let merkle_proof = tree.proof(0).map_err(|e| SelftestError::Core(e.to_string()))?;
    let merkle_root = tree.root();

    let recipient_bytes = [0x11u8; 32];
    let relayer_bytes = [0x42u8; 32];

    let secret_fr = Fr::from_be_bytes_mod_order(secret.as_bytes());
    let nullifier_fr = Fr::from_be_bytes_mod_order(nullifier.as_bytes());
    let merkle_root_fr = Fr::from_be_bytes_mod_order(merkle_root.as_bytes());
    let nullifier_hash_fr = Fr::from_be_bytes_mod_order(nullifier_hash.as_bytes());
    let recipient_fr = Fr::from_be_bytes_mod_order(&recipient_bytes);
    let relayer_fr = Fr::from_be_bytes_mod_order(&relayer_bytes);
    let fee_fr = Fr::from(0u64);

    let mut siblings = [Fr::from(0u64); DEPTH];
    for (slot, sib) in siblings.iter_mut().zip(merkle_proof.siblings.iter()) {
        *slot = Fr::from_be_bytes_mod_order(sib.as_bytes());
    }
    let mut path_indices = [false; DEPTH];
    for (i, bit) in path_indices.iter_mut().enumerate() {
        *bit = (merkle_proof.leaf_index >> i) & 1 == 1;
    }

    let circuit = WithdrawCircuit::<DEPTH> {
        secret: Some(secret_fr),
        nullifier: Some(nullifier_fr),
        path_siblings: Some(siblings),
        path_indices: Some(path_indices),
        merkle_root: Some(merkle_root_fr),
        nullifier_hash: Some(nullifier_hash_fr),
        recipient: Some(recipient_fr),
        relayer_address: Some(relayer_fr),
        relayer_fee: Some(fee_fr),
    };

    let mut rng = StdRng::seed_from_u64(seed);
    let proof = Groth16::<Bn254, CircomReduction>::prove(&pk, circuit, &mut rng)
        .map_err(|e| SelftestError::Prove(e.to_string()))?;

    let public = [merkle_root_fr, nullifier_hash_fr, recipient_fr, relayer_fr, fee_fr];
    let ok = Groth16::<Bn254>::verify(&pk.vk, &public, &proof)
        .map_err(|e| SelftestError::Verify(e.to_string()))?;
    if !ok {
        return Err(SelftestError::Rejected);
    }
    Ok(pk.vk.clone())
}
