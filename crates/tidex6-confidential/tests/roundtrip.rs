//! End-to-end крипто-ядра Этапа 2: скрытая сумма доказывается и принимается
//! on-chain-путём (`groth16-solana`), с настоящим Merkle-деревом пула.
//!
//! Оба доказательства проверяются дважды: off-chain arkworks и байт-в-байт
//! через `groth16-solana` — тем же крейтом, что крутит верификатор на mainnet.

use ark_bn254::Fr;
use ark_ff::{PrimeField, UniformRand};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tidex6_confidential::bytes::fr_to_be_bytes;
use tidex6_confidential::onchain::verify_onchain_compat;
use tidex6_confidential::transfer::{self, TransferWitness, TRANSFER_NR_PUBLIC_INPUTS};
use tidex6_confidential::withdraw::{
    self, note_commitment, WithdrawWitness, POOL_TREE_DEPTH, WITHDRAW_NR_PUBLIC_INPUTS,
};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::Commitment;

/// Fr → байты публичного входа для on-chain-проверки.
fn pi_bytes<const N: usize>(inputs: &[Fr; N]) -> [[u8; 32]; N] {
    core::array::from_fn(|i| fr_to_be_bytes(inputs[i]))
}

/// Строит дерево с единственным листом `commitment`, возвращает путь для
/// membership-доказательства: siblings как `Fr`, index-биты, корень как `Fr`.
fn tree_with_leaf(commitment: Fr) -> ([Fr; POOL_TREE_DEPTH], [bool; POOL_TREE_DEPTH], Fr) {
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH).expect("tree");
    let leaf = Commitment::from_bytes(fr_to_be_bytes(commitment));
    let (leaf_index, _root) = tree.insert(leaf).expect("insert");
    let proof = tree.proof(leaf_index).expect("proof");

    let mut siblings = [Fr::from(0u64); POOL_TREE_DEPTH];
    for (dst, sib) in siblings.iter_mut().zip(proof.siblings.iter()) {
        *dst = Fr::from_be_bytes_mod_order(sib.as_bytes());
    }
    let mut index_bits = [false; POOL_TREE_DEPTH];
    for (i, bit) in index_bits.iter_mut().enumerate() {
        *bit = (leaf_index >> i) & 1 == 1;
    }
    let root = Fr::from_be_bytes_mod_order(&proof.root.to_bytes());
    (siblings, index_bits, root)
}

#[test]
fn withdraw_hidden_amount_verifies_onchain() {
    let mut rng = StdRng::seed_from_u64(0xD1D6_0001);
    let (pk, vk) = withdraw::setup(&mut rng).expect("setup");

    let secret = Fr::rand(&mut rng);
    let nullifier = Fr::rand(&mut rng);
    let amount: u64 = 250_000_000; // 250 USDC при decimals=6

    let commitment = note_commitment(secret, nullifier, Fr::from(amount));
    let (path_siblings, path_indices, merkle_root) = tree_with_leaf(commitment);

    let mut recipient = [0u8; 32];
    let mut relayer = [0u8; 32];
    rng.fill_bytes(&mut recipient);
    rng.fill_bytes(&mut relayer);

    let witness = WithdrawWitness {
        amount,
        secret,
        nullifier,
        path_siblings,
        path_indices,
        merkle_root,
        recipient,
        relayer,
        relayer_fee: 0,
    };

    let (proof, public_inputs) = withdraw::prove(&pk, &witness, &mut rng).expect("prove");

    // off-chain
    let prepared = withdraw::prepare_vk(&vk);
    assert!(
        withdraw::verify(&prepared, &proof, &public_inputs).expect("verify"),
        "off-chain withdraw verify failed"
    );

    // on-chain-совместимый путь (groth16-solana)
    let pi = pi_bytes(&public_inputs);
    assert!(
        verify_onchain_compat::<WITHDRAW_NR_PUBLIC_INPUTS>(&proof, &vk, &pi),
        "on-chain-compat withdraw verify failed"
    );
}

#[test]
fn transfer_hidden_amounts_verify_onchain() {
    let mut rng = StdRng::seed_from_u64(0x7A5F_u64);
    let (pk, vk) = transfer::setup(&mut rng).expect("setup");

    // Входная нота на 1000, делится на 600 (получателю) + 400 (сдача).
    let secret_in = Fr::rand(&mut rng);
    let nullifier_in = Fr::rand(&mut rng);
    let amount_in: u64 = 1000;

    let commitment_in = note_commitment(secret_in, nullifier_in, Fr::from(amount_in));
    let (path_siblings, path_indices, merkle_root) = tree_with_leaf(commitment_in);

    let witness = TransferWitness {
        amount_in,
        secret_in,
        nullifier_in,
        path_siblings,
        path_indices,
        amount_out1: 600,
        secret_out1: Fr::rand(&mut rng),
        nullifier_out1: Fr::rand(&mut rng),
        amount_out2: 400,
        secret_out2: Fr::rand(&mut rng),
        nullifier_out2: Fr::rand(&mut rng),
        merkle_root,
    };

    let (proof, public_inputs) = transfer::prove(&pk, &witness, &mut rng).expect("prove");

    let prepared = transfer::prepare_vk(&vk);
    assert!(
        transfer::verify(&prepared, &proof, &public_inputs).expect("verify"),
        "off-chain transfer verify failed"
    );

    let pi = pi_bytes(&public_inputs);
    assert!(
        verify_onchain_compat::<TRANSFER_NR_PUBLIC_INPUTS>(&proof, &vk, &pi),
        "on-chain-compat transfer verify failed"
    );
}

/// Conservation обязателен: out1 + out2 != in делает систему констрейнтов
/// невыполнимой — proof построить нельзя. Проверяем каноническим способом
/// (synthesize + is_satisfied), а не через panic-fail arkworks-prover'а.
#[test]
fn transfer_rejects_value_inflation() {
    use ark_relations::r1cs::ConstraintSystem;
    use tidex6_confidential::transfer::TransferCircuit;

    let mut rng = StdRng::seed_from_u64(0xBADF_u64);

    let secret_in = Fr::rand(&mut rng);
    let nullifier_in = Fr::rand(&mut rng);
    let amount_in: u64 = 1000;
    let commitment_in = note_commitment(secret_in, nullifier_in, Fr::from(amount_in));
    let (path_siblings, path_indices, merkle_root) = tree_with_leaf(commitment_in);

    // Пытаемся выпустить 600 + 500 = 1100 из 1000 (инфляция).
    let amount_out1 = 600u64;
    let amount_out2 = 500u64;
    let secret_out1 = Fr::rand(&mut rng);
    let nullifier_out1 = Fr::rand(&mut rng);
    let secret_out2 = Fr::rand(&mut rng);
    let nullifier_out2 = Fr::rand(&mut rng);
    let c_out1 = note_commitment(secret_out1, nullifier_out1, Fr::from(amount_out1));
    let c_out2 = note_commitment(secret_out2, nullifier_out2, Fr::from(amount_out2));

    let nh = tidex6_confidential::withdraw::nullifier_hash(nullifier_in);
    let circuit = TransferCircuit {
        amount_in: Some(Fr::from(amount_in)),
        secret_in: Some(secret_in),
        nullifier_in: Some(nullifier_in),
        path_siblings: Some(path_siblings),
        path_indices: Some(path_indices),
        amount_out1: Some(Fr::from(amount_out1)),
        secret_out1: Some(secret_out1),
        nullifier_out1: Some(nullifier_out1),
        amount_out2: Some(Fr::from(amount_out2)),
        secret_out2: Some(secret_out2),
        nullifier_out2: Some(nullifier_out2),
        merkle_root: Some(merkle_root),
        nullifier_hash: Some(nh),
        commitment_out1: Some(c_out1),
        commitment_out2: Some(c_out2),
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    use ark_relations::r1cs::ConstraintSynthesizer;
    circuit
        .generate_constraints(cs.clone())
        .expect("synthesis runs");
    assert!(
        !cs.is_satisfied().expect("satisfiability check"),
        "inflation (600+500 > 1000) must leave conservation constraint unsatisfied"
    );
}
