//! Экспорт валидного witness нашего `WithdrawCircuit<20>` в circom/iden3
//! `.wtns` формат — для дефинитивной проверки церемонии (Путь A).
//!
//! Строим реальный depth-20 inclusion-proof, синтезируем схему в Prove-режиме,
//! вынимаем полный assignment (instance ++ witness) в порядке проводов r1cs и
//! пишем `.wtns`. Дальше: `snarkjs groth16 prove withdraw_0002.zkey withdraw.wtns
//! proof.json public.json` + `snarkjs groth16 verify vk.json public.json
//! proof.json`. Если verify проходит — коэффициенты r1cs верны, setup — для
//! нашей схемы, весь Путь A валиден end-to-end.
//!
//! Запуск: cargo run -p tidex6-circuits --bin export_wtns
//! Выход:  crates/tidex6-circuits/artifacts/withdraw.wtns (+ печать 5 public)

use std::io::Write;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use tidex6_circuits::withdraw::{WithdrawCircuit, WITHDRAW_TREE_DEPTH};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

const DEPTH: usize = WITHDRAW_TREE_DEPTH;

fn main() {
    // ── Валидный inclusion-proof: один лист в depth-20 дереве ──────────
    let secret = Secret::random().expect("secret");
    let nullifier = Nullifier::random().expect("nullifier");
    let commitment = Commitment::derive(&secret, &nullifier).expect("commitment");
    let nullifier_hash = nullifier.derive_hash().expect("nullifier hash");

    let mut tree = MerkleTree::new(DEPTH).expect("tree");
    tree.insert(commitment).expect("insert");
    let merkle_proof = tree.proof(0).expect("merkle proof");
    let merkle_root = tree.root();

    assert!(
        tidex6_core::merkle::verify_proof(commitment, &merkle_proof, merkle_root, DEPTH)
            .expect("offchain verify"),
        "offchain merkle verify must accept"
    );

    // Публичные поля (как в тесте): произвольный recipient / relayer, fee=0.
    let recipient_bytes: [u8; 32] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed,
        0xfe, 0x0f,
    ];
    let relayer_address_bytes: [u8; 32] = [0x42u8; 32];

    // ── Конверсия в circuit-поля (как prove_withdraw внутри) ───────────
    let secret_fr = Fr::from_be_bytes_mod_order(secret.as_bytes());
    let nullifier_fr = Fr::from_be_bytes_mod_order(nullifier.as_bytes());
    let merkle_root_fr = Fr::from_be_bytes_mod_order(merkle_root.as_bytes());
    let nullifier_hash_fr = Fr::from_be_bytes_mod_order(nullifier_hash.as_bytes());
    let recipient_fr = Fr::from_be_bytes_mod_order(&recipient_bytes);
    let relayer_address_fr = Fr::from_be_bytes_mod_order(&relayer_address_bytes);
    let relayer_fee_fr = Fr::from(0u64);

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
        relayer_address: Some(relayer_address_fr),
        relayer_fee: Some(relayer_fee_fr),
    };

    // ── Синтез в Prove-режиме → полный assignment ──────────────────────
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .expect("generate_constraints");
    cs.finalize();
    assert!(
        cs.is_satisfied().expect("is_satisfied"),
        "witness must satisfy the circuit before export"
    );

    let cs_inner = cs.into_inner().expect("into_inner");
    let instance = cs_inner.instance_assignment.clone();
    let witness = cs_inner.witness_assignment.clone();

    // Полный вектор проводов: [one, pub1..pub5, priv...] — порядок r1cs.
    let full: Vec<Fr> = instance.iter().chain(witness.iter()).copied().collect();
    let n_witness = full.len() as u32;

    println!("wires (n_witness): {n_witness}");
    println!("public inputs (5, decimal):");
    // instance[0] = ONE, instance[1..6] = 5 публичных входов.
    for (i, v) in instance.iter().skip(1).enumerate() {
        println!("  [{i}] {}", fr_to_dec(v));
    }

    // ── Header (section 1) ─────────────────────────────────────────────
    let mut header = Vec::new();
    header.extend_from_slice(&32u32.to_le_bytes()); // n8
    let mut prime = Fr::MODULUS.to_bytes_le();
    prime.resize(32, 0);
    header.extend_from_slice(&prime);
    header.extend_from_slice(&n_witness.to_le_bytes());

    // ── Witness data (section 2): nWitness × 32-byte LE ────────────────
    let mut data = Vec::with_capacity(full.len() * 32);
    for v in &full {
        let mut b = v.into_bigint().to_bytes_le();
        b.resize(32, 0);
        data.extend_from_slice(&b);
    }

    // ── Собрать файл ───────────────────────────────────────────────────
    let mut out = Vec::new();
    out.extend_from_slice(b"wtns");
    out.extend_from_slice(&2u32.to_le_bytes()); // version
    out.extend_from_slice(&2u32.to_le_bytes()); // nSections
    write_section(&mut out, 1, &header);
    write_section(&mut out, 2, &data);

    let home = std::env::var("HOME").unwrap();
    let path = format!("{home}/work/rust/tidex6/crates/tidex6-circuits/artifacts/withdraw.wtns");
    let mut f = std::fs::File::create(&path).expect("create wtns");
    f.write_all(&out).expect("write wtns");
    println!("wrote {} ({} bytes)", path, out.len());
}

/// Fr → десятичная строка (для сверки с snarkjs public.json).
fn fr_to_dec(v: &Fr) -> String {
    let bytes = v.into_bigint().to_bytes_be();
    // маленький bignum→dec без внешних крейтов
    let mut digits = vec![0u8; 1];
    for &byte in &bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let cur = (*d as u32) * 256 + carry;
            *d = (cur % 10) as u8;
            carry = cur / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn write_section(out: &mut Vec<u8>, section_type: u32, data: &[u8]) {
    out.extend_from_slice(&section_type.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
}
