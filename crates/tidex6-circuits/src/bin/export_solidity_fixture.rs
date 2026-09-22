//! Produce a real withdraw proof and print it as EVM calldata.
//!
//! `export_solidity_verifier` emits the contract; this emits the test vector
//! that proves the contract actually accepts our proofs. Together they let
//! anyone reproduce the claim "tidex6 proofs verify on an EVM chain" without
//! trusting us: regenerate both, run the Solidity test, watch it pass.
//!
//! The proof is generated with the same development setup the dev-mode
//! verifier is built from, at the production tree depth, so the fixture
//! exercises exactly the deployed constants.
//!
//! Usage:
//!
//! ```text
//! cargo run --bin export_solidity_fixture --release
//! ```
//!
//! Writes `contracts/test/fixture.json` and prints it.

use std::fs;

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;

use tidex6_circuits::ceremony::find_workspace_root;
use tidex6_circuits::withdraw::{
    WITHDRAW_TREE_DEPTH, WithdrawWitness, prepare_verifying_key, prove_withdraw,
    relayer_fee_bytes_from_u64, setup_withdraw_circuit, verify_withdraw_proof,
};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

/// Same seed as `export_solidity_verifier`, so the fixture matches the
/// verifier it is meant to exercise.
const DEV_SETUP_SEED: u64 = 0x7715_ef25_d061_3517;

/// Seed for proof randomness. Fixed so the fixture is reproducible.
const PROVER_SEED: u64 = 0x51_0d_17_ff_ec_a0_1e_05;

/// Leaf the withdraw proof will be about.
const TARGET_LEAF: u64 = 2;

/// Decimal string of a base-field element.
fn fq_decimal(value: &Fq) -> String {
    decimal_from_be(&value.into_bigint().to_bytes_be())
}

/// Decimal string of a scalar-field element.
fn fr_decimal(value: &Fr) -> String {
    decimal_from_be(&value.into_bigint().to_bytes_be())
}

/// Convert big-endian bytes into a decimal string by repeated division.
fn decimal_from_be(bytes: &[u8]) -> String {
    let mut work = bytes.to_vec();
    let mut digits: Vec<u8> = Vec::new();

    while work.iter().any(|byte| *byte != 0) {
        let mut remainder = 0u16;
        for byte in work.iter_mut() {
            let current = (remainder << 8) | u16::from(*byte);
            *byte = (current / 10) as u8;
            remainder = current % 10;
        }
        digits.push(remainder as u8);
    }

    if digits.is_empty() {
        return "0".to_string();
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

/// G1 point as `[x, y]` decimals.
fn g1_pair(point: &G1Affine) -> [String; 2] {
    [fq_decimal(&point.x), fq_decimal(&point.y)]
}

/// G2 point as `[[x.c1, x.c0], [y.c1, y.c0]]` — EVM pairing order.
fn g2_pairs(point: &G2Affine) -> [[String; 2]; 2] {
    let flip = |c: &Fq2| [fq_decimal(&c.c1), fq_decimal(&c.c0)];
    [flip(&point.x), flip(&point.y)]
}

/// Turn a leaf index into `WITHDRAW_TREE_DEPTH` LSB-first bits.
fn leaf_index_bits(leaf_index: u64) -> [bool; WITHDRAW_TREE_DEPTH] {
    let mut bits = [false; WITHDRAW_TREE_DEPTH];
    for (index, bit) in bits.iter_mut().enumerate() {
        *bit = (leaf_index >> index) & 1 == 1;
    }
    bits
}

fn main() {
    println!("building a depth-{WITHDRAW_TREE_DEPTH} tree…");
    let mut tree = MerkleTree::new(WITHDRAW_TREE_DEPTH).expect("tree");
    let mut target = None;
    for index in 0..5 {
        let secret = Secret::random().expect("secret");
        let nullifier = Nullifier::random().expect("nullifier");
        let commitment = Commitment::derive(&secret, &nullifier).expect("commitment");
        tree.insert(commitment).expect("insert");
        if index == TARGET_LEAF as usize {
            target = Some((secret, nullifier));
        }
    }
    let (secret, nullifier) = target.expect("target leaf");

    let merkle_proof = tree.proof(TARGET_LEAF).expect("merkle proof");
    let nullifier_hash = nullifier.derive_hash().expect("nullifier hash");
    let merkle_root = tree.root();

    println!("running the DEVELOPMENT setup (seed 0x{DEV_SETUP_SEED:016x})…");
    let mut setup_rng = StdRng::seed_from_u64(DEV_SETUP_SEED);
    let (pk, vk) = setup_withdraw_circuit::<WITHDRAW_TREE_DEPTH, _>(&mut setup_rng).expect("setup");

    let sibling_bytes: Vec<[u8; 32]> = merkle_proof
        .siblings
        .iter()
        .map(|commitment| *commitment.as_bytes())
        .collect();
    assert_eq!(sibling_bytes.len(), WITHDRAW_TREE_DEPTH);
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] = std::array::from_fn(|i| &sibling_bytes[i]);

    let recipient_bytes = [0x11u8; 32];
    let relayer_address_bytes = [0x42u8; 32];
    let relayer_fee_bytes = relayer_fee_bytes_from_u64(0);

    let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
        secret: secret.as_bytes(),
        nullifier: nullifier.as_bytes(),
        path_siblings: sibling_refs,
        path_indices: leaf_index_bits(merkle_proof.leaf_index),
        merkle_root: merkle_root.as_bytes(),
        nullifier_hash: nullifier_hash.as_bytes(),
        recipient: &recipient_bytes,
        relayer_address: &relayer_address_bytes,
        relayer_fee: &relayer_fee_bytes,
    };

    println!("proving…");
    let mut prover_rng = StdRng::seed_from_u64(PROVER_SEED);
    let (proof, public_inputs) = prove_withdraw(&pk, witness, &mut prover_rng).expect("prove");

    // Offchain gate: never emit a fixture the arkworks verifier rejects.
    let prepared = prepare_verifying_key(&vk);
    let accepted = verify_withdraw_proof(&prepared, &proof, &public_inputs).expect("verify");
    assert!(
        accepted,
        "arkworks rejected our own proof — refusing to emit"
    );
    println!("arkworks verifier accepts the proof");

    let Proof { a, b, c } = proof;
    let a_pair = g1_pair(&a);
    let b_pairs = g2_pairs(&b);
    let c_pair = g1_pair(&c);
    let inputs: Vec<String> = public_inputs.iter().map(fr_decimal).collect();

    let json = format!(
        r#"{{
  "_comment": "Development-key fixture for Tidex6Verifier.sol. Regenerate with `cargo run --bin export_solidity_fixture --release`.",
  "a": ["{a0}", "{a1}"],
  "b": [["{b00}", "{b01}"], ["{b10}", "{b11}"]],
  "c": ["{c0}", "{c1}"],
  "publicInputs": ["{i0}", "{i1}", "{i2}", "{i3}", "{i4}"]
}}
"#,
        a0 = a_pair[0],
        a1 = a_pair[1],
        b00 = b_pairs[0][0],
        b01 = b_pairs[0][1],
        b10 = b_pairs[1][0],
        b11 = b_pairs[1][1],
        c0 = c_pair[0],
        c1 = c_pair[1],
        i0 = inputs[0],
        i1 = inputs[1],
        i2 = inputs[2],
        i3 = inputs[3],
        i4 = inputs[4],
    );

    let out_dir = find_workspace_root().join("contracts/test");
    fs::create_dir_all(&out_dir).expect("create contracts/test");
    let out_path = out_dir.join("fixture.json");
    fs::write(&out_path, json.as_bytes()).expect("write fixture.json");

    println!("\n{json}");
    println!("wrote {}", out_path.display());
}
