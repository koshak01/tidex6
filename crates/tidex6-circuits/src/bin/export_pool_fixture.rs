//! Produce a withdraw proof bound to EVM addresses, for the pool test.
//!
//! `export_solidity_fixture` proves the verifier accepts our proofs.
//! This proves something stronger: that a tree built by the Solidity pool
//! and a tree built by our Rust client arrive at the *same root*, and that
//! a proof against that root spends correctly with EVM addresses as the
//! recipient and relayer.
//!
//! If the roots disagree, deposits made on an EVM pool could never be
//! withdrawn — so this fixture is the one that has to pass before any value
//! goes near the contract.
//!
//! Usage:
//!
//! ```text
//! cargo run --bin export_pool_fixture --release
//! ```

use std::fs;

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;

use tidex6_circuits::ceremony::find_workspace_root;
use tidex6_circuits::withdraw::{
    WITHDRAW_TREE_DEPTH, WithdrawWitness, prepare_verifying_key, prove_withdraw,
    setup_withdraw_circuit, verify_withdraw_proof,
};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

/// Same development seed as the verifier export.
const DEV_SETUP_SEED: u64 = 0x7715_ef25_d061_3517;

/// Deterministic proof randomness.
const PROVER_SEED: u64 = 0xf00d_5e11_a17e_0001;

/// Fixed test note. Both values start with 0x01, so they are comfortably
/// below the BN254 modulus and are valid field elements.
const TEST_SECRET: [u8; 32] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

/// Fixed test nullifier.
const TEST_NULLIFIER: [u8; 32] = [
    0x01, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
    0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
];

/// Recipient in the test — an ordinary EVM address.
const RECIPIENT: [u8; 20] = [
    0xA4, 0x39, 0xAd, 0x51, 0x90, 0x46, 0xCC, 0xd7, 0x05, 0x6D, 0xdf, 0x74, 0xfb, 0xaA, 0xc9, 0x9d,
    0x74, 0x0B, 0xdf, 0x09,
];

/// Relayer in the test.
const RELAYER: [u8; 20] = [
    0x8f, 0x4f, 0x72, 0xdd, 0x44, 0x21, 0xbc, 0x39, 0xaf, 0x3b, 0x3f, 0xf1, 0x45, 0xe0, 0x70, 0x2f,
    0x6a, 0xc9, 0x5f, 0xb9,
];

/// Fee paid to the relayer, in the token's smallest unit.
///
/// 0.1 of a token at six decimals — the same floor the Solana side charges, and
/// the same shape of number a person sees in the interface. It was a whole
/// token here, which is invisible while the fixture is only a fixture: the test
/// used a denomination of 100, so a fee of 1 looked ordinary. On a pool whose
/// denomination is one token, that same fixture hands the recipient nothing and
/// the entire payment to the relayer — the withdrawal succeeds and the money
/// goes to the wrong place, which is the worst way for a demo to be wrong.
const FEE: u64 = 100_000;


/// EIP-55 checksummed form of an address.
///
/// Solidity rejects an all-lowercase address literal on purpose: the mixed
/// case carries a checksum, so a single mistyped character will not compile.
/// Emitting the lowercase form and letting a human "fix" it by hand defeats
/// exactly the protection that exists to catch a wrong payout address.
fn to_checksum_address(address: &[u8; 20]) -> String {
    use sha3::{Digest, Keccak256};

    let lower: String = address.iter().map(|b| format!("{b:02x}")).collect();
    let hash = Keccak256::digest(lower.as_bytes());

    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (index, ch) in lower.chars().enumerate() {
        let nibble = if index % 2 == 0 {
            hash[index / 2] >> 4
        } else {
            hash[index / 2] & 0x0f
        };
        if ch.is_ascii_digit() || nibble < 8 {
            out.push(ch);
        } else {
            out.push(ch.to_ascii_uppercase());
        }
    }
    out
}

/// An EVM address as a field element: left-padded to 32 bytes. Always below
/// the modulus, since an address is 160 bits.
fn address_to_field_bytes(address: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address);
    out
}

/// A `u64` as a big-endian field element.
fn u64_to_field_bytes(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

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
        return "0".into();
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

fn fq_decimal(value: &Fq) -> String {
    decimal_from_be(&value.into_bigint().to_bytes_be())
}

fn fr_decimal(value: &Fr) -> String {
    decimal_from_be(&value.into_bigint().to_bytes_be())
}

fn g1_pair(point: &G1Affine) -> [String; 2] {
    [fq_decimal(&point.x), fq_decimal(&point.y)]
}

fn g2_pairs(point: &G2Affine) -> [[String; 2]; 2] {
    let flip = |c: &Fq2| [fq_decimal(&c.c1), fq_decimal(&c.c0)];
    [flip(&point.x), flip(&point.y)]
}

fn leaf_index_bits(leaf_index: u64) -> [bool; WITHDRAW_TREE_DEPTH] {
    let mut bits = [false; WITHDRAW_TREE_DEPTH];
    for (index, bit) in bits.iter_mut().enumerate() {
        *bit = (leaf_index >> index) & 1 == 1;
    }
    bits
}

fn main() {
    // One deposit into an empty tree — exactly what the pool test does.
    //
    // The note is built from fixed test bytes rather than a seeded RNG:
    // `Secret::random` takes entropy from the OS and must keep doing so, since
    // a predictable secret is a stolen deposit. These are obviously-test
    // values, not a weakened generator.
    let secret = Secret::from_bytes(TEST_SECRET);
    let nullifier = Nullifier::from_bytes(TEST_NULLIFIER);
    let commitment = Commitment::derive(&secret, &nullifier).expect("commitment");

    let mut tree = MerkleTree::new(WITHDRAW_TREE_DEPTH).expect("tree");
    tree.insert(commitment).expect("insert");

    let merkle_proof = tree.proof(0).expect("merkle proof");
    let nullifier_hash = nullifier.derive_hash().expect("nullifier hash");
    let merkle_root = tree.root();

    println!("single-deposit tree, depth {WITHDRAW_TREE_DEPTH}");
    println!("  commitment = {}", decimal_from_be(commitment.as_bytes()));
    println!("  root       = {}", decimal_from_be(merkle_root.as_bytes()));

    println!("running the DEVELOPMENT setup…");
    let mut setup_rng = StdRng::seed_from_u64(DEV_SETUP_SEED);
    let (pk, vk) = setup_withdraw_circuit::<WITHDRAW_TREE_DEPTH, _>(&mut setup_rng).expect("setup");

    let sibling_bytes: Vec<[u8; 32]> = merkle_proof
        .siblings
        .iter()
        .map(|commitment| *commitment.as_bytes())
        .collect();
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] = std::array::from_fn(|i| &sibling_bytes[i]);

    let recipient_bytes = address_to_field_bytes(&RECIPIENT);
    let relayer_bytes = address_to_field_bytes(&RELAYER);
    let fee_bytes = u64_to_field_bytes(FEE);

    let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
        secret: secret.as_bytes(),
        nullifier: nullifier.as_bytes(),
        path_siblings: sibling_refs,
        path_indices: leaf_index_bits(merkle_proof.leaf_index),
        merkle_root: merkle_root.as_bytes(),
        nullifier_hash: nullifier_hash.as_bytes(),
        recipient: &recipient_bytes,
        relayer_address: &relayer_bytes,
        relayer_fee: &fee_bytes,
    };

    println!("proving…");
    let mut prover_rng = StdRng::seed_from_u64(PROVER_SEED);
    let (proof, public_inputs) = prove_withdraw(&pk, witness, &mut prover_rng).expect("prove");

    let prepared = prepare_verifying_key(&vk);
    assert!(
        verify_withdraw_proof(&prepared, &proof, &public_inputs).expect("verify"),
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
  "_comment": "Pool fixture: one deposit into an empty depth-20 tree, withdrawn to an EVM address. Regenerate with `cargo run --bin export_pool_fixture --release`.",
  "commitment": "{commitment}",
  "root": "{root}",
  "nullifierHash": "{nullifier_hash}",
  "recipient": "{recipient_hex}",
  "relayer": "{relayer_hex}",
  "fee": "{fee}",
  "a": ["{a0}", "{a1}"],
  "b": [["{b00}", "{b01}"], ["{b10}", "{b11}"]],
  "c": ["{c0}", "{c1}"],
  "publicInputs": ["{i0}", "{i1}", "{i2}", "{i3}", "{i4}"]
}}
"#,
        commitment = decimal_from_be(commitment.as_bytes()),
        root = decimal_from_be(merkle_root.as_bytes()),
        nullifier_hash = decimal_from_be(nullifier_hash.as_bytes()),
        recipient_hex = to_checksum_address(&RECIPIENT),
        relayer_hex = to_checksum_address(&RELAYER),
        fee = FEE,
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
    let out_path = out_dir.join("pool_fixture.json");
    fs::write(&out_path, json.as_bytes()).expect("write pool_fixture.json");

    println!("\n{json}");
    println!("wrote {}", out_path.display());
}
