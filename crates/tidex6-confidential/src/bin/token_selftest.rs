//! Self-test of the confidential-token circuits: constraint counts, a real
//! setup, one proof per circuit, verification — and the native ElGamal round
//! trip (encrypt, homomorphic subtract, decrypt, decode). Run before touching
//! the contracts: the numbers here decide whether the design fits the browser.
//!
//! ```text
//! cargo run --release -p tidex6-confidential --bin token_selftest
//! ```

use std::time::Instant;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use tidex6_confidential::bytes::{fr_from_u64, fr_to_be_bytes};
use tidex6_confidential::token::deposit::{self, DepositFromTokenCircuit, DepositFromTokenWitness};
use tidex6_confidential::token::elgamal::{self, PublicKey, SecretKey};
use tidex6_confidential::token::exit::{self, WithdrawToTokenCircuit, WithdrawToTokenWitness};
use tidex6_confidential::token::pubkey::{self, PubkeyValidityCircuit};
use tidex6_confidential::token::transfer::{self, TokenTransferCircuit, TokenTransferWitness};
use tidex6_confidential::token::unwrap::{self, TokenUnwrapCircuit, TokenUnwrapWitness};
use tidex6_confidential::withdraw::{note_commitment, POOL_TREE_DEPTH};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::Commitment;

fn hex(f: &Fr) -> String {
    let bytes = f.into_bigint().to_bytes_be();
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn count_constraints<C: ConstraintSynthesizer<Fr>>(circuit: C) -> (usize, usize) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    // Setup mode: the shape is counted without assignments, like setup does.
    cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).expect("synthesize");
    (cs.num_constraints(), cs.num_instance_variables() - 1)
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0x7469_6465_7836_5f43); // "tidex6_C"

    // ── generators ───────────────────────────────────────────────────
    let g = elgamal::generator_g();
    let h = elgamal::generator_h();
    println!("G = ({}, {})", hex(&g.x), hex(&g.y));
    println!("H = ({}, {})", hex(&h.x), hex(&h.y));

    // ── native round trip ────────────────────────────────────────────
    let alice = SecretKey::random(&mut rng);
    let bob = SecretKey::random(&mut rng);
    let alice_pk = alice.public_key().expect("pk");
    let bob_pk = bob.public_key().expect("pk");

    let wrap = elgamal::plain(1_000_000);
    let r = elgamal::random_opening(&mut rng);
    let payment = elgamal::encrypt(&alice_pk, 250_000, r);
    let remaining = elgamal::sub(&wrap, &payment);
    let decoded = elgamal::decode_amount(&alice.decrypt_point(&remaining), 32).expect("decode");
    println!("native: wrap 1_000_000, pay 250_000, remaining decodes to {decoded}");
    assert_eq!(decoded, 750_000);
    let bob_view = elgamal::Ciphertext { commitment: payment.commitment, handle: bob_pk.handle(r) };
    assert_eq!(elgamal::decode_amount(&bob.decrypt_point(&bob_view), 32).expect("decode"), 250_000);
    assert!(elgamal::opens_to(&payment.commitment, 250_000, r));
    assert!(!elgamal::opens_to(&payment.commitment, 250_001, r));

    // ── pubkey circuit ───────────────────────────────────────────────
    let (n, inputs) = count_constraints(PubkeyValidityCircuit::default());
    println!("PubkeyValidity: {n} constraints, {inputs} public inputs");
    let t = Instant::now();
    let (pk_key, vk_key) = pubkey::setup(&mut rng).expect("setup");
    println!("  setup {:?}", t.elapsed());
    let t = Instant::now();
    let (proof, public) = pubkey::prove(&pk_key, &alice, &alice_pk, &mut rng).expect("prove");
    println!("  prove {:?}", t.elapsed());
    let ok = pubkey::verify(&pubkey::prepare_vk(&vk_key), &proof, &public).expect("verify");
    println!("  verify: {ok}");
    assert!(ok);

    // ── transfer circuit ─────────────────────────────────────────────
    let (n, inputs) = count_constraints(TokenTransferCircuit::default());
    println!("TokenTransfer: {n} constraints, {inputs} public inputs");
    let t = Instant::now();
    let (pk_tr, vk_tr) = transfer::setup(&mut rng).expect("setup");
    println!("  setup {:?}", t.elapsed());
    let witness = TokenTransferWitness {
        secret: alice.clone(),
        balance: 1_000_000,
        available: wrap,
        amount: 250_000,
        opening: r,
        recipient: bob_pk,
        auditor: PublicKey(alice_pk.0),
    };
    let t = Instant::now();
    let (proof, public) = transfer::prove(&pk_tr, &witness, &mut rng).expect("prove");
    println!("  prove {:?}", t.elapsed());
    let prepared = transfer::prepare_vk(&vk_tr);
    let ok = transfer::verify(&prepared, &proof, &public.inputs()).expect("verify");
    println!("  verify: {ok}");
    assert!(ok);
    // The same proof must fail on a tampered amount commitment.
    let mut tampered = public.inputs();
    tampered[6] += Fr::from(1u64);
    let bad = transfer::verify(&prepared, &proof, &tampered).expect("verify");
    println!("  verify (tampered): {bad}");
    assert!(!bad);
    // Overspending must not even synthesize a witness.
    let overspend = TokenTransferWitness { amount: 1_000_001, ..witness };
    assert!(transfer::prove(&pk_tr, &overspend, &mut rng).is_err());
    println!("  overspend rejected");

    // ── unwrap circuit ───────────────────────────────────────────────
    let (n, inputs) = count_constraints(TokenUnwrapCircuit::default());
    println!("TokenUnwrap: {n} constraints, {inputs} public inputs");
    let t = Instant::now();
    let (pk_un, vk_un) = unwrap::setup(&mut rng).expect("setup");
    println!("  setup {:?}", t.elapsed());
    let t = Instant::now();
    let (proof, public) = unwrap::prove(
        &pk_un,
        &TokenUnwrapWitness { secret: alice.clone(), balance: 1_000_000, available: wrap, amount: 400_000 },
        &mut rng,
    )
    .expect("prove");
    println!("  prove {:?}", t.elapsed());
    let ok = unwrap::verify(&unwrap::prepare_vk(&vk_un), &proof, &public).expect("verify");
    println!("  verify: {ok}");
    assert!(ok);

    // ── deposit-from-token circuit ───────────────────────────────────
    let (n, inputs) = count_constraints(DepositFromTokenCircuit::default());
    println!("DepositFromToken: {n} constraints, {inputs} public inputs");
    let t = Instant::now();
    let (pk_dep, vk_dep) = deposit::setup(&mut rng).expect("setup");
    println!("  setup {:?}", t.elapsed());
    let note_secret = Fr::from(0x5ec2e7_u64);
    let note_nullifier = Fr::from(0x4011_u64);
    let t = Instant::now();
    let (proof, public) = deposit::prove(
        &pk_dep,
        &DepositFromTokenWitness {
            secret: alice.clone(),
            balance: 1_000_000,
            available: wrap,
            amount: 300_000,
            opening: r,
            note_secret,
            note_nullifier,
        },
        &mut rng,
    )
    .expect("prove");
    println!("  prove {:?}", t.elapsed());
    let ok = deposit::verify(&deposit::prepare_vk(&vk_dep), &proof, &public.inputs()).expect("verify");
    println!("  verify: {ok}");
    assert!(ok);

    // ── withdraw-to-token circuit ────────────────────────────────────
    let (n, inputs) = count_constraints(WithdrawToTokenCircuit::default());
    println!("WithdrawToToken: {n} constraints, {inputs} public inputs");
    let t = Instant::now();
    let (pk_ex, vk_ex) = exit::setup(&mut rng).expect("setup");
    println!("  setup {:?}", t.elapsed());
    // The note deposited above sits at leaf 0 of an otherwise empty tree.
    let leaf = note_commitment(note_secret, note_nullifier, fr_from_u64(300_000));
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH).expect("tree");
    tree.insert(Commitment::from_bytes(fr_to_be_bytes(leaf))).expect("insert");
    let merkle_proof = tree.proof(0).expect("proof");
    let mut siblings = [Fr::from(0u64); POOL_TREE_DEPTH];
    for (slot, sibling) in siblings.iter_mut().zip(merkle_proof.siblings.iter()) {
        *slot = Fr::from_be_bytes_mod_order(sibling.as_bytes());
    }
    let mut indices = [false; POOL_TREE_DEPTH];
    for (i, bit) in indices.iter_mut().enumerate() {
        *bit = (merkle_proof.leaf_index >> i) & 1 == 1;
    }
    let t = Instant::now();
    let (proof, public) = exit::prove(
        &pk_ex,
        &WithdrawToTokenWitness {
            note_secret,
            note_nullifier,
            amount: 300_000,
            path_siblings: siblings,
            path_indices: indices,
            merkle_root: Fr::from_be_bytes_mod_order(tree.root().as_bytes()),
            opening: elgamal::random_opening(&mut rng),
            recipient: bob_pk,
        },
        &mut rng,
    )
    .expect("prove");
    println!("  prove {:?}", t.elapsed());
    let ok = exit::verify(&exit::prepare_vk(&vk_ex), &proof, &public.inputs()).expect("verify");
    println!("  verify: {ok}");
    assert!(ok);
    // Bob reads what landed on his pending balance.
    let credited = elgamal::decode_amount(&bob.decrypt_point(&public.credited), 32).expect("decode");
    println!("  recipient decodes pending credit: {credited}");
    assert_eq!(credited, 300_000);
    println!("Done.");
}
