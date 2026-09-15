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
use tidex6_confidential::token::elgamal::{self, PublicKey, SecretKey};
use tidex6_confidential::token::pubkey::{self, PubkeyValidityCircuit};
use tidex6_confidential::token::transfer::{self, TokenTransferCircuit, TokenTransferWitness};

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
    println!("Done.");
}
