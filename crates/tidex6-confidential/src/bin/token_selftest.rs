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
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use tidex6_confidential::bytes::fr_to_be_bytes;
use tidex6_confidential::note_v2;
use tidex6_confidential::token::deposit::{self, DepositFromTokenCircuit, DepositFromTokenWitness};
use tidex6_confidential::token::elgamal::{self, PublicKey, SecretKey};
use tidex6_confidential::token::exit::{self, WithdrawToTokenCircuit, WithdrawToTokenWitness};
use tidex6_confidential::token::pubkey::{self, PubkeyValidityCircuit};
use tidex6_confidential::token::transfer::{self, TokenTransferCircuit, TokenTransferWitness};
use tidex6_confidential::token::unwrap::{self, TokenUnwrapCircuit, TokenUnwrapWitness};
use tidex6_confidential::transfer_v2::fee_for;
use tidex6_confidential::withdraw::POOL_TREE_DEPTH;
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
    circuit
        .generate_constraints(cs.clone())
        .expect("synthesize");
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
    let bob_view = elgamal::Ciphertext {
        commitment: payment.commitment,
        handle: bob_pk.handle(r),
    };
    assert_eq!(
        elgamal::decode_amount(&bob.decrypt_point(&bob_view), 32).expect("decode"),
        250_000
    );
    assert!(elgamal::opens_to(&payment.commitment, 250_000, r));
    assert!(!elgamal::opens_to(&payment.commitment, 250_001, r));

    // ── pubkey circuit ───────────────────────────────────────────────
    let (n, inputs) = count_constraints(PubkeyValidityCircuit::default());
    println!("PubkeyValidity: {n} constraints, {inputs} public inputs");
    let t = Instant::now();
    let (pk_key, vk_key) = pubkey::setup(&mut rng).expect("setup");
    println!("  setup {:?}", t.elapsed());
    let t = Instant::now();
    let owner = [0x11u8; 32];
    let (proof, public) =
        pubkey::prove(&pk_key, &alice, &alice_pk, &owner, &mut rng).expect("prove");
    println!("  prove {:?}", t.elapsed());
    let prepared_key = pubkey::prepare_vk(&vk_key);
    let ok = pubkey::verify(&prepared_key, &proof, &public).expect("verify");
    println!("  verify: {ok}");
    assert!(ok);
    // The same proof submitted for another address must not verify.
    let mut stolen = public;
    stolen[3] += Fr::from(1u64);
    let bad = pubkey::verify(&prepared_key, &proof, &stolen).expect("verify");
    println!("  verify for another owner: {bad}");
    assert!(!bad);

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
    let overspend = TokenTransferWitness {
        amount: 1_000_001,
        ..witness
    };
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
        &TokenUnwrapWitness {
            secret: alice.clone(),
            balance: 1_000_000,
            available: wrap,
            amount: 400_000,
        },
        &mut rng,
    )
    .expect("prove");
    println!("  prove {:?}", t.elapsed());
    let ok = unwrap::verify(&unwrap::prepare_vk(&vk_un), &proof, &public).expect("verify");
    println!("  verify: {ok}");
    assert!(ok);

    // ── deposit-from-token circuit (v2 leaves) ───────────────────────
    let (n, inputs) = count_constraints(DepositFromTokenCircuit::default());
    println!("DepositFromToken: {n} constraints, {inputs} public inputs");
    let t = Instant::now();
    let (pk_dep, vk_dep) = deposit::setup(&mut rng).expect("setup");
    println!("  setup {:?}", t.elapsed());
    // Bob receives a v2 note: his spending key, his owner key, a fresh core.
    let bob_sk_spend = Fr::from(0xb0b5e_u64);
    let rho = Fr::from(0xe4011_u64);
    let aux = Fr::from(0xa0_u64);
    let core_pay = note_v2::core(note_v2::owner_pk(bob_sk_spend), rho, aux);
    let treasury_pk = note_v2::owner_pk(Fr::from(0x7ea5_u64));
    let fee_floor = 100_000u64;
    let pay = 300_000u64;
    let fee = fee_for(pay, fee_floor);
    let deposit_witness = DepositFromTokenWitness {
        secret: alice.clone(),
        balance: 1_000_000,
        available: wrap,
        amount_pay: pay,
        amount_fee: fee,
        opening: r,
        core_pay,
        rho_fee: Fr::from(0xfee_u64),
        treasury_pk,
        fee_floor,
    };
    let t = Instant::now();
    let (proof, public) = deposit::prove(&pk_dep, &deposit_witness, &mut rng).expect("prove");
    println!("  prove {:?}", t.elapsed());
    let prepared_dep = deposit::prepare_vk(&vk_dep);
    let ok = deposit::verify(&prepared_dep, &proof, &public.inputs()).expect("verify");
    println!("  verify: {ok}");
    assert!(ok);
    // The debit covers payment and fee, and nothing else.
    let debit = elgamal::decode_amount(&alice.decrypt_point(&public.debit), 32).expect("decode");
    println!("  sender debit decodes to {debit} (pay {pay} + fee {fee})");
    assert_eq!(debit, pay + fee);
    // A fee below the pool's policy must not even synthesize a witness.
    let cheap = DepositFromTokenWitness {
        amount_fee: fee - 1,
        ..deposit_witness
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    let cheap_public = deposit::public_part(&cheap).expect("public");
    DepositFromTokenCircuit {
        secret: Some(cheap.secret.0),
        balance: Some(cheap.balance),
        amount_pay: Some(cheap.amount_pay),
        amount_fee: Some(cheap.amount_fee),
        opening: Some(cheap.opening),
        core_pay: Some(cheap.core_pay),
        rho_fee: Some(cheap.rho_fee),
        sender_key: Some(cheap_public.sender_key),
        balance_commitment: Some(cheap_public.available.commitment),
        balance_handle: Some(cheap_public.available.handle),
        debit_commitment: Some(cheap_public.debit.commitment),
        debit_handle: Some(cheap_public.debit.handle),
        commitment_pay: Some(cheap_public.commitment_pay),
        commitment_fee: Some(cheap_public.commitment_fee),
        treasury_pk: Some(cheap_public.treasury_pk),
        fee_floor: Some(cheap_public.fee_floor),
    }
    .generate_constraints(cs.clone())
    .expect("synthesize");
    assert!(!cs.is_satisfied().expect("check"));
    println!("  fee below the floor rejected");

    // ── withdraw-to-token circuit (v2 note) ──────────────────────────
    let (n, inputs) = count_constraints(WithdrawToTokenCircuit::default());
    println!("WithdrawToToken: {n} constraints, {inputs} public inputs");
    let t = Instant::now();
    let (pk_ex, vk_ex) = exit::setup(&mut rng).expect("setup");
    println!("  setup {:?}", t.elapsed());
    // Bob's payment note from the deposit above sits at leaf 0.
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH).expect("tree");
    tree.insert(Commitment::from_bytes(fr_to_be_bytes(
        public.commitment_pay,
    )))
    .expect("insert");
    let merkle_proof = tree.proof(0).expect("proof");
    let mut siblings = [Fr::from(0u64); POOL_TREE_DEPTH];
    for (slot, sibling) in siblings.iter_mut().zip(merkle_proof.siblings.iter()) {
        *slot = Fr::from_be_bytes_mod_order(sibling.as_bytes());
    }
    let mut indices = [false; POOL_TREE_DEPTH];
    for (i, bit) in indices.iter_mut().enumerate() {
        *bit = (merkle_proof.leaf_index >> i) & 1 == 1;
    }
    let exit_witness = WithdrawToTokenWitness {
        sk_spend: bob_sk_spend,
        rho,
        aux,
        amount: pay,
        refund: Fr::from(0u64),
        path_siblings: siblings,
        path_indices: indices,
        merkle_root: Fr::from_be_bytes_mod_order(tree.root().as_bytes()),
        opening: elgamal::random_opening(&mut rng),
        recipient: bob_pk,
    };
    let t = Instant::now();
    let (proof, public) = exit::prove(&pk_ex, &exit_witness, &mut rng).expect("prove");
    println!("  prove {:?}", t.elapsed());
    let prepared_ex = exit::prepare_vk(&vk_ex);
    let ok = exit::verify(&prepared_ex, &proof, &public.inputs()).expect("verify");
    println!("  verify: {ok}");
    assert!(ok);
    // Bob reads what landed on his pending balance.
    let credited =
        elgamal::decode_amount(&bob.decrypt_point(&public.credited), 32).expect("decode");
    println!("  recipient decodes pending credit: {credited}");
    assert_eq!(credited, pay);
    // Alice, who paid, cannot spend Bob's note: her key gives another leaf.
    let thief = WithdrawToTokenWitness {
        sk_spend: Fr::from(0xa11ce_u64),
        ..exit_witness
    };
    let thief_public = exit::public_part(&thief);
    let cs = ConstraintSystem::<Fr>::new_ref();
    WithdrawToTokenCircuit {
        sk_spend: Some(thief.sk_spend),
        rho: Some(thief.rho),
        aux: Some(thief.aux),
        amount: Some(thief.amount),
        refund: Some(thief.refund),
        path_siblings: Some(thief.path_siblings),
        path_indices: Some(thief.path_indices),
        opening: Some(thief.opening),
        merkle_root: Some(thief_public.merkle_root),
        nullifier: Some(thief_public.nullifier),
        recipient_key: Some(thief_public.recipient_key),
        amount_commitment: Some(thief_public.credited.commitment),
        recipient_handle: Some(thief_public.credited.handle),
    }
    .generate_constraints(cs.clone())
    .expect("synthesize");
    assert!(!cs.is_satisfied().expect("check"));
    println!("  spending with someone else's key rejected");
    println!("Done.");
}
