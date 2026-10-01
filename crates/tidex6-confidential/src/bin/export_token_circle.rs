//! Build every proof of one full confidential-token round, offline, for a
//! live run against freshly deployed contracts (ADR-023).
//!
//! The contracts' state is a deterministic function of the calls, so this
//! binary simulates it with the same arithmetic and proves each step against
//! the balance the contract will hold at that moment:
//!
//! ```text
//!  1. Alice and Bob register their keys
//!  2. Alice wraps 1 000 000                 → available (m·G, O) after applyPending
//!  3. Alice pays Bob 250 000 (auditor Alice) → no amount on chain
//!  4. Alice deposits 300 000 to Bob's note   → pool leaves: payment, fee 100 000
//!  5. Bob takes that note onto his balance   → no amount on chain
//!  6. Bob unwraps 550 000, Alice 350 000     → the only public numbers besides 2
//! ```
//!
//! Writes `contracts/script/token_circle.json`; `contracts/script/TokenCircle.s.sol`
//! deploys the Solidity contracts and replays it. Proving keys are the
//! development ones in `artifacts/` — run `export_token_verifiers` first, the
//! verifiers and the keys must come from the same setup.
//!
//! ```text
//! cargo run --release -p tidex6-confidential --bin export_token_circle
//! ```

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use ark_bn254::{Bn254, Fr};
use ark_ed_on_bn254::EdwardsAffine;
use ark_ff::PrimeField;
use ark_groth16::{Proof, ProvingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use tidex6_circuits::ceremony::find_workspace_root;
use tidex6_circuits::evm_solidity::groth16_proof_to_evm_bytes;
use tidex6_confidential::bytes::fr_to_be_bytes;
use tidex6_confidential::note_v2;
use tidex6_confidential::token::elgamal::{self, Ciphertext, SecretKey};
use tidex6_confidential::token::{deposit, exit, pubkey, transfer, unwrap};
use tidex6_confidential::transfer_v2::fee_for;
use tidex6_confidential::withdraw::POOL_TREE_DEPTH;
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::Commitment;

const FEE_FLOOR: u64 = 100_000;

/// Who registers each key, as `TokenCircle.s.sol` derives them: Alice is the
/// devnode's prefunded key, Bob `keccak256("tidex6 token circle: bob")`. The
/// script checks `vm.addr` against these before the first call, so a drift
/// shows up as one clear failure instead of an invalid proof.
const ALICE_ADDRESS: [u8; 20] = hex20("3f1eae7d46d88f08fc2f8ed27fcb2ab183eb2d0e");
const BOB_ADDRESS: [u8; 20] = hex20("6820a6fdafafd445f5f558fcccb18c95dc471032");

const fn hex20(text: &str) -> [u8; 20] {
    let bytes = text.as_bytes();
    let mut out = [0u8; 20];
    let mut i = 0;
    while i < 20 {
        out[i] = nibble(bytes[2 * i]) << 4 | nibble(bytes[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        _ => c - b'a' + 10,
    }
}

/// An EVM address as the 32-byte word the circuits take.
fn word(address: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&address);
    out
}

fn hex(f: &Fr) -> String {
    let mut out = String::from("0x");
    for b in fr_to_be_bytes(*f) {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn load_pk(root: &Path, stem: &str) -> ProvingKey<Bn254> {
    let path = root.join(format!(
        "crates/tidex6-confidential/artifacts/token_{stem}_pk.bin"
    ));
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    ProvingKey::deserialize_uncompressed_unchecked(&bytes[..]).expect("proving key")
}

/// One call: the EVM proof as eight words and the public inputs.
fn step(proof: &Proof<Bn254>, inputs: &[Fr]) -> String {
    let bytes = groth16_proof_to_evm_bytes(proof);
    let words: Vec<String> = bytes
        .chunks(32)
        .map(|w| hex(&Fr::from_be_bytes_mod_order(w)))
        .collect();
    let inputs: Vec<String> = inputs.iter().map(hex).collect();
    format!(
        "{{\"proof\": [\"{}\"], \"input\": [\"{}\"]}}",
        words.join("\", \""),
        inputs.join("\", \"")
    )
}

fn point_json(p: &EdwardsAffine) -> String {
    format!("[\"{}\", \"{}\"]", hex(&p.x), hex(&p.y))
}

fn add(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    elgamal::add(a, b)
}

fn sub(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    elgamal::sub(a, b)
}

fn empty() -> Ciphertext {
    elgamal::plain(0)
}

fn main() {
    let root = find_workspace_root();
    let mut rng = StdRng::seed_from_u64(0x7469_6465_7836_4369); // "tidex6Ci"

    let alice = SecretKey::from_seed(&[0x11; 64]).expect("alice key");
    let bob = SecretKey::from_seed(&[0x22; 64]).expect("bob key");
    let alice_pk = alice.public_key().expect("pk");
    let bob_pk = bob.public_key().expect("pk");

    let pk_pubkey = load_pk(&root, "pubkey");
    let pk_transfer = load_pk(&root, "transfer");
    let pk_unwrap = load_pk(&root, "unwrap");
    let pk_deposit = load_pk(&root, "deposit");
    let pk_exit = load_pk(&root, "exit");

    // 1. Registration.
    let (p, i) = pubkey::prove(
        &pk_pubkey,
        &alice,
        &alice_pk,
        &word(ALICE_ADDRESS),
        &mut rng,
    )
    .expect("alice pubkey");
    let register_alice = step(&p, &i);
    let (p, i) =
        pubkey::prove(&pk_pubkey, &bob, &bob_pk, &word(BOB_ADDRESS), &mut rng).expect("bob pubkey");
    let register_bob = step(&p, &i);

    // 2. Wrap + applyPending: available = O + (m·G, O).
    let wrapped = 1_000_000u64;
    let mut alice_available = add(&empty(), &elgamal::plain(wrapped));
    let mut alice_balance = wrapped;

    // 3. Alice → Bob, auditor Alice.
    let paid = 250_000u64;
    let w = transfer::TokenTransferWitness {
        secret: alice.clone(),
        balance: alice_balance,
        available: alice_available,
        amount: paid,
        opening: elgamal::random_opening(&mut rng),
        recipient: bob_pk,
        auditor: alice_pk,
    };
    let (p, public) = transfer::prove(&pk_transfer, &w, &mut rng).expect("transfer");
    let transfer_step = step(&p, &public.inputs());
    alice_available = sub(
        &alice_available,
        &Ciphertext {
            commitment: public.amount_commitment,
            handle: public.sender_handle,
        },
    );
    alice_balance -= paid;
    let bob_credit = Ciphertext {
        commitment: public.amount_commitment,
        handle: public.recipient_handle,
    };
    // Bob applies: available = O + pending.
    let mut bob_available = add(&empty(), &add(&empty(), &bob_credit));
    let mut bob_balance = paid;

    // 4. Alice deposits a payment note for Bob.
    let bob_spend = Fr::from(0x0b0b_u64);
    let rho = Fr::from(0x0e40_u64);
    let aux = Fr::from(0x0a0a_u64);
    let core_pay = note_v2::core(note_v2::owner_pk(bob_spend), rho, aux);
    let treasury_pk = note_v2::owner_pk(Fr::from(0x7ea5_u64));
    let pay = 300_000u64;
    let fee = fee_for(pay, FEE_FLOOR);
    let w = deposit::DepositFromTokenWitness {
        secret: alice.clone(),
        balance: alice_balance,
        available: alice_available,
        amount_pay: pay,
        amount_fee: fee,
        opening: elgamal::random_opening(&mut rng),
        core_pay,
        rho_fee: Fr::from(0x0fee_u64),
        treasury_pk,
        fee_floor: FEE_FLOOR,
    };
    let (p, public) = deposit::prove(&pk_deposit, &w, &mut rng).expect("deposit");
    let deposit_step = step(&p, &public.inputs());
    alice_available = sub(&alice_available, &public.debit);
    alice_balance -= pay + fee;

    // The pool files payment at 0, fee at 1.
    let mut tree = MerkleTree::new(POOL_TREE_DEPTH).expect("tree");
    for leaf in [public.commitment_pay, public.commitment_fee] {
        tree.insert(Commitment::from_bytes(fr_to_be_bytes(leaf)))
            .expect("insert");
    }
    let merkle_root = Fr::from_be_bytes_mod_order(tree.root().as_bytes());
    let merkle_proof = tree.proof(0).expect("proof");
    let mut siblings = [Fr::from(0u64); POOL_TREE_DEPTH];
    for (slot, sibling) in siblings.iter_mut().zip(merkle_proof.siblings.iter()) {
        *slot = Fr::from_be_bytes_mod_order(sibling.as_bytes());
    }
    let mut indices = [false; POOL_TREE_DEPTH];
    for (i, bit) in indices.iter_mut().enumerate() {
        *bit = (merkle_proof.leaf_index >> i) & 1 == 1;
    }

    // 5. Bob takes the note onto his balance.
    let w = exit::WithdrawToTokenWitness {
        sk_spend: bob_spend,
        rho,
        aux,
        amount: pay,
        refund: Fr::from(0u64),
        path_siblings: siblings,
        path_indices: indices,
        merkle_root,
        opening: elgamal::random_opening(&mut rng),
        recipient: bob_pk,
    };
    let (p, public) = exit::prove(&pk_exit, &w, &mut rng).expect("exit");
    let exit_step = step(&p, &public.inputs());
    // Bob applies again.
    bob_available = add(&bob_available, &add(&empty(), &public.credited));
    bob_balance += pay;

    // 6. Both leave for the open token.
    let (p, i) = unwrap::prove(
        &pk_unwrap,
        &unwrap::TokenUnwrapWitness {
            secret: bob.clone(),
            balance: bob_balance,
            available: bob_available,
            amount: bob_balance,
        },
        &mut rng,
    )
    .expect("bob unwrap");
    let unwrap_bob = step(&p, &i);
    let (p, i) = unwrap::prove(
        &pk_unwrap,
        &unwrap::TokenUnwrapWitness {
            secret: alice.clone(),
            balance: alice_balance,
            available: alice_available,
            amount: alice_balance,
        },
        &mut rng,
    )
    .expect("alice unwrap");
    let unwrap_alice = step(&p, &i);

    let json = format!(
        "{{\n  \"wrapped\": {wrapped},\n  \"feeFloor\": {FEE_FLOOR},\n  \"treasuryPk\": \"{}\",\n  \
         \"aliceAddress\": \"0x{}\",\n  \"bobAddress\": \"0x{}\",\n  \"aliceKey\": {},\n  \"bobKey\": {},\n  \"poolRootAfterDeposit\": \"{}\",\n  \
         \"bobUnwraps\": {bob_balance},\n  \"aliceUnwraps\": {alice_balance},\n  \
         \"registerAlice\": {register_alice},\n  \"registerBob\": {register_bob},\n  \
         \"transfer\": {transfer_step},\n  \"deposit\": {deposit_step},\n  \"exit\": {exit_step},\n  \
         \"unwrapBob\": {unwrap_bob},\n  \"unwrapAlice\": {unwrap_alice}\n}}\n",
        hex(&treasury_pk),
        ALICE_ADDRESS
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        BOB_ADDRESS
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        point_json(&alice_pk.0),
        point_json(&bob_pk.0),
        hex(&merkle_root),
    );
    let dir = root.join("contracts/script");
    fs::create_dir_all(&dir).expect("script dir");
    let path = dir.join("token_circle.json");
    fs::write(&path, json).expect("write circle");
    println!("wrote {}", path.display());
    println!(
        "alice ends with {alice_balance}, bob with {bob_balance}, the pool keeps the fee note of {fee}"
    );
}
