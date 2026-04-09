//! `WithdrawCircuit`: the Day 9-10 withdraw circuit.
//!
//! Statement: "I know `(secret, nullifier)` and a Merkle authentication
//! path such that
//!
//! 1. `commitment = Poseidon(secret, nullifier)`
//! 2. `nullifier_hash = Poseidon(nullifier)`
//! 3. `commitment` is the leaf at some position in the Merkle tree
//!    whose root is `merkle_root`.
//!
//! All three Poseidon hashes inside the circuit must match the
//! offchain `tidex6_core::poseidon` wrapper byte-for-byte so the
//! onchain `sol_poseidon` syscall and the arkworks gadget agree.
//! That invariant is validated in
//! `tests/poseidon_gadget_equivalence.rs`.
//!
//! # Public inputs
//!
//! - `merkle_root` — a recent root from the onchain ring buffer.
//! - `nullifier_hash` — the value the caller will write to a
//!   per-nullifier PDA to prevent double-spend.
//! - `recipient` — the account that receives the withdrawn SOL.
//!   Bound to the proof via a degenerate `recipient * recipient`
//!   constraint (Tornado-style), so a front-runner cannot swap the
//!   recipient field in a submitted transaction without invalidating
//!   the proof.
//!
//! # Private witnesses
//!
//! - `secret`, `nullifier` — the preimages of the commitment.
//! - `path_siblings` — the `DEPTH` sibling hashes from leaf to root.
//! - `path_indices` — the `DEPTH` bits of the leaf index. Bit `i` is
//!   `true` when the current node at level `i` is the right child of
//!   its parent.

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use thiserror::Error;

use crate::poseidon_gadget::{poseidon_hash_n_var, poseidon_hash_pair_var};

/// Fixed Merkle tree depth used by the MVP shielded pool. Matches
/// `tidex6_core::merkle::DEFAULT_DEPTH`. Changing this value changes
/// the verifying key and therefore invalidates every previously
/// issued proof.
pub const WITHDRAW_TREE_DEPTH: usize = 20;

/// The withdraw circuit, parametrised over Merkle tree depth so
/// tests can run a small tree quickly. Production uses
/// `WithdrawCircuit<WITHDRAW_TREE_DEPTH>`.
#[derive(Clone, Debug)]
pub struct WithdrawCircuit<const DEPTH: usize> {
    // ── Private witnesses ───────────────────────────────────────────
    /// `Secret` as a BN254 scalar.
    pub secret: Option<Fr>,
    /// `Nullifier` as a BN254 scalar.
    pub nullifier: Option<Fr>,
    /// `DEPTH` sibling hashes bottom-up.
    pub path_siblings: Option<[Fr; DEPTH]>,
    /// Leaf-index bits, LSB first: `path_indices[0]` is bit 0 of the
    /// leaf index. `true` means the walking node is the right child
    /// at this level.
    pub path_indices: Option<[bool; DEPTH]>,

    // ── Public inputs ──────────────────────────────────────────────
    /// The Merkle root committed to by the pool.
    pub merkle_root: Option<Fr>,
    /// `Poseidon(nullifier)` — written to the per-nullifier PDA.
    pub nullifier_hash: Option<Fr>,
    /// Recipient account, bound to the proof. The raw recipient
    /// pubkey is reduced to an `Fr` by the caller (see
    /// `recipient_fr_from_bytes`).
    pub recipient: Option<Fr>,
}

impl<const DEPTH: usize> ConstraintSynthesizer<Fr> for WithdrawCircuit<DEPTH> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Allocate private witnesses ─────────────────────────────
        let secret_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nullifier_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mut sibling_vars: Vec<FpVar<Fr>> = Vec::with_capacity(DEPTH);
        let mut index_bit_vars: Vec<Boolean<Fr>> = Vec::with_capacity(DEPTH);
        for level in 0..DEPTH {
            let sibling_var = FpVar::<Fr>::new_witness(cs.clone(), || {
                self.path_siblings
                    .ok_or(SynthesisError::AssignmentMissing)
                    .map(|siblings| siblings[level])
            })?;
            sibling_vars.push(sibling_var);

            let bit_var = Boolean::<Fr>::new_witness(cs.clone(), || {
                self.path_indices
                    .ok_or(SynthesisError::AssignmentMissing)
                    .map(|bits| bits[level])
            })?;
            index_bit_vars.push(bit_var);
        }

        // ── Allocate public inputs ────────────────────────────────
        let merkle_root_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.merkle_root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nullifier_hash_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.nullifier_hash
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let recipient_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.recipient.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── Constraint 1: commitment = Poseidon(secret, nullifier) ─
        let commitment_var =
            poseidon_hash_pair_var(cs.clone(), &secret_var, &nullifier_var)?;

        // ── Constraint 2: nullifier_hash = Poseidon(nullifier) ────
        let computed_nullifier_hash =
            poseidon_hash_n_var(cs.clone(), &[nullifier_var.clone()])?;
        computed_nullifier_hash.enforce_equal(&nullifier_hash_var)?;

        // ── Constraint 3: Merkle authentication path ─────────────
        //
        // Walk from the leaf up to the root. At each level decide
        // whether the walking node is the left or the right child of
        // its parent using the index bit. If the bit is 0 the walking
        // node is the left child and the sibling is on the right; if
        // the bit is 1 they swap. `CondSelectGadget` reduces this to
        // two selections per level.
        let mut current = commitment_var;
        for level in 0..DEPTH {
            let bit = &index_bit_vars[level];
            let sibling = &sibling_vars[level];

            let left = FpVar::<Fr>::conditionally_select(bit, sibling, &current)?;
            let right = FpVar::<Fr>::conditionally_select(bit, &current, sibling)?;

            current = poseidon_hash_pair_var(cs.clone(), &left, &right)?;
        }

        current.enforce_equal(&merkle_root_var)?;

        // ── Constraint 4: bind the recipient ──────────────────────
        //
        // Tornado-style: use the recipient in a degenerate
        // multiplication so a front-runner who rewrites the
        // recipient field in a submitted transaction invalidates the
        // proof, even though the recipient has no semantic meaning
        // inside the circuit. `recipient * recipient` is the cheapest
        // non-trivial constraint that involves the public input.
        let _recipient_squared = &recipient_var * &recipient_var;

        Ok(())
    }
}

/// Errors produced by the withdraw-circuit helpers.
#[derive(Debug, Error)]
pub enum WithdrawCircuitError {
    /// Underlying arkworks synthesis / proving error.
    #[error("Groth16 synthesis error: {0}")]
    Synthesis(#[from] SynthesisError),
}

/// Witness data the prover must supply. Expressed in 32-byte
/// big-endian form so the caller can pass values straight from
/// `tidex6_core` newtypes without knowing the underlying field.
#[derive(Clone, Debug)]
pub struct WithdrawWitness<'a, const DEPTH: usize> {
    pub secret: &'a [u8; 32],
    pub nullifier: &'a [u8; 32],
    pub path_siblings: [&'a [u8; 32]; DEPTH],
    /// Leaf-index bits, LSB first — `path_indices[0]` is bit 0 of
    /// the leaf index.
    pub path_indices: [bool; DEPTH],
    pub merkle_root: &'a [u8; 32],
    pub nullifier_hash: &'a [u8; 32],
    pub recipient: &'a [u8; 32],
}

/// Run a local, single-contributor Groth16 setup for the withdraw
/// circuit at compile-time fixed depth `DEPTH`.
///
/// **DEVELOPMENT ONLY.** See `docs/release/security.md` section 1.4.
pub fn setup_withdraw_circuit<const DEPTH: usize, R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), WithdrawCircuitError> {
    let shape = WithdrawCircuit::<DEPTH> {
        secret: None,
        nullifier: None,
        path_siblings: None,
        path_indices: None,
        merkle_root: None,
        nullifier_hash: None,
        recipient: None,
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(shape, rng)?;
    Ok((pk, vk))
}

/// Generate a withdraw proof. Returns the proof plus the three
/// public-input field elements the caller must forward to the
/// verifier in the same order: `[merkle_root, nullifier_hash, recipient]`.
pub fn prove_withdraw<const DEPTH: usize, R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    witness: WithdrawWitness<'_, DEPTH>,
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; 3]), WithdrawCircuitError> {
    let secret = Fr::from_be_bytes_mod_order(witness.secret);
    let nullifier = Fr::from_be_bytes_mod_order(witness.nullifier);
    let merkle_root = Fr::from_be_bytes_mod_order(witness.merkle_root);
    let nullifier_hash = Fr::from_be_bytes_mod_order(witness.nullifier_hash);
    let recipient = Fr::from_be_bytes_mod_order(witness.recipient);

    let mut siblings = [Fr::from(0u64); DEPTH];
    for (slot, bytes) in siblings.iter_mut().zip(witness.path_siblings.iter()) {
        *slot = Fr::from_be_bytes_mod_order(*bytes);
    }

    let circuit = WithdrawCircuit::<DEPTH> {
        secret: Some(secret),
        nullifier: Some(nullifier),
        path_siblings: Some(siblings),
        path_indices: Some(witness.path_indices),
        merkle_root: Some(merkle_root),
        nullifier_hash: Some(nullifier_hash),
        recipient: Some(recipient),
    };

    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok((proof, [merkle_root, nullifier_hash, recipient]))
}

/// Verify a withdraw proof against a prepared verifying key. The
/// caller supplies the three public inputs in the same order the
/// prover used.
pub fn verify_withdraw_proof(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; 3],
) -> Result<bool, WithdrawCircuitError> {
    let ok = Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, public_inputs, proof)?;
    Ok(ok)
}

/// Convenience: turn a raw `VerifyingKey` into the prepared form.
pub fn prepare_verifying_key(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    Groth16::<Bn254>::process_vk(vk).expect("process_vk cannot fail for well-formed VKs")
}

/// Reduce an arbitrary 32-byte identifier (e.g. a Solana pubkey)
/// into a BN254 scalar field element. The caller uses this to
/// compute the `recipient` public input.
pub fn recipient_fr_from_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}
