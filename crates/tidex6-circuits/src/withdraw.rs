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
//! The circuit has **five** public inputs, committed in this exact
//! order (offchain prover and onchain verifier must agree byte-for-byte):
//!
//! 1. `merkle_root` — a recent root from the onchain ring buffer.
//! 2. `nullifier_hash` — the value the caller will write to a
//!    per-nullifier PDA to prevent double-spend.
//! 3. `recipient` — the account that receives the withdrawn SOL,
//!    less any relayer fee.
//! 4. `relayer_address` — the account that receives the relayer fee
//!    and is the fee-payer of the on-chain transaction. Added in
//!    ADR-011 so the proof binds the specific relayer, preventing a
//!    front-runner from rewriting this field in mempool.
//! 5. `relayer_fee` — the SOL amount (as a raw `u64` reduced into an
//!    `Fr`) the verifier transfers to `relayer_address`. The reference
//!    `tidex6-relayer` service hardcodes this to zero; the circuit is
//!    agnostic so any integrator can choose non-zero.
//!
//! Every public input is bound via a degenerate `x * x` constraint
//! (Tornado-style). The constraint has no semantic meaning inside the
//! circuit but prevents arkworks from optimizing an unused public
//! input away, and it forces the prover to commit to the specific
//! value — a front-runner who rewrites any of these fields in the
//! submitted transaction invalidates the proof.
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
    /// Relayer account that receives the relayer fee and is the
    /// on-chain fee-payer of the withdraw transaction. Reduced to an
    /// `Fr` by the caller the same way `recipient` is.
    ///
    /// Added in ADR-011. Binding this in the circuit prevents a
    /// front-runner from rewriting the `relayer` field in a submitted
    /// transaction to redirect the fee to themselves.
    pub relayer_address: Option<Fr>,
    /// SOL amount — as a raw `u64`, embedded into the low 64 bits of
    /// an `Fr` via `relayer_fee_fr_from_u64` — that the verifier
    /// transfers from the pool vault to `relayer_address` as part of
    /// the `withdraw` instruction. The reference `tidex6-relayer`
    /// service always sets this to zero; the circuit treats any
    /// `u64` as valid so non-zero-fee relayers are supported without
    /// a circuit change.
    pub relayer_fee: Option<Fr>,
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
            self.nullifier_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let recipient_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.recipient.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // New in ADR-011: two additional public inputs. Order matters
        // — both the offchain prover and the onchain verifier pack
        // their public-input arrays as
        // [merkle_root, nullifier_hash, recipient, relayer_address, relayer_fee]
        // so any rearrangement here requires a matching change to
        // `prove_withdraw`, `verify_withdraw_proof`, and `pool.rs`.
        let relayer_address_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.relayer_address
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let relayer_fee_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.relayer_fee.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ── Constraint 1: commitment = Poseidon(secret, nullifier) ─
        let commitment_var = poseidon_hash_pair_var(cs.clone(), &secret_var, &nullifier_var)?;

        // ── Constraint 2: nullifier_hash = Poseidon(nullifier) ────
        let computed_nullifier_hash =
            poseidon_hash_n_var(cs.clone(), std::slice::from_ref(&nullifier_var))?;
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

        // ── Constraint 5 (ADR-011): bind the relayer address ─────
        //
        // Same Tornado-style trick as constraint 4. Without this the
        // prover could commit to a proof that verifies regardless of
        // which relayer account the tx is submitted with, and a
        // front-runner would rewrite the `relayer` field to steal the
        // relayer fee.
        let _relayer_address_squared = &relayer_address_var * &relayer_address_var;

        // ── Constraint 6 (ADR-011): bind the relayer fee ─────────
        //
        // Same pattern. Binds the specific fee amount so a
        // front-runner cannot rewrite it (e.g. inflate it to drain the
        // vault to themselves or zero it to avoid paying a relayer
        // that expects a fee).
        let _relayer_fee_squared = &relayer_fee_var * &relayer_fee_var;

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
///
/// The public-input byte arrays must already be in the canonical
/// BN254 scalar encoding that the onchain verifier will receive — the
/// circuit reduces them via `Fr::from_be_bytes_mod_order` but the
/// onchain verifier expects values that are already less than the
/// BN254 modulus. See `tidex6_verifier::pool::reduce_mod_bn254`.
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
    /// Relayer account — pubkey bytes already reduced modulo the
    /// BN254 scalar field. Added in ADR-011.
    pub relayer_address: &'a [u8; 32],
    /// Relayer fee expressed as a 32-byte big-endian field-element
    /// encoding of a `u64` SOL amount. Use
    /// [`relayer_fee_bytes_from_u64`] to build this from a raw `u64`.
    pub relayer_fee: &'a [u8; 32],
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
        relayer_address: None,
        relayer_fee: None,
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(shape, rng)?;
    Ok((pk, vk))
}

/// Generate a withdraw proof. Returns the proof plus the five
/// public-input field elements the caller must forward to the
/// verifier in this exact order:
/// `[merkle_root, nullifier_hash, recipient, relayer_address, relayer_fee]`.
///
/// The order is load-bearing. `programs/tidex6-verifier/src/pool.rs::handle_withdraw`
/// packs its `public_inputs` array in the same sequence; a mismatch
/// here silently rejects every proof.
pub fn prove_withdraw<const DEPTH: usize, R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    witness: WithdrawWitness<'_, DEPTH>,
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; 5]), WithdrawCircuitError> {
    let secret = Fr::from_be_bytes_mod_order(witness.secret);
    let nullifier = Fr::from_be_bytes_mod_order(witness.nullifier);
    let merkle_root = Fr::from_be_bytes_mod_order(witness.merkle_root);
    let nullifier_hash = Fr::from_be_bytes_mod_order(witness.nullifier_hash);
    let recipient = Fr::from_be_bytes_mod_order(witness.recipient);
    let relayer_address = Fr::from_be_bytes_mod_order(witness.relayer_address);
    let relayer_fee = Fr::from_be_bytes_mod_order(witness.relayer_fee);

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
        relayer_address: Some(relayer_address),
        relayer_fee: Some(relayer_fee),
    };

    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok((
        proof,
        [
            merkle_root,
            nullifier_hash,
            recipient,
            relayer_address,
            relayer_fee,
        ],
    ))
}

/// Verify a withdraw proof against a prepared verifying key. The
/// caller supplies the five public inputs in the same order the
/// prover used.
pub fn verify_withdraw_proof(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; 5],
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

/// Reduce an arbitrary 32-byte identifier (e.g. the relayer's
/// Solana pubkey) into a BN254 scalar field element. Alias of
/// [`recipient_fr_from_bytes`], named separately for call-site
/// readability in ADR-011 code paths.
pub fn relayer_address_fr_from_bytes(bytes: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Encode a `u64` relayer fee (in lamports) as a 32-byte big-endian
/// field-element representation suitable for
/// [`WithdrawWitness::relayer_fee`].
///
/// The output is the canonical BN254 encoding of the scalar whose
/// low 64 bits equal `fee` — the top 192 bits are zero. The onchain
/// verifier builds the same encoding by zero-extending the
/// little-endian bytes of its `relayer_fee` instruction argument and
/// byte-reversing them to big-endian, then feeding the result into
/// `reduce_mod_bn254` (a no-op for values below the modulus, which
/// includes every `u64`).
pub fn relayer_fee_bytes_from_u64(fee: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&fee.to_be_bytes());
    out
}
