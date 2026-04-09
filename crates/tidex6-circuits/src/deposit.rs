//! `DepositCircuit`: the real Day 7-8 deposit circuit.
//!
//! Statement: "I know `(secret, nullifier)` such that
//! `Poseidon(secret, nullifier) == public commitment`".
//!
//! This is the proof a user must present to deposit into the
//! shielded pool: they commit publicly to a `commitment` value, and
//! in zero knowledge prove they know the preimage of that
//! commitment under Poseidon. The prover never reveals `secret` or
//! `nullifier`; only the derived `commitment` becomes public.
//!
//! The in-circuit Poseidon is
//! `poseidon_gadget::poseidon_hash_pair_var`, which is
//! byte-for-byte equivalent to `tidex6_core::poseidon::hash_pair`
//! (validated in `tests/poseidon_gadget_equivalence.rs`). This
//! invariant is what lets a user compute the commitment offchain
//! and the circuit reproduce it exactly.

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use thiserror::Error;

use crate::poseidon_gadget::poseidon_hash_pair_var;

/// The deposit circuit: `Poseidon(secret, nullifier) == commitment`.
///
/// `secret` and `nullifier` are private witnesses known only to the
/// depositor. `commitment` is the single public input — it is the
/// value the shielded-pool program stores in its Merkle tree.
#[derive(Clone, Debug)]
pub struct DepositCircuit {
    /// Private witness: the 32-byte `Secret` as a BN254 scalar.
    pub secret: Option<Fr>,
    /// Private witness: the 32-byte `Nullifier` as a BN254 scalar.
    pub nullifier: Option<Fr>,
    /// Public input: the `Commitment` the verifier will see.
    pub commitment: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let secret_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nullifier_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let commitment_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Compute Poseidon(secret, nullifier) inside the circuit and
        // enforce equality with the public commitment.
        let computed = poseidon_hash_pair_var(cs, &secret_var, &nullifier_var)?;
        computed.enforce_equal(&commitment_var)?;

        Ok(())
    }
}

/// Errors produced by the deposit-circuit helpers.
#[derive(Debug, Error)]
pub enum DepositCircuitError {
    /// Underlying arkworks synthesis / proving error.
    #[error("Groth16 synthesis error: {0}")]
    Synthesis(#[from] SynthesisError),
}

/// Run a local, single-contributor Groth16 Phase-2 setup for
/// `DepositCircuit`. Returns `(proving_key, verifying_key)`.
///
/// **DEVELOPMENT ONLY.** See `docs/release/security.md` section 1.4
/// for the production Phase-2 ceremony requirements.
pub fn setup_deposit_circuit<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), DepositCircuitError> {
    // Shape-only circuit: Groth16 setup only uses the constraint
    // structure, not the witness values.
    let shape = DepositCircuit {
        secret: None,
        nullifier: None,
        commitment: None,
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(shape, rng)?;
    Ok((pk, vk))
}

/// Generate a Groth16 proof for a specific `(secret, nullifier)`
/// pair. The caller supplies the 32-byte big-endian representations
/// and the matching commitment (the value they committed to
/// onchain). Returns the proof plus the public-input `Fr` so the
/// caller can forward it to the verifier without recomputing it.
pub fn prove_deposit<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    secret_bytes: &[u8; 32],
    nullifier_bytes: &[u8; 32],
    commitment_bytes: &[u8; 32],
    rng: &mut R,
) -> Result<(Proof<Bn254>, Fr), DepositCircuitError> {
    let secret = Fr::from_be_bytes_mod_order(secret_bytes);
    let nullifier = Fr::from_be_bytes_mod_order(nullifier_bytes);
    let commitment = Fr::from_be_bytes_mod_order(commitment_bytes);

    let circuit = DepositCircuit {
        secret: Some(secret),
        nullifier: Some(nullifier),
        commitment: Some(commitment),
    };

    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok((proof, commitment))
}

/// Verify a deposit proof against a prepared verifying key. The
/// caller supplies the `commitment` public input that was used
/// during proving.
pub fn verify_deposit_proof(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    commitment: Fr,
) -> Result<bool, DepositCircuitError> {
    let public_inputs = [commitment];
    let ok = Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, &public_inputs, proof)?;
    Ok(ok)
}

/// Convenience: turn a raw `VerifyingKey` into the prepared form
/// expected by `verify_deposit_proof`.
pub fn prepare_verifying_key(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    Groth16::<Bn254>::process_vk(vk).expect("process_vk cannot fail for well-formed VKs")
}
