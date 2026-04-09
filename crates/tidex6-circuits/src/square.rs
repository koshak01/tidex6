//! `SquareCircuit`: the Day-6 pipeline-validation circuit.
//!
//! Statement: "I know `x` such that `x * x == public y`". This is
//! the smallest non-trivial R1CS constraint that exercises every
//! step of the arkworks → Groth16 pipeline: private witness
//! allocation, public input allocation, a multiplication gate, a
//! final equality check.
//!
//! We pick the `Bn254` curve so the resulting proof and verifying
//! key can be verified onchain via the `groth16-solana` crate.

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use thiserror::Error;

/// The trivial R1CS circuit that drives the Day-6 pipeline
/// validation.
///
/// `x` is the private witness; `y = x * x` is the public input the
/// verifier sees. A valid proof is a demonstration that the prover
/// knows an `x` whose square equals `y`.
#[derive(Clone, Debug)]
pub struct SquareCircuit {
    /// Private witness: the value whose square is being proved.
    /// `None` during setup (when only the circuit shape matters),
    /// `Some(x)` during proving.
    pub x: Option<Fr>,
    /// Public input: the claimed square of `x`.
    /// `None` during setup, `Some(y)` during proving.
    pub y: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for SquareCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate the private witness.
        let x_var = FpVar::<Fr>::new_witness(cs.clone(), || {
            self.x.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Allocate the public input.
        let y_var = FpVar::<Fr>::new_input(cs.clone(), || {
            self.y.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Enforce x * x == y.
        let x_squared = &x_var * &x_var;
        x_squared.enforce_equal(&y_var)?;

        Ok(())
    }
}

/// Errors produced by the Groth16 helpers in this module.
#[derive(Debug, Error)]
pub enum SquareCircuitError {
    /// Underlying Groth16 setup or proving returned an error.
    #[error("Groth16 synthesis error: {0}")]
    Synthesis(#[from] SynthesisError),
}

/// Run a local, single-contributor Groth16 trusted setup for
/// `SquareCircuit`. The caller passes in a cryptographically secure
/// RNG; the returned proving and verifying keys are valid for any
/// `(x, y)` pair that satisfies the circuit.
///
/// **DEVELOPMENT ONLY.** A single-contributor setup means the
/// "toxic waste" existed on one machine. For production, run a
/// multi-contributor Phase-2 ceremony. See
/// `docs/release/security.md` section 1.4.
pub fn setup_square_circuit<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SquareCircuitError> {
    // Shape-only circuit: no witness or public input yet. Groth16
    // setup only cares about the constraint structure, not the
    // specific values.
    let shape = SquareCircuit { x: None, y: None };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(shape, rng)?;
    Ok((pk, vk))
}

/// Generate a proof that the prover knows an `x` whose square is
/// `x * x`. Also returns the public input `y = x * x` so the caller
/// can forward it to the verifier.
pub fn prove_square<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    x: u64,
    rng: &mut R,
) -> Result<(Proof<Bn254>, Fr), SquareCircuitError> {
    let x_fr = Fr::from(x);
    let y_fr = x_fr * x_fr;

    let circuit = SquareCircuit {
        x: Some(x_fr),
        y: Some(y_fr),
    };

    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok((proof, y_fr))
}

/// Verify a `SquareCircuit` proof against a prepared verifying
/// key. The caller supplies the same `y` that was used during
/// proving — the verifier will reject the proof if the prover used
/// a different public input.
pub fn verify_square_proof(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    y: Fr,
) -> Result<bool, SquareCircuitError> {
    let public_inputs = [y];
    let ok = Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, &public_inputs, proof)?;
    Ok(ok)
}

/// Convenience helper: turn a raw `VerifyingKey` into a
/// `PreparedVerifyingKey` for use with `verify_square_proof`.
pub fn prepare_verifying_key(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    Groth16::<Bn254>::process_vk(vk).expect("process_vk cannot fail for well-formed VKs")
}

/// Compute `y = x * x` as a `Fr` field element. Used by callers
/// who need the public input without running the full prover.
pub fn square(x: u64) -> Fr {
    let x_fr = Fr::from(x);
    x_fr * x_fr
}

/// Serialize a `Fr` public input into the 32-byte big-endian
/// encoding that `groth16-solana` expects.
pub fn fr_to_be_bytes(value: Fr) -> [u8; 32] {
    let bigint = value.into_bigint();
    let mut bytes = bigint.to_bytes_be();
    // `to_bytes_be` may return fewer than 32 bytes if the high bits
    // are zero. Pad the most-significant side with zeros.
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.append(&mut bytes);
        bytes = padded;
    }
    bytes
        .try_into()
        .expect("BN254 Fr always fits in 32 bytes once padded")
}
