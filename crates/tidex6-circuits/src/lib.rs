//! Arkworks R1CS circuits and Groth16 proving helpers for tidex6.
//!
//! The Day-6 starting point is a trivial pipeline-validation
//! circuit: "I know `x` such that `x * x == public y`". It is
//! deliberately not Poseidon-based because the goal of Day 6 is to
//! prove that the whole arkworks → Groth16 setup → proof generation
//! → byte-format conversion → onchain verification pipeline works
//! end-to-end with code we control, independent of any upstream
//! test vectors. Once this pipeline is proven, Day-7 and Day-8
//! work focuses on replacing `SquareCircuit` with a
//! Poseidon-based `DepositCircuit` whose in-circuit hash gadget
//! matches the offchain `tidex6_core::poseidon` wrapper.
//!
//! Public API:
//!
//! - `SquareCircuit` — the trivial R1CS definition.
//! - `setup_square_circuit` — runs a local, single-contributor
//!   trusted setup and returns `(proving_key, verifying_key)`.
//!   DEVELOPMENT ONLY per ADR-007 and `docs/release/security.md`
//!   section 1.4.
//! - `prove_square` — generates a Groth16 proof for a specific
//!   `x`.
//! - `verify_square_proof` — verifies a proof offchain. Used in
//!   tests and as a sanity check before submitting to devnet.
//! - `Groth16SolanaBytes` — helper that converts an arkworks VK +
//!   proof into the byte layout expected by the `groth16-solana`
//!   crate, which is the layout the onchain `tidex6-verifier`
//!   program consumes.

pub mod deposit;
pub mod poseidon_gadget;
pub mod solana_bytes;
pub mod square;
pub mod withdraw;
