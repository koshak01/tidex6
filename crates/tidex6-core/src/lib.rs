//! Core primitives for the tidex6 privacy framework.
//!
//! tidex6 is a Rust-native privacy framework for Solana. This crate provides
//! the shared primitives used by the circuits, the client SDK, and the
//! onchain verifier program:
//!
//! - `Commitment`, `Nullifier`, `NullifierHash`, `MerkleRoot` — domain types
//! - `MerkleTree` — offchain tree with onchain-compatible root computation
//! - `Keys` — spending key, viewing key, key derivation
//! - `Poseidon` wrapper — circom-compatible, byte-for-byte equivalent to the
//!   onchain `solana-poseidon` syscall
//! - `ElGamal` on BN254 G1 and Baby Jubjub — for per-deposit selective disclosure
//! - `DepositNote` — the first-class concept a user holds to spend a deposit
//!
//! The engineering brief with full design rationale lives at
//! `docs/release/PROJECT_BRIEF.md`.
//! Architectural decisions with their rationale live under
//! `docs/release/adr/`.
//! The threat model, known limitations, and the Day-1 Validation Checklist
//! that governs the first steps of implementation live at
//! `docs/release/security.md`.
