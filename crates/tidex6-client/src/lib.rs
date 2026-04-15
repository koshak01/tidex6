//! tidex6 Rust SDK: high-level API for shielded deposits and
//! withdrawals.
//!
//! This crate is the primary integration surface for Rust-side
//! consumers of the tidex6 privacy framework. It wraps the lower
//! layers (`tidex6-core` primitives, `tidex6-circuits` Groth16
//! proving, `tidex6-indexer` Merkle tree reconstruction, and the
//! onchain `tidex6-verifier` Anchor program) into a builder-pattern
//! API that a dapp developer can pick up in five lines of code.
//!
//! # Example
//!
//! ```no_run
//! use anchor_client::Cluster;
//! use solana_keypair::Keypair;
//! use tidex6_client::PrivatePool;
//! use tidex6_core::note::Denomination;
//!
//! # fn demo(payer: Keypair, recipient: anchor_client::anchor_lang::prelude::Pubkey)
//! #     -> anyhow::Result<()> {
//! let pool = PrivatePool::connect(Cluster::Devnet, Denomination::OneSol)?;
//!
//! // Depositor side: make a fresh note and push it into the pool.
//! let outcome = pool.deposit(&payer).send()?;
//! std::fs::write("parents.note", outcome.note.to_text())?;
//! let note = outcome.note.clone();
//!
//! // Recipient side: redeem the note. The pool rebuilds its
//! // Merkle tree from on-chain history via `tidex6-indexer` and
//! // generates the withdraw proof.
//! let withdraw_sig = pool
//!     .withdraw(&payer)
//!     .note(note)
//!     .to(recipient)
//!     .send()?;
//! # drop((outcome.signature, withdraw_sig));
//! # Ok(())
//! # }
//! ```
//!
//! # Design
//!
//! - [`PrivatePool`] is a handle for one pool instance on one
//!   cluster. A `PrivatePool` is scoped to exactly one
//!   [`Denomination`][`tidex6_core::note::Denomination`] because
//!   the onchain program enforces a fixed-amount constraint per
//!   pool.
//! - [`DepositBuilder`] and [`WithdrawBuilder`] are consumed by
//!   `.send()` and return a tuple of `(Signature, ...)`. Both
//!   builders hold a reference to the parent `PrivatePool` so the
//!   caller only constructs one connection per pool.
//! - The proving key for the withdraw circuit is loaded once on
//!   demand from the cached artifact in
//!   `crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin`,
//!   or the caller can supply their own `Arc<ProvingKey<Bn254>>`
//!   via [`WithdrawBuilder::proving_key`] to amortise the ~50 MB
//!   deserialisation cost across many withdraws.
//!
//! # Errors
//!
//! All top-level methods return `anyhow::Result<T>` so callers
//! can `?` straight through. Upstream crates still expose their
//! own `thiserror`-based error types (see
//! [`tidex6_core::types::DomainError`],
//! [`tidex6_circuits::withdraw::WithdrawCircuitError`],
//! [`tidex6_indexer::IndexerError`]) — the SDK wraps those with
//! short context strings rather than re-exporting them, so
//! integrators see one error type at the top of their call graph.

pub mod accountant;
pub mod deposit;
pub mod pool;
pub mod withdraw;

pub use accountant::{AccountantEntry, AccountantScanner};
pub use deposit::{DepositBuilder, DepositOutcome};
pub use pool::PrivatePool;
pub use withdraw::WithdrawBuilder;

// Re-export commonly needed types so consumers can use the SDK
// without pulling in tidex6-core directly for trivial types.
pub use tidex6_core::note::{Denomination, DepositNote, NoteError};
