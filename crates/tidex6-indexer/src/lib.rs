//! tidex6-indexer: offchain Merkle tree reconstruction.
//!
//! The onchain `tidex6-verifier` program stores only a ring buffer
//! of recent Merkle roots plus a `next_leaf_index` counter. The
//! full tree lives offchain and must be rebuilt by anyone who
//! wants to generate a withdrawal proof for a past deposit.
//!
//! This crate walks the Solana transaction history of a pool PDA,
//! parses the `tidex6-deposit:<leaf>:<commitment>:<root>` program
//! log lines emitted by every successful deposit, orders them
//! chronologically, and replays the inserts into a
//! `tidex6_core::merkle::MerkleTree`. The resulting tree can serve
//! `MerkleTree::proof(leaf_index)` for any leaf the pool has
//! observed.
//!
//! The crate is intentionally small and single-purpose. It is used
//! by `tidex6-cli` and `tidex6-client` whenever they need a Merkle
//! inclusion proof for a withdrawal, and by integrators who want
//! to snapshot a pool without running their own node.

pub mod rebuild;

pub use rebuild::{IndexerError, PoolIndexer};
