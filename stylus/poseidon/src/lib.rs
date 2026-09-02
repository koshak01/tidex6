//! Poseidon-T3 over BN254 as its own Stylus contract.
//!
//! The pool needs twenty Poseidon hashes per deposit, and the round constants
//! alone are six kilobytes that no compressor can shrink: they are random
//! field elements. Inside the pool they pushed the WASM past the 24 KB code
//! limit, which on Arbitrum Sepolia means a fragmented, factory-driven deploy
//! that costs more than the rest of the system. Here the hash lives in a
//! contract of its own and the pool calls it — one static call per parent.
//!
//! `hash(uint256,uint256)` is byte-identical to `tidex6_core::poseidon::hash_pair`,
//! to the in-circuit gadget, to the `solana-poseidon` syscall and to
//! `contracts/src/PoseidonT3.sol`. Reverts with empty data when an input is
//! not a field element, so a caller can never get a "hash" of something other
//! than what it passed.

#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
extern crate alloc;

// The stylus-proc macros (`#[storage]`, `#[public]`) expand to `Vec` and
// `vec!`; under `no_std` nobody imports those for us.
#[allow(unused_imports)]
use alloc::vec;
#[allow(unused_imports)]
use alloc::vec::Vec;

use alloy_primitives::U256;
use stylus_sdk::prelude::*;

use tidex6_stylus_common::poseidon::hash_pair;

/// Stateless: the constants are code.
#[storage]
#[entrypoint]
pub struct Tidex6Poseidon {}

#[public]
impl Tidex6Poseidon {
    /// Poseidon(left, right) — the Merkle parent hash.
    pub fn hash(&self, left: U256, right: U256) -> Result<U256, Vec<u8>> {
        hash_pair(left, right).ok_or_else(Vec::new)
    }
}
