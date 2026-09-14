//! Shared arithmetic for the tidex6 Stylus contracts.
//!
//! Everything here is pure: no storage, no host calls. The contracts that need
//! the VM (the verifiers, the pools, `registry`) depend on this crate for the
//! field constants, the Poseidon hash and the Groth16 pairing check so that
//! all of them agree on these by construction rather than by copy.

#![no_std]

extern crate alloc;

pub mod field;
pub mod groth16;
pub mod poseidon;
mod poseidon_consts;
