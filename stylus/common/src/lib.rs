//! Shared arithmetic for the tidex6 Stylus contracts.
//!
//! Everything here is pure: no storage, no host calls. The contracts that need
//! the VM (`verifier`, `pool`, `registry`) depend on this crate for the field
//! constants and the Poseidon hash so that all three agree on them by
//! construction rather than by copy.

#![no_std]

pub mod field;
pub mod poseidon;
mod poseidon_consts;
