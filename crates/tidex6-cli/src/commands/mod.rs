//! CLI subcommand modules.
//!
//! Each submodule is one `tidex6 <command>` verb. The top-level
//! dispatch lives in `main.rs` and just calls into these handlers.

pub mod accountant;
pub mod deposit;
pub mod keygen;
pub mod withdraw;
