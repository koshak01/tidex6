// Anchor macros emit cfg values for `target_os = "solana"` and
// `feature = "anchor-debug"` that are not in rustc's default check list.
// These are part of Anchor's internal feature gating and are not bugs.
#![allow(unexpected_cfgs)]
// Anchor's `#[program]` macro generates code that uses `use super::*`
// to bring account-context types into scope inside the program module,
// and contains control-flow shapes that trip clippy's
// `diverging_sub_expression` lint. Both are internal to the macro and
// not under our control, so we silence them crate-wide.
#![allow(clippy::wildcard_imports, clippy::diverging_sub_expression)]

//! tidex6-verifier — onchain Groth16 verifier and Day-1 primitive validation.
//!
//! In the MVP this program starts as the validation harness for the
//! Day-1 Validation Checklist from `docs/release/security.md` section 3.
//! Its instructions exercise the onchain primitives that the rest of the
//! framework will later depend on: the Poseidon syscall, the `alt_bn128`
//! syscalls, and the `groth16-solana` verification crate.
//!
//! Once the primitives are proven to work onchain, this program grows
//! into the full `tidex6-verifier` described in the project brief:
//! a singleton, non-upgradeable Groth16 verifier that integrator
//! programs call via CPI. See `docs/release/adr/ADR-005-non-upgradeable-verifier.md`.

use anchor_lang::prelude::*;
use solana_poseidon::{Endianness, Parameters, hashv};

declare_id!("77CwxmFdDaFpKHXTjR5fHVpUJ36DmhnfBNBzn8dXKo42");

#[program]
pub mod tidex6_verifier {
    use super::*;

    /// Compute `Poseidon(inputs)` onchain and emit the 32-byte result in
    /// a program log. The client fetches the log, decodes the bytes, and
    /// compares them against the offchain `tidex6_core::poseidon` output.
    ///
    /// This is the onchain half of Day-1 Validation Checklist item 1:
    /// byte-for-byte equivalence between `light-poseidon::new_circom` and
    /// the onchain `sol_poseidon` syscall.
    ///
    /// Accepts between 1 and 12 inputs, each 32 bytes, in big-endian
    /// encoding. Values that exceed the BN254 scalar field modulus are
    /// rejected by the syscall itself with a descriptive error.
    pub fn hash_poseidon(context: Context<HashPoseidon>, inputs: Vec<[u8; 32]>) -> Result<()> {
        let _ = context;

        require!(
            !inputs.is_empty() && inputs.len() <= 12,
            Tidex6VerifierError::UnsupportedInputCount
        );

        let slices: Vec<&[u8]> = inputs.iter().map(|slice| slice.as_slice()).collect();
        let hash = hashv(Parameters::Bn254X5, Endianness::BigEndian, &slices)
            .map_err(|_| Tidex6VerifierError::PoseidonSyscallFailed)?;

        // Log the hash as a hex string with a known prefix so the Day-1
        // validation harness can parse it out of the transaction logs
        // without needing Anchor event decoding. This keeps the client
        // side simple and avoids a base64 + discriminator dance.
        let bytes = hash.to_bytes();
        msg!("tidex6-day1-poseidon:{}", encode_hex(bytes));

        Ok(())
    }
}

/// Encode 32 bytes as a lowercase hexadecimal string.
///
/// Deliberately avoids pulling in the `hex` crate so that the program
/// dependency graph stays as small as possible. Runs in O(64) with
/// negligible compute-unit cost.
fn encode_hex(bytes: [u8; 32]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX_CHARS[(byte >> 4) as usize] as char);
        out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Accounts required by `hash_poseidon`.
///
/// The instruction is pure compute — it does not touch any program-owned
/// state, so the only required account is the fee payer. A future
/// production version will require a configuration PDA instead, but for
/// the Day-1 validation harness the minimum surface is correct.
#[derive(Accounts)]
pub struct HashPoseidon<'info> {
    pub payer: Signer<'info>,
}

#[error_code]
pub enum Tidex6VerifierError {
    #[msg("Unsupported Poseidon input count: must be between 1 and 12.")]
    UnsupportedInputCount,
    #[msg("Onchain Poseidon syscall failed.")]
    PoseidonSyscallFailed,
}
