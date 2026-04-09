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
use groth16_solana::groth16::Groth16Verifier;
use solana_poseidon::{Endianness, Parameters, hashv};

mod groth16_test_vectors;
mod pool;

use groth16_test_vectors::{PUBLIC_INPUTS, VERIFYING_KEY};
pub use pool::{DepositEvent, FIELD_ELEMENT_BYTES, PoolState, ROOT_RING_SIZE, TREE_DEPTH};

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

    /// Verify a Groth16 proof onchain against the hardcoded
    /// `VERIFYING_KEY` and `PUBLIC_INPUTS` from the upstream
    /// `groth16-solana` test suite. The caller passes the three proof
    /// components `(proof_a, proof_b, proof_c)` in the serialization
    /// expected by `groth16-solana`: `proof_a` must already be negated
    /// offchain, `proof_b` and `proof_c` are passed through verbatim.
    ///
    /// This is Day-1 Validation Checklist item 2 (Groth16 pipeline
    /// smoke test) and item 3 (alt_bn128 syscall availability) in a
    /// single instruction: a successful `Groth16Verifier::verify()`
    /// proves that `alt_bn128_addition`, `alt_bn128_multiplication`,
    /// and `alt_bn128_pairing` syscalls are all active on the target
    /// cluster.
    ///
    /// Logs `tidex6-day1-groth16:VALID` on success or
    /// `tidex6-day1-groth16:INVALID` on failure. Also logs
    /// `tidex6-day1-alt_bn128:OK` because a successful pairing result
    /// transitively validates Gate 3.
    /// Initialise a new shielded pool for the given denomination.
    /// Delegates to `pool::handle_init_pool`. See `pool.rs` and
    /// ADR-002 for the full rationale.
    pub fn init_pool(context: Context<InitPool>, denomination: u64) -> Result<()> {
        pool::handle_init_pool(context, denomination)
    }

    /// Deposit `commitment` into the pool, transferring
    /// `denomination` lamports from the payer into the vault PDA
    /// and updating the onchain Merkle root.
    pub fn deposit(context: Context<Deposit>, commitment: [u8; FIELD_ELEMENT_BYTES]) -> Result<()> {
        pool::handle_deposit(context, commitment)
    }

    pub fn verify_test_proof(
        context: Context<VerifyTestProof>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
    ) -> Result<()> {
        let _ = context;

        let mut verifier =
            Groth16Verifier::<9>::new(&proof_a, &proof_b, &proof_c, &PUBLIC_INPUTS, &VERIFYING_KEY)
                .map_err(|_| Tidex6VerifierError::Groth16VerifierConstructFailed)?;

        match verifier.verify() {
            Ok(()) => {
                msg!("tidex6-day1-groth16:VALID");
                msg!("tidex6-day1-alt_bn128:OK");
                Ok(())
            }
            Err(_) => {
                msg!("tidex6-day1-groth16:INVALID");
                Err(Tidex6VerifierError::Groth16VerificationFailed.into())
            }
        }
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

/// Accounts for `init_pool`. Creates the `PoolState` PDA for a
/// given denomination and its companion vault PDA. Both seeds are
/// derived from the denomination so there is exactly one pool per
/// denomination on any given cluster.
///
/// `pool` uses `AccountLoader` because `PoolState` is a zero-copy
/// account — see the type definition in `pool.rs` for the rationale.
#[derive(Accounts)]
#[instruction(denomination: u64)]
pub struct InitPool<'info> {
    #[account(
        init,
        payer = payer,
        space = PoolState::DISCRIMINATOR.len() + std::mem::size_of::<PoolState>(),
        seeds = [PoolState::POOL_SEED_PREFIX, &denomination.to_le_bytes()],
        bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    /// CHECK: the vault is a system-owned PDA created here with a
    /// deterministic seed; lamports flow in via the system program
    /// and out via a seeded signer at withdrawal time. No further
    /// account-level validation is needed.
    #[account(
        init,
        payer = payer,
        space = 0,
        seeds = [PoolState::VAULT_SEED_PREFIX, &denomination.to_le_bytes()],
        bump,
        owner = anchor_lang::system_program::ID,
    )]
    pub vault: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Accounts for `deposit`. The pool PDA and vault PDA are both
/// re-derived from the pool's denomination field at runtime so the
/// caller cannot confuse one denomination for another.
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX, &pool.load()?.denomination.to_le_bytes()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    /// CHECK: vault is a known-seed system-owned PDA derived from
    /// the same denomination as `pool`. SOL flows into it via the
    /// system program.
    #[account(
        mut,
        seeds = [PoolState::VAULT_SEED_PREFIX, &pool.load()?.denomination.to_le_bytes()],
        bump,
    )]
    pub vault: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Accounts required by `verify_test_proof`. Same minimum surface as
/// `HashPoseidon` — pure compute, no program-owned state.
#[derive(Accounts)]
pub struct VerifyTestProof<'info> {
    pub payer: Signer<'info>,
}

#[error_code]
pub enum Tidex6VerifierError {
    #[msg("Unsupported Poseidon input count: must be between 1 and 12.")]
    UnsupportedInputCount,
    #[msg("Onchain Poseidon syscall failed.")]
    PoseidonSyscallFailed,
    #[msg("Failed to construct the Groth16 verifier from the supplied proof.")]
    Groth16VerifierConstructFailed,
    #[msg("Groth16 proof verification failed.")]
    Groth16VerificationFailed,
    #[msg("Pool denomination must be greater than zero.")]
    InvalidDenomination,
    #[msg("Pool is full; no more deposits can be accepted into this tree.")]
    PoolFull,
}
