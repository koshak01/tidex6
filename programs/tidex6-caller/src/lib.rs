// Anchor macros emit cfg values and code patterns that our workspace
// lints would otherwise flag. Same exemptions as tidex6-verifier.
#![allow(unexpected_cfgs)]
#![allow(clippy::wildcard_imports, clippy::diverging_sub_expression)]

//! tidex6-caller — Day-1 Validation Checklist Gate 4.
//!
//! This program exists for one reason: to prove that a Solana program
//! built with Anchor 1.0 can make a cross-program invocation into
//! another Anchor 1.0 program while passing a 256-byte Groth16 proof
//! as instruction data, and have the downstream program verify the
//! proof successfully.
//!
//! It forwards a `verify_test_proof` call to `tidex6-verifier` via
//! CPI, then logs `tidex6-day1-cpi:OK` if the verifier returned
//! `Ok(())`. The offchain validation harness scans for that log line.
//!
//! This is a throwaway program. Once Day-1 is closed it will be
//! removed or repurposed as a reference integration example.

use anchor_lang::prelude::*;
use tidex6_verifier::cpi::accounts::VerifyTestProof as VerifyTestProofAccounts;
use tidex6_verifier::program::Tidex6Verifier;

declare_id!("FnNv9i3uPNcRg7XuQ6Bd7w7j3MBNprXhbffnnJQMjmb7");

#[program]
pub mod tidex6_caller {
    use super::*;

    /// Forwards the three Groth16 proof components to the
    /// `tidex6-verifier` program via CPI. On success, logs
    /// `tidex6-day1-cpi:OK` so the Day-1 harness can detect Gate 4
    /// passing.
    pub fn forward_verify(
        context: Context<ForwardVerify>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
    ) -> Result<()> {
        let cpi_program_id = context.accounts.tidex6_verifier_program.key();
        let cpi_accounts = VerifyTestProofAccounts {
            payer: context.accounts.payer.to_account_info(),
        };
        let cpi_context = CpiContext::new(cpi_program_id, cpi_accounts);

        tidex6_verifier::cpi::verify_test_proof(cpi_context, proof_a, proof_b, proof_c)?;

        msg!("tidex6-day1-cpi:OK");
        Ok(())
    }
}

/// Accounts required for `forward_verify`. Mirrors the downstream
/// `VerifyTestProof` accounts plus the verifier program account that
/// the CPI targets.
#[derive(Accounts)]
pub struct ForwardVerify<'info> {
    pub payer: Signer<'info>,
    pub tidex6_verifier_program: Program<'info, Tidex6Verifier>,
}
