// Anchor macros emit cfg values and code patterns the workspace
// lints would otherwise flag.
#![allow(unexpected_cfgs)]
#![allow(clippy::wildcard_imports, clippy::diverging_sub_expression)]

//! tidex6-tip-jar — reference integration example.
//!
//! A *third-party* Anchor program that uses `tidex6-verifier` as a
//! privacy primitive via Cross-Program Invocation. Anyone can call
//! `tip(creator, ...)` to drop a fixed-denomination shielded deposit
//! that is *addressed* to a creator pubkey; the creator later
//! redeems the note through the normal tidex6 withdraw path
//! (CLI / SDK / `tidex6.com`). To everyone watching the chain, the
//! tipper is invisible — the only public information is "someone
//! tipped this creator", and even that is opt-in via the
//! `TipEvent` we emit.
//!
//! # Why this exists
//!
//! This program demonstrates the **composability** story of tidex6:
//! a DAO, a payroll program, a subscription service, an NFT royalty
//! splitter — anything that already runs as an Anchor program — can
//! integrate privacy in **~30 lines of code** by routing its money
//! flow through a CPI into `tidex6_verifier::deposit`.
//!
//! The note returned by a CPI deposit is identical to one produced
//! by a direct CLI deposit:
//!   - same `(secret, nullifier)` pair derives the same commitment
//!   - same Merkle insertion produces the same on-chain history
//!   - same `MemoEnvelope` ciphertext layout
//!
//! Critically: the third-party program **never sees the user's
//! secret material**. The tipper computes `(secret, nullifier,
//! commitment, memo_payload)` off-chain (via `tidex6-client`), then
//! passes only the public commitment + envelope into the program.
//! The note file goes back to the tipper, who hands it to the
//! creator through any out-of-band channel.
//!
//! # Wire format
//!
//! `tip(commitment, memo_payload)` instruction inputs:
//!   - `commitment`: `[u8; 32]` Poseidon(secret, nullifier)
//!   - `memo_payload`: `Vec<u8>` ADR-012 `MemoEnvelope::to_bytes()`
//!
//! Accounts:
//!   - `tipper`: signer + payer; SOL flows from this account to the
//!     pool vault inside the CPI
//!   - `creator`: receiver of the public `TipEvent`; not a signer
//!     and not financially involved at deposit time
//!   - `pool` / `vault`: tidex6 pool PDAs for the chosen denomination
//!   - `tidex6_verifier_program`: the verifier program the CPI
//!     targets
//!   - `system_program`: required by `tidex6_verifier::deposit` for
//!     the SOL transfer into the vault
//!
//! # What is intentionally NOT here
//!
//! This program does not maintain its own state. There is no PDA
//! tracking "how much creator X has earned" — that intentionally
//! lives off-chain in the creator's note set. Any aggregation a
//! UI wants to do can listen to `TipEvent` logs without being
//! tied to this program's storage.

use anchor_lang::prelude::*;
use tidex6_verifier::cpi::accounts::Deposit as VerifierDeposit;
use tidex6_verifier::program::Tidex6Verifier;

declare_id!("5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x");

#[program]
pub mod tidex6_tip_jar {
    use super::*;

    /// Anyone tips a creator with a fixed-denomination shielded
    /// deposit. The tipper supplies a pre-computed commitment and
    /// memo envelope; the program forwards them into
    /// `tidex6_verifier::deposit` via CPI and emits a public
    /// `TipEvent` for indexers and creator-side UIs.
    pub fn tip(
        ctx: Context<Tip>,
        commitment: [u8; 32],
        memo_payload: Vec<u8>,
    ) -> Result<()> {
        // CpiContext::new wants the program's Pubkey (its on-chain
        // address), not the AccountInfo — anchor-lang 1.0.0 signature.
        let cpi_program_id = ctx.accounts.tidex6_verifier_program.key();
        let cpi_accounts = VerifierDeposit {
            pool: ctx.accounts.pool.to_account_info(),
            vault: ctx.accounts.vault.to_account_info(),
            payer: ctx.accounts.tipper.to_account_info(),
            system_program: ctx.accounts.system_program.to_account_info(),
        };
        let cpi_ctx = CpiContext::new(cpi_program_id, cpi_accounts);
        tidex6_verifier::cpi::deposit(cpi_ctx, commitment, memo_payload)?;

        emit!(TipEvent {
            creator: ctx.accounts.creator.key(),
            commitment,
        });
        Ok(())
    }
}

/// Accounts for a single `tip(...)` call.
///
/// Mirrors `tidex6_verifier::Deposit` plus a non-signer `creator`
/// account so we can publish a `TipEvent` referencing the recipient
/// pubkey. `pool` and `vault` are unchecked here — the verifier
/// itself enforces the seeds and bump derivation, so an attacker who
/// supplied the wrong pool would simply have the inner CPI fail.
#[derive(Accounts)]
pub struct Tip<'info> {
    /// CHECK: forwarded as `pool` to `tidex6_verifier::deposit`.
    /// The verifier validates seeds + bump against `denomination`.
    #[account(mut)]
    pub pool: UncheckedAccount<'info>,

    /// CHECK: forwarded as `vault` to `tidex6_verifier::deposit`.
    /// SOL is moved into it via the verifier's internal system_program::transfer CPI.
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,

    /// The tipper. Pays the deposit + tx fee.
    #[account(mut)]
    pub tipper: Signer<'info>,

    /// CHECK: address only — used purely to surface `creator` in the
    /// emitted `TipEvent`. Not financially involved at this stage;
    /// they redeem later via the normal withdraw path.
    pub creator: UncheckedAccount<'info>,

    pub tidex6_verifier_program: Program<'info, Tidex6Verifier>,
    pub system_program: Program<'info, System>,
}

/// Emitted on every successful `tip(...)`. Indexers and creator UIs
/// subscribe to this to count incoming tips and surface new notes.
/// The `commitment` is public anyway (it lands on-chain inside the
/// pool's Merkle tree), so emitting it here costs no privacy and
/// gives consumers a stable handle for cross-referencing.
#[event]
pub struct TipEvent {
    pub creator: Pubkey,
    pub commitment: [u8; 32],
}
