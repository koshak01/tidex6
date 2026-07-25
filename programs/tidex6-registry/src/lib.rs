// Anchor macros emit cfg values and code patterns the workspace
// lints would otherwise flag.
#![allow(unexpected_cfgs)]
#![allow(clippy::wildcard_imports, clippy::diverging_sub_expression)]

//! tidex6-registry — publish the lock, keep the key (ADR-019).
//!
//! Maps a Solana wallet address to the reader address that wallet has
//! published, so that a sender needs to know **nothing but the recipient's
//! ordinary wallet address**. No key exchange, no long strings copied between
//! people, no interaction between sender and recipient before a payment.
//!
//! # Why this program has to exist
//!
//! Since ADR-018 a reader's keys are derived from a wallet signature and stored
//! nowhere. Only the owner can produce that signature, so only the owner can
//! compute their own public key — a sender cannot derive it from a wallet
//! address. Someone has to publish it, and the chain is the only place where
//! publishing does not create a party everyone has to trust.
//!
//! # What is published, and why that is safe
//!
//! The stored value is the ADR-014 `ReaderAddress`: an ML-KEM-768 public key
//! (1184 bytes) followed by an X25519 view-tag key (32 bytes). It is a **lock,
//! not a key**. Holding it lets you seal a payment *to* someone; it does not
//! let you open one, spend one, or learn that any payment occurred.
//!
//! Anyone can read this — that is what a public ledger is, and no program can
//! change it: validators hold the whole account set and `getAccountInfo` takes
//! no signature. The design does not depend on read access being restricted.
//!
//! What must **never** be published here is the signature the keys are derived
//! from. The derivation is public, so a stored signature is a stored *private*
//! key — and because withdrawal from the pool proves knowledge of the note's
//! secret rather than ownership of a wallet, whoever read it could move the
//! money without ever touching the victim's wallet. This program has no
//! instruction that accepts a signature, which is the only reliable way to
//! ensure one is never stored by accident.
//!
//! # Authority
//!
//! Write: the wallet itself, as signer. The entry's address is derived from the
//! wallet, so a signer can only ever reach their own — someone else's address
//! derives a different account and the seeds check rejects it.
//!
//! Rotation (when the identity version in the signed phrase is bumped) is
//! `close_reader` then `init_reader`, deliberately two steps: an in-place
//! overwrite could be triggered by a replayed transaction and would leave the
//! entry half-written, with senders sealing to a lock nobody can open.
//!
//! This program holds no funds, has no admin, and cannot affect any other
//! program. The worst outcome of a bug here is that someone publishes a wrong
//! lock for their own wallet and receives payments they cannot open.
//!
//! # Chunked writes
//!
//! 1216 bytes does not fit in a 1232-byte transaction, so `init_reader`
//! allocates the account and `write_reader_chunk` fills it with an offset
//! check — the same pattern `append_memo` uses in the verifier.

use anchor_lang::prelude::*;

declare_id!("D1dCoBuiRehhT24XTF8Dmhm9cFERpmfANLB1bb3aGxLJ");

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "tidex6-registry",
    project_url: "https://tidex6.com",
    contacts: "email:p.elagin@gmail.com,link:https://github.com/koshak01/tidex6/security/advisories/new",
    policy: "https://github.com/koshak01/tidex6/blob/master/SECURITY.md",
    preferred_languages: "en,ru",
    source_code: "https://github.com/koshak01/tidex6",
    source_release: env!("CARGO_PKG_VERSION"),
    auditors: "Unaudited"
}

/// ML-KEM-768 public key length, bytes.
pub const ML_KEM_768_EK_LEN: usize = 1184;

/// X25519 view-tag public key length, bytes.
pub const X25519_PK_LEN: usize = 32;

/// Exact length of a published reader address: `mlkem_pk ‖ x25519_pk`.
///
/// Fixed rather than variable: every valid reader address is exactly this size,
/// so accepting anything else would only let a caller waste rent or publish a
/// lock nobody can use.
pub const READER_ADDRESS_LEN: usize = ML_KEM_768_EK_LEN + X25519_PK_LEN;

/// Largest chunk accepted in one `write_reader_chunk` call.
///
/// A Solana transaction is capped at 1232 bytes in total, and the instruction
/// carries accounts, discriminator and the offset alongside the payload. 900
/// leaves comfortable room, so a full reader address takes two calls.
pub const MAX_CHUNK_LEN: usize = 900;

#[program]
pub mod tidex6_registry {
    use super::*;

    /// Allocate the caller's registry entry.
    ///
    /// Called by the wallet that is registering, as signer: an entry can only
    /// ever be created by its own owner. Fails if one already exists —
    /// replacing a lock is `close_reader` followed by `init_reader`, which
    /// makes rotation an explicit two-step act rather than something that can
    /// happen by accident or by a replayed transaction.
    pub fn init_reader(ctx: Context<InitReader>, version: u8) -> Result<()> {
        let entry = &mut ctx.accounts.entry;
        entry.owner = ctx.accounts.wallet.key();
        entry.version = version;
        entry.written_len = 0;
        entry.is_finalized = false;
        entry.bump = ctx.bumps.entry;
        entry.data = vec![0u8; READER_ADDRESS_LEN];

        msg!(
            "tidex6-registry-init:{}:{}",
            ctx.accounts.wallet.key(),
            version
        );
        Ok(())
    }

    /// Append the next chunk of the reader address.
    ///
    /// `offset` must equal what has already been written: chunks arrive in
    /// order, and a gap would leave zero bytes inside a key that then silently
    /// fails to decrypt anything. The entry becomes usable only once the last
    /// byte lands.
    pub fn write_reader_chunk(
        ctx: Context<WriteReaderChunk>,
        offset: u32,
        chunk: Vec<u8>,
    ) -> Result<()> {
        let entry = &mut ctx.accounts.entry;

        require!(!entry.is_finalized, RegistryError::AlreadyFinalized);
        require!(!chunk.is_empty(), RegistryError::EmptyChunk);
        require!(chunk.len() <= MAX_CHUNK_LEN, RegistryError::ChunkTooLarge);
        require!(offset == entry.written_len, RegistryError::OffsetMismatch);

        let end = (offset as usize)
            .checked_add(chunk.len())
            .ok_or(RegistryError::ChunkOverflow)?;
        require!(end <= READER_ADDRESS_LEN, RegistryError::ChunkOverflow);

        entry.data[offset as usize..end].copy_from_slice(&chunk);
        entry.written_len = end as u32;

        if entry.written_len as usize == READER_ADDRESS_LEN {
            entry.is_finalized = true;
            msg!(
                "tidex6-registry-ready:{}:{}",
                ctx.accounts.wallet.key(),
                entry.version
            );
        }
        Ok(())
    }

    /// Close the entry and refund its rent to the owner.
    ///
    /// After this the wallet is no longer findable and cannot be paid until it
    /// registers again. Provided because rent belongs to whoever paid it, and
    /// because a person is entitled to stop being listed.
    pub fn close_reader(ctx: Context<CloseReader>) -> Result<()> {
        msg!("tidex6-registry-closed:{}", ctx.accounts.wallet.key());
        Ok(())
    }
}

/// One wallet's published reader address.
///
/// Deliberately contains no counterparties, no amounts and no history — only
/// this wallet's own lock. An earlier design had the owner list the wallets
/// allowed to pay them; that would publish the social graph, which is usually
/// more sensitive than the amounts, and a lock needs no allowlist.
#[account]
pub struct ReaderEntry {
    /// The wallet this entry belongs to. Redundant with the PDA seed, kept so a
    /// reader who fetched the account by address can verify it without
    /// recomputing the derivation.
    pub owner: Pubkey,
    /// Identity version from the signed phrase (ADR-018). Lets a sender notice
    /// that a recipient has rotated, rather than silently sealing to a lock the
    /// recipient no longer opens.
    pub version: u8,
    /// Bytes written so far. Equals `READER_ADDRESS_LEN` when complete.
    pub written_len: u32,
    /// PDA bump, stored so clients need not re-derive it.
    pub bump: u8,
    /// True once every byte has landed. A sender must ignore entries where this
    /// is false: a partially written key is not a key.
    pub is_finalized: bool,
    /// `mlkem_pk ‖ x25519_pk`.
    pub data: Vec<u8>,
}

impl ReaderEntry {
    /// Seed prefix for the entry PDA: `[b"reader", wallet_pubkey]`.
    pub const SEED_PREFIX: &'static [u8] = b"reader";

    /// Account size: discriminator + owner + version + written_len + bump +
    /// is_finalized + Vec length prefix + payload.
    pub const SPACE: usize = 8 + 32 + 1 + 4 + 1 + 1 + 4 + READER_ADDRESS_LEN;
}

#[derive(Accounts)]
pub struct InitReader<'info> {
    /// The wallet registering itself. Signer, so no entry can be created for
    /// somebody else, and payer, so rent comes from the person who benefits.
    #[account(mut)]
    pub wallet: Signer<'info>,

    #[account(
        init,
        payer = wallet,
        space = ReaderEntry::SPACE,
        seeds = [ReaderEntry::SEED_PREFIX, wallet.key().as_ref()],
        bump,
    )]
    pub entry: Account<'info, ReaderEntry>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WriteReaderChunk<'info> {
    pub wallet: Signer<'info>,

    // The PDA is derived from `wallet.key()`, so a signer can only ever reach
    // their own entry — someone else's address derives a different PDA and the
    // seeds constraint rejects it. The stored `owner` is checked too, as a
    // belt-and-braces guard against a future refactor of the seeds.
    #[account(
        mut,
        seeds = [ReaderEntry::SEED_PREFIX, wallet.key().as_ref()],
        bump = entry.bump,
        constraint = entry.owner == wallet.key() @ RegistryError::NotOwner,
    )]
    pub entry: Account<'info, ReaderEntry>,
}

#[derive(Accounts)]
pub struct CloseReader<'info> {
    #[account(mut)]
    pub wallet: Signer<'info>,

    #[account(
        mut,
        seeds = [ReaderEntry::SEED_PREFIX, wallet.key().as_ref()],
        bump = entry.bump,
        constraint = entry.owner == wallet.key() @ RegistryError::NotOwner,
        close = wallet,
    )]
    pub entry: Account<'info, ReaderEntry>,
}

#[error_code]
pub enum RegistryError {
    #[msg("this entry is complete; call init_reader first to replace it")]
    AlreadyFinalized,

    #[msg("chunk is empty")]
    EmptyChunk,

    #[msg("chunk exceeds the per-transaction limit")]
    ChunkTooLarge,

    #[msg("chunk offset does not continue where the last one ended")]
    OffsetMismatch,

    #[msg("chunk would write past the end of a reader address")]
    ChunkOverflow,

    #[msg("only the owning wallet may modify this entry")]
    NotOwner,
}
