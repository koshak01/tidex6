#![allow(unexpected_cfgs)]
#![allow(clippy::wildcard_imports, clippy::diverging_sub_expression)]

//! tidex6-confidential-pool — hidden-amount shielded pool (ADR-015, Stage 2).
//!
//! Forked from `tidex6-verifier-v2` and upgraded to arbitrary hidden
//! amounts over a USDC token-vault. The amount lives inside the commitment
//! `Poseidon(secret, nullifier, amount)` (range-proved), so there are no
//! fixed denominations. `withdraw` verifies the 8-public-input
//! `WithdrawCircuit` with exact recipient/relayer binding (GAP2 fix) and
//! `relayer_fee` (ADR-011); `transfer_note` verifies the 4-public-input
//! JoinSplit `TransferCircuit` — a fully confidential internal transfer
//! that moves no tokens. The Merkle mechanics and per-nullifier PDA are
//! reused unchanged. See `docs/release/adr/ADR-015-*.md`.

use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

mod pool;
mod transfer_vk;
mod withdraw_vk;

pub use pool::{
    DepositEvent, FIELD_ELEMENT_BYTES, MemoAccount, NullifierRecord, PoolState, ROOT_RING_SIZE,
    TREE_DEPTH, TransferNoteEvent, WithdrawEvent,
};
pub use transfer_vk::{TRANSFER_NR_PUBLIC_INPUTS, TRANSFER_VERIFYING_KEY};
pub use withdraw_vk::{WITHDRAW_NR_PUBLIC_INPUTS, WITHDRAW_VERIFYING_KEY};

declare_id!("8zyGqNJ3xibXJEA6WZ9SAq124tztUj7MSN9u1gDM7AgH");

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "tidex6-confidential-pool",
    project_url: "https://github.com/koshak01/tidex6",
    contacts: "email:koshak01@users.noreply.github.com",
    policy: "https://github.com/koshak01/tidex6/blob/master/SECURITY.md",
    preferred_languages: "en,ru",
    source_code: "https://github.com/koshak01/tidex6",
    auditors: "Unaudited - see docs/release/security.md for threat model"
}

#[program]
pub mod tidex6_confidential_pool {
    use super::*;

    /// Initialise a confidential pool for the given mint (USDC).
    pub fn init_pool(context: Context<InitPool>) -> Result<()> {
        pool::handle_init_pool(context)
    }

    /// Deposit a hidden-amount note. Transfers `amount` tokens into the
    /// vault, appends `commitment = Poseidon(secret, nullifier, amount)`,
    /// and opens the ML-KEM memo account.
    pub fn deposit(
        context: Context<Deposit>,
        commitment: [u8; FIELD_ELEMENT_BYTES],
        amount: u64,
        memo_total_len: u32,
        revoke_window: i64,
        memo_chunk: Vec<u8>,
    ) -> Result<()> {
        pool::handle_deposit(
            context,
            commitment,
            amount,
            memo_total_len,
            revoke_window,
            memo_chunk,
        )
    }

    /// Append the next chunk of the ML-KEM envelope.
    pub fn append_memo(
        context: Context<AppendMemo>,
        commitment: [u8; FIELD_ELEMENT_BYTES],
        offset: u32,
        chunk: Vec<u8>,
    ) -> Result<()> {
        let _ = commitment;
        pool::handle_append_memo(context, offset, chunk)
    }

    /// Reclaim a never-withdrawn deposit after its revoke window.
    pub fn refund(
        context: Context<Refund>,
        commitment: [u8; FIELD_ELEMENT_BYTES],
        secret: [u8; FIELD_ELEMENT_BYTES],
        nullifier: [u8; FIELD_ELEMENT_BYTES],
        nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
        amount: u64,
    ) -> Result<()> {
        pool::handle_refund(
            context,
            commitment,
            secret,
            nullifier,
            nullifier_hash,
            amount,
        )
    }

    /// Withdraw a hidden-amount note (8-public-input WithdrawCircuit).
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        context: Context<Withdraw>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        merkle_root: [u8; FIELD_ELEMENT_BYTES],
        nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
        amount: u64,
        relayer_fee: u64,
    ) -> Result<()> {
        pool::handle_withdraw(
            context,
            proof_a,
            proof_b,
            proof_c,
            merkle_root,
            nullifier_hash,
            amount,
            relayer_fee,
        )
    }

    /// Confidential internal transfer (4-public-input JoinSplit
    /// TransferCircuit): spend one note, mint two, conserve value, hide
    /// every amount. No tokens move.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_note(
        context: Context<TransferNote>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        merkle_root: [u8; FIELD_ELEMENT_BYTES],
        nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
        commitment_out1: [u8; FIELD_ELEMENT_BYTES],
        commitment_out2: [u8; FIELD_ELEMENT_BYTES],
    ) -> Result<()> {
        pool::handle_transfer_note(
            context,
            proof_a,
            proof_b,
            proof_c,
            merkle_root,
            nullifier_hash,
            commitment_out1,
            commitment_out2,
        )
    }
}

/// Encode 32 bytes as a lowercase hexadecimal string.
fn encode_hex(bytes: [u8; 32]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX_CHARS[(byte >> 4) as usize] as char);
        out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    out
}

// ──────────────────────────────────────────────────────────────────────
// Accounts
// ──────────────────────────────────────────────────────────────────────

/// `init_pool` — creates the pool state PDA and its token vault (a PDA
/// token account owned by the pool PDA).
#[derive(Accounts)]
pub struct InitPool<'info> {
    #[account(
        init,
        payer = payer,
        space = PoolState::DISCRIMINATOR.len() + std::mem::size_of::<PoolState>(),
        seeds = [PoolState::POOL_SEED_PREFIX, mint.key().as_ref()],
        bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        init,
        payer = payer,
        seeds = [PoolState::VAULT_SEED_PREFIX, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = pool,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

/// `deposit` — moves `amount` USDC into the vault and opens the memo.
#[derive(Accounts)]
#[instruction(commitment: [u8; FIELD_ELEMENT_BYTES], amount: u64, memo_total_len: u32)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX, pool.load()?.mint.as_ref()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [PoolState::VAULT_SEED_PREFIX, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = pool,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = payer,
    )]
    pub depositor_token: Account<'info, TokenAccount>,

    #[account(
        init,
        payer = payer,
        space = MemoAccount::space(memo_total_len),
        seeds = [MemoAccount::SEED_PREFIX, &commitment],
        bump,
    )]
    pub memo: Account<'info, MemoAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// `append_memo` — re-derives the memo from the commitment.
#[derive(Accounts)]
#[instruction(commitment: [u8; FIELD_ELEMENT_BYTES])]
pub struct AppendMemo<'info> {
    #[account(
        mut,
        seeds = [MemoAccount::SEED_PREFIX, &commitment],
        bump = memo.bump,
        has_one = depositor,
    )]
    pub memo: Account<'info, MemoAccount>,

    pub depositor: Signer<'info>,
}

/// `refund` — returns `amount` USDC and permanently spends the note.
#[derive(Accounts)]
#[instruction(
    commitment: [u8; FIELD_ELEMENT_BYTES],
    secret: [u8; FIELD_ELEMENT_BYTES],
    nullifier: [u8; FIELD_ELEMENT_BYTES],
    nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
)]
pub struct Refund<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX, pool.load()?.mint.as_ref()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [PoolState::VAULT_SEED_PREFIX, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = pool,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = depositor,
    )]
    pub depositor_token: Account<'info, TokenAccount>,

    #[account(
        mut,
        close = depositor,
        seeds = [MemoAccount::SEED_PREFIX, &commitment],
        bump = memo.bump,
        has_one = depositor,
    )]
    pub memo: Account<'info, MemoAccount>,

    #[account(
        init,
        payer = depositor,
        space = NullifierRecord::ACCOUNT_SIZE,
        seeds = [NullifierRecord::SEED_PREFIX, &nullifier_hash],
        bump,
    )]
    pub nullifier: Account<'info, NullifierRecord>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// `withdraw` — pays the recipient and relayer from the vault.
#[derive(Accounts)]
#[instruction(
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: [u8; FIELD_ELEMENT_BYTES],
    nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX, pool.load()?.mint.as_ref()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [PoolState::VAULT_SEED_PREFIX, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = pool,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(
        init,
        payer = payer,
        space = NullifierRecord::ACCOUNT_SIZE,
        seeds = [NullifierRecord::SEED_PREFIX, &nullifier_hash],
        bump,
    )]
    pub nullifier: Account<'info, NullifierRecord>,

    /// CHECK: recipient wallet, bound to the proof (public inputs 3–4).
    pub recipient: UncheckedAccount<'info>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = recipient,
    )]
    pub recipient_token: Account<'info, TokenAccount>,

    /// CHECK: relayer wallet, bound to the proof (public inputs 5–6, ADR-011).
    pub relayer: UncheckedAccount<'info>,

    #[account(
        mut,
        token::mint = mint,
        token::authority = relayer,
    )]
    pub relayer_token: Account<'info, TokenAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

/// `transfer_note` — JoinSplit; burns one nullifier, appends two leaves.
/// No token accounts: value stays in the vault.
#[derive(Accounts)]
#[instruction(
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: [u8; FIELD_ELEMENT_BYTES],
    nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
)]
pub struct TransferNote<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX, pool.load()?.mint.as_ref()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    #[account(
        init,
        payer = payer,
        space = NullifierRecord::ACCOUNT_SIZE,
        seeds = [NullifierRecord::SEED_PREFIX, &nullifier_hash],
        bump,
    )]
    pub nullifier: Account<'info, NullifierRecord>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum Tidex6VerifierError {
    #[msg("Onchain Poseidon syscall failed.")]
    PoseidonSyscallFailed,
    #[msg("Failed to construct the Groth16 verifier from the supplied proof.")]
    Groth16VerifierConstructFailed,
    #[msg("Groth16 proof verification failed.")]
    Groth16VerificationFailed,
    #[msg("Deposit amount must be greater than zero.")]
    InvalidAmount,
    #[msg("Pool is full; no more deposits can be accepted into this tree.")]
    PoolFull,
    #[msg("The supplied Merkle root is not in the pool's recent-root ring buffer.")]
    MerkleRootNotRecent,
    #[msg("Relayer fee must not exceed the note amount.")]
    InvalidRelayerFee,
    #[msg("Memo total length is outside the accepted bounds.")]
    InvalidMemoTotalLen,
    #[msg("Memo chunk would write past the declared total length.")]
    MemoChunkOverflow,
    #[msg("Memo append offset does not match the written-length cursor.")]
    MemoOffsetMismatch,
    #[msg("Memo account is already finalized; no more appends allowed.")]
    MemoAlreadyFinalized,
    #[msg("Refund presented (secret, nullifier, amount) that do not hash to the commitment.")]
    RefundCommitmentMismatch,
    #[msg("Refund presented a nullifier that does not hash to the nullifier_hash.")]
    RefundNullifierMismatch,
    #[msg("Refund attempted before the deposit's revoke window elapsed.")]
    RefundTooEarly,
    #[msg("This deposit is irrevocable (revoke_window = 0); refund is disabled.")]
    RefundDisabled,
}
