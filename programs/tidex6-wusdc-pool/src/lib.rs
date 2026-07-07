#![allow(unexpected_cfgs)]
#![allow(clippy::wildcard_imports, clippy::diverging_sub_expression)]

//! tidex6-wusdc-pool — verify-only shielded pool for Token-2022 CT wUSDC (ADR-015).
//!
//! Hides the LINKAGE (who↔whom) while the amount stays hidden by the Token-2022
//! confidential wUSDC layer. The pool moves no asset: it proves membership and
//! burns the nullifier, then emits an event; the relayer moves the confidential
//! wUSDC to the recipient. Reuses the 5-public-input `WithdrawCircuit` VK
//! (commitment = Poseidon(secret, nullifier), no amount) — so no new ceremony.
//! See `_analysis/WUSDC_POOL_DESIGN.md`.

use anchor_lang::prelude::*;

mod pool;
mod withdraw_vk;

pub use pool::{
    DepositEvent, MemoAccount, NullifierRecord, PoolState, RefundApproved, WithdrawApproved,
    FIELD_ELEMENT_BYTES, ROOT_RING_SIZE, TREE_DEPTH,
};
pub use withdraw_vk::{WITHDRAW_NR_PUBLIC_INPUTS, WITHDRAW_VERIFYING_KEY};

// Тот же код пула, два program-id: wUSDC (дефолт) и wUSDT (feature "wusdt").
// PDA program-scoped → отдельная программа = полностью изолированный пул.
#[cfg(not(feature = "wusdt"))]
declare_id!("AYTRKmF8VBdqRWGZr9c6Mx582SRm2tbUEwMesFMhcPcU");
#[cfg(feature = "wusdt")]
declare_id!("QGPYpwyMnWhJUPGieXyJU5jhAkKsKuU7iGN53VCWPz2");

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "tidex6-wusdc-pool",
    project_url: "https://github.com/koshak01/tidex6",
    contacts: "email:koshak01@users.noreply.github.com",
    policy: "https://github.com/koshak01/tidex6/blob/master/SECURITY.md",
    preferred_languages: "en,ru",
    source_code: "https://github.com/koshak01/tidex6",
    auditors: "Unaudited - see docs/release/security.md for threat model"
}

#[program]
pub mod tidex6_wusdc_pool {
    use super::*;

    /// Initialise the singleton wUSDC pool for the given mint.
    pub fn init_pool(context: Context<InitPool>, mint: Pubkey) -> Result<()> {
        pool::handle_init_pool(context, mint)
    }

    /// Deposit `commitment = Poseidon(secret, nullifier)` and open the memo.
    /// Moves no asset — the wUSDC arrives in the pool CT account separately.
    pub fn deposit(
        context: Context<Deposit>,
        commitment: [u8; FIELD_ELEMENT_BYTES],
        memo_total_len: u32,
        revoke_window: i64,
        memo_chunk: Vec<u8>,
    ) -> Result<()> {
        pool::handle_deposit(context, commitment, memo_total_len, revoke_window, memo_chunk)
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

    /// Revoke: burn the nullifier, emit `RefundApproved` (relayer returns wUSDC).
    pub fn refund(
        context: Context<Refund>,
        commitment: [u8; FIELD_ELEMENT_BYTES],
        secret: [u8; FIELD_ELEMENT_BYTES],
        nullifier: [u8; FIELD_ELEMENT_BYTES],
        nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    ) -> Result<()> {
        pool::handle_refund(context, commitment, secret, nullifier, nullifier_hash)
    }

    /// Verify a withdrawal proof, burn the nullifier, emit `WithdrawApproved`
    /// (relayer moves the confidential wUSDC to the recipient). Moves no asset.
    pub fn withdraw(
        context: Context<Withdraw>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        merkle_root: [u8; FIELD_ELEMENT_BYTES],
        nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
        relayer_fee: u64,
    ) -> Result<()> {
        pool::handle_withdraw(
            context,
            proof_a,
            proof_b,
            proof_c,
            merkle_root,
            nullifier_hash,
            relayer_fee,
        )
    }
}

/// Encode 32 bytes as lowercase hex.
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
// Accounts — no vault, no token program (the pool moves no asset).
// ──────────────────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitPool<'info> {
    #[account(
        init,
        payer = payer,
        space = PoolState::DISCRIMINATOR.len() + std::mem::size_of::<PoolState>(),
        seeds = [PoolState::POOL_SEED_PREFIX],
        bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(commitment: [u8; FIELD_ELEMENT_BYTES], memo_total_len: u32)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

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

    pub system_program: Program<'info, System>,
}

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

    pub system_program: Program<'info, System>,
}

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
        seeds = [PoolState::POOL_SEED_PREFIX],
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

    /// CHECK: recipient wallet, bound to the proof (public input 3).
    pub recipient: UncheckedAccount<'info>,

    /// CHECK: relayer wallet, bound to the proof (public input 4, ADR-011).
    pub relayer: UncheckedAccount<'info>,

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
    #[msg("Pool is full; no more deposits can be accepted into this tree.")]
    PoolFull,
    #[msg("The supplied Merkle root is not in the pool's recent-root ring buffer.")]
    MerkleRootNotRecent,
    #[msg("Memo total length is outside the accepted bounds.")]
    InvalidMemoTotalLen,
    #[msg("Memo chunk would write past the declared total length.")]
    MemoChunkOverflow,
    #[msg("Memo append offset does not match the written-length cursor.")]
    MemoOffsetMismatch,
    #[msg("Memo account is already finalized; no more appends allowed.")]
    MemoAlreadyFinalized,
    #[msg("Refund presented (secret, nullifier) that do not hash to the commitment.")]
    RefundCommitmentMismatch,
    #[msg("Refund presented a nullifier that does not hash to the nullifier_hash.")]
    RefundNullifierMismatch,
    #[msg("Refund attempted before the deposit's revoke window elapsed.")]
    RefundTooEarly,
    #[msg("This deposit is irrevocable (revoke_window = 0); refund is disabled.")]
    RefundDisabled,
}
