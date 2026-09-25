#![allow(unexpected_cfgs)]
#![allow(clippy::wildcard_imports, clippy::diverging_sub_expression)]

//! tidex6-pool-v2 — shielded pool with note format v2 (ADR-022).
//!
//! The program holds the tokens and files every leaf itself, so a note is
//! bound to the amount actually paid; only the owner's key spends; the
//! funder may refund after its window; every deposit and every in-pool
//! forward pays the 1% fee as a note for the treasury key set at
//! `init_pool`. Same circuits, leaf layout and fee rule as the EVM
//! `Tidex6HiddenPoolV2`. See `pool.rs` and `docs/release/adr/ADR-022-*.md`.

use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

mod pool;
mod transfer_vk;
mod withdraw_vk;

pub use pool::{
    DepositArgs, DepositEvent, FIELD_ELEMENT_BYTES, MemoAccount, NullifierRecord, OwnerKey,
    PoolState, ROOT_RING_SIZE, RefundEvent, TREE_DEPTH, TransferNoteEvent, WithdrawEvent,
};
pub use transfer_vk::{TRANSFER_V2_NR_PUBLIC_INPUTS, TRANSFER_V2_VERIFYING_KEY};
pub use withdraw_vk::{WITHDRAW_V2_NR_PUBLIC_INPUTS, WITHDRAW_V2_VERIFYING_KEY};

// Program key generated in the deployment sandbox, 26.09.2026 (devnet first).
declare_id!("6Pgc17kacebLurJxCmMtrjHcpxvdQR1PtQJf63hG1sVe");

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "tidex6-pool-v2",
    project_url: "https://github.com/koshak01/tidex6",
    contacts: "email:koshak01@users.noreply.github.com",
    policy: "https://github.com/koshak01/tidex6/blob/master/SECURITY.md",
    preferred_languages: "en,ru",
    source_code: "https://github.com/koshak01/tidex6",
    auditors: "Unaudited - see docs/release/security.md for threat model"
}

type Field = [u8; FIELD_ELEMENT_BYTES];

#[program]
pub mod tidex6_pool_v2 {
    use super::*;

    /// Create the pool for a mint with its treasury key and fee floor.
    /// Upgrade authority only.
    pub fn init_pool(
        context: Context<InitPool>,
        treasury_owner_pk: Field,
        fee_floor: u64,
    ) -> Result<()> {
        pool::handle_init_pool(context, treasury_owner_pk, fee_floor)
    }

    /// Publish (or replace) the caller's owner key — what a sender binds a
    /// v2 note to. One per wallet for the whole program, every mint.
    pub fn publish_owner_key(context: Context<PublishOwnerKey>, owner_pk: Field) -> Result<()> {
        pool::handle_publish_owner_key(context, owner_pk)
    }

    /// Pay into the pool: the payment note and its fee note.
    pub fn deposit(context: Context<Deposit>, args: DepositArgs) -> Result<()> {
        pool::handle_deposit(context, args)
    }

    /// Append the next chunk of a note's envelope.
    pub fn append_memo(
        context: Context<AppendMemo>,
        leaf: Field,
        offset: u32,
        chunk: Vec<u8>,
    ) -> Result<()> {
        let _ = leaf;
        pool::handle_append_memo(context, offset, chunk)
    }

    /// Take a note back after its window, if its owner has not spent it.
    pub fn refund(
        context: Context<Refund>,
        leaf: Field,
        owner_pk: Field,
        rho: Field,
        aux: Field,
        nullifier: Field,
    ) -> Result<()> {
        let _ = leaf;
        pool::handle_refund(context, owner_pk, rho, aux, nullifier)
    }

    /// Withdraw a note (owner only, v2 withdraw circuit).
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        context: Context<Withdraw>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        merkle_root: Field,
        nullifier: Field,
        amount: u64,
        relayer_fee: u64,
    ) -> Result<()> {
        pool::handle_withdraw(
            context,
            proof_a,
            proof_b,
            proof_c,
            merkle_root,
            nullifier,
            amount,
            relayer_fee,
        )
    }

    /// Forward a note inside the pool: payment, change, fee. Each output
    /// gets its memo account (`memo_lens`: envelope lengths of pay, change,
    /// fee), filled with `append_memo` afterwards by the same signer.
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_note(
        context: Context<TransferNote>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        merkle_root: Field,
        nullifier: Field,
        leaf_pay: Field,
        leaf_change: Field,
        leaf_fee: Field,
        memo_lens: [u32; 3],
    ) -> Result<()> {
        pool::handle_transfer_note(
            context,
            proof_a,
            proof_b,
            proof_c,
            merkle_root,
            nullifier,
            [leaf_pay, leaf_change, leaf_fee],
            memo_lens,
        )
    }
}

// ── Accounts ─────────────────────────────────────────────────────────────

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

    /// The upgrade authority of this program — the only one who may name a
    /// pool's treasury.
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(constraint = program.programdata_address()? == Some(program_data.key()))]
    pub program: Program<'info, crate::program::Tidex6PoolV2>,

    #[account(constraint = program_data.upgrade_authority_address == Some(payer.key()) @ PoolError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct PublishOwnerKey<'info> {
    #[account(
        init_if_needed,
        payer = wallet,
        space = OwnerKey::ACCOUNT_SIZE,
        seeds = [OwnerKey::SEED_PREFIX, wallet.key().as_ref()],
        bump,
    )]
    pub owner_key: Account<'info, OwnerKey>,

    #[account(mut)]
    pub wallet: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(args: DepositArgs)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX, pool.load()?.mint.as_ref()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    #[account(address = pool.load()?.mint)]
    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [PoolState::VAULT_SEED_PREFIX, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = pool,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut, token::mint = mint, token::authority = payer)]
    pub depositor_token: Account<'info, TokenAccount>,

    #[account(
        init,
        payer = payer,
        space = MemoAccount::space(args.memo_total_len),
        seeds = [MemoAccount::SEED_PREFIX, &args.leaf],
        bump,
    )]
    pub memo: Account<'info, MemoAccount>,

    #[account(
        init,
        payer = payer,
        space = MemoAccount::space(args.fee_memo_total_len),
        seeds = [MemoAccount::SEED_PREFIX, &args.fee_leaf],
        bump,
    )]
    pub fee_memo: Account<'info, MemoAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(leaf: [u8; FIELD_ELEMENT_BYTES])]
pub struct AppendMemo<'info> {
    #[account(
        mut,
        seeds = [MemoAccount::SEED_PREFIX, &leaf],
        bump = memo.bump,
        has_one = depositor,
    )]
    pub memo: Account<'info, MemoAccount>,

    pub depositor: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(
    leaf: [u8; FIELD_ELEMENT_BYTES],
    owner_pk: [u8; FIELD_ELEMENT_BYTES],
    rho: [u8; FIELD_ELEMENT_BYTES],
    aux: [u8; FIELD_ELEMENT_BYTES],
    nf: [u8; FIELD_ELEMENT_BYTES],
)]
pub struct Refund<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX, pool.load()?.mint.as_ref()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    #[account(address = pool.load()?.mint)]
    pub mint: Account<'info, Mint>,

    #[account(
        mut,
        seeds = [PoolState::VAULT_SEED_PREFIX, mint.key().as_ref()],
        bump,
        token::mint = mint,
        token::authority = pool,
    )]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut, token::mint = mint, token::authority = depositor)]
    pub depositor_token: Account<'info, TokenAccount>,

    // Not closed: the memo accounts are the pool's leaf list — every client
    // rebuilds the tree from them, and a closed one would leave a hole that
    // no later withdraw could prove against.
    #[account(
        seeds = [MemoAccount::SEED_PREFIX, &leaf],
        bump = memo.bump,
        has_one = depositor,
    )]
    pub memo: Account<'info, MemoAccount>,

    #[account(
        init,
        payer = depositor,
        space = NullifierRecord::ACCOUNT_SIZE,
        seeds = [NullifierRecord::SEED_PREFIX, &nf],
        bump,
    )]
    pub nullifier: Account<'info, NullifierRecord>,

    #[account(mut)]
    pub depositor: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: [u8; FIELD_ELEMENT_BYTES],
    nf: [u8; FIELD_ELEMENT_BYTES],
)]
pub struct Withdraw<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX, pool.load()?.mint.as_ref()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    #[account(address = pool.load()?.mint)]
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
        seeds = [NullifierRecord::SEED_PREFIX, &nf],
        bump,
    )]
    pub nullifier: Account<'info, NullifierRecord>,

    /// CHECK: recipient wallet, bound to the proof (public inputs 3–4).
    pub recipient: UncheckedAccount<'info>,

    #[account(mut, token::mint = mint, token::authority = recipient)]
    pub recipient_token: Account<'info, TokenAccount>,

    /// CHECK: relayer wallet, bound to the proof (public inputs 5–6).
    pub relayer: UncheckedAccount<'info>,

    /// `dup`: a recipient withdrawing on their own is also the relayer, and
    /// the two token accounts are one. Token accounts belong to the token
    /// program, so Anchor writes neither back on exit.
    #[account(mut, dup, token::mint = mint, token::authority = relayer)]
    pub relayer_token: Account<'info, TokenAccount>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: [u8; FIELD_ELEMENT_BYTES],
    nf: [u8; FIELD_ELEMENT_BYTES],
    leaf_pay: [u8; FIELD_ELEMENT_BYTES],
    leaf_change: [u8; FIELD_ELEMENT_BYTES],
    leaf_fee: [u8; FIELD_ELEMENT_BYTES],
    memo_lens: [u32; 3],
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
        seeds = [NullifierRecord::SEED_PREFIX, &nf],
        bump,
    )]
    pub nullifier: Account<'info, NullifierRecord>,

    /// Envelope of the payment note — how its owner finds it.
    #[account(
        init,
        payer = payer,
        space = MemoAccount::space(memo_lens[0]),
        seeds = [MemoAccount::SEED_PREFIX, &leaf_pay],
        bump,
    )]
    pub memo_pay: Box<Account<'info, MemoAccount>>,

    /// Envelope of the change note, sealed back to the spender.
    #[account(
        init,
        payer = payer,
        space = MemoAccount::space(memo_lens[1]),
        seeds = [MemoAccount::SEED_PREFIX, &leaf_change],
        bump,
    )]
    pub memo_change: Box<Account<'info, MemoAccount>>,

    /// Envelope of the fee note, sealed to the treasury.
    #[account(
        init,
        payer = payer,
        space = MemoAccount::space(memo_lens[2]),
        seeds = [MemoAccount::SEED_PREFIX, &leaf_fee],
        bump,
    )]
    pub memo_fee: Box<Account<'info, MemoAccount>>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum PoolError {
    #[msg("Onchain Poseidon syscall failed (an input outside the field).")]
    PoseidonSyscallFailed,
    #[msg("Failed to construct the Groth16 verifier from the supplied proof.")]
    Groth16VerifierConstructFailed,
    #[msg("Groth16 proof verification failed.")]
    Groth16VerificationFailed,
    #[msg("Amount must be greater than zero and fit with its fee.")]
    InvalidAmount,
    #[msg("Pool is full.")]
    PoolFull,
    #[msg("The Merkle root is not in the pool's recent-root ring.")]
    MerkleRootNotRecent,
    #[msg("Relayer fee must not exceed the note amount.")]
    InvalidRelayerFee,
    #[msg("Memo total length is outside the accepted bounds.")]
    InvalidMemoTotalLen,
    #[msg("Memo chunk would write past the declared total length.")]
    MemoChunkOverflow,
    #[msg("Memo append offset does not match the written-length cursor.")]
    MemoOffsetMismatch,
    #[msg("Memo account is already finalized.")]
    MemoAlreadyFinalized,
    #[msg("The leaf the client named is not the leaf the program computed.")]
    LeafMismatch,
    #[msg("The nullifier does not match the note being refunded.")]
    NullifierMismatch,
    #[msg("Refund attempted before the note's refund time.")]
    RefundTooEarly,
    #[msg("This note has no refund.")]
    RefundDisabled,
    #[msg("Refund time is outside five minutes to thirty days from now.")]
    RefundWindowOutOfRange,
    #[msg("Only the program's upgrade authority may initialise a pool.")]
    NotUpgradeAuthority,
    #[msg("The owner key must be a non-zero field element.")]
    InvalidOwnerKey,
}
