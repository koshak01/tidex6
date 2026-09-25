//! Pool v2 state and instructions (ADR-022).
//!
//! The same model as the EVM `Tidex6HiddenPoolV2`, on Solana:
//!
//! - the program holds the tokens (an SPL vault owned by the pool PDA) and
//!   **files each leaf itself** from the amount it received:
//!   `leaf = H(H(core, amount), refund)` — a note cannot claim more than was
//!   paid into it;
//! - **only the owner spends**: the withdraw circuit proves the owner's
//!   spending key; the funder may take a note back through `refund` — no
//!   proof, only after `refund_after`, checked against the leaf rebuilt with
//!   the signer in the funder's place;
//! - **the fee cannot be skipped**: every deposit pays 1% (rounded up, at
//!   least `fee_floor`) as a note the program files for the treasury key set
//!   at `init_pool`; forwards inside the pool are 1 → 3 with the fee proved
//!   in the circuit.
//!
//! `H` is two-input Poseidon (`Bn254X5`), the same as the circuits and the
//! EVM pool; the nullifier is `H(H(D_NF, rho), position)` on both paths.

use anchor_lang::prelude::*;
use anchor_spl::token::{TransferChecked, transfer_checked};
use groth16_solana::groth16::Groth16Verifier;
use solana_poseidon::{Endianness, Parameters, hashv};

use crate::transfer_vk::{TRANSFER_V2_NR_PUBLIC_INPUTS, TRANSFER_V2_VERIFYING_KEY};
use crate::withdraw_vk::{WITHDRAW_V2_NR_PUBLIC_INPUTS, WITHDRAW_V2_VERIFYING_KEY};
use crate::{
    AppendMemo, Deposit, InitPool, PoolError, PublishOwnerKey, Refund, TransferNote, Withdraw,
};

pub const TREE_DEPTH: usize = 20;
pub const ROOT_RING_SIZE: usize = 30;
pub const FIELD_ELEMENT_BYTES: usize = 32;

/// Refund windows a depositor may choose; `refund_after = 0` — no refund.
pub const MIN_REFUND_WINDOW: i64 = 5 * 60;
pub const MAX_REFUND_WINDOW: i64 = 30 * 24 * 60 * 60;

/// The fee: 1% of the payment, rounded up, never below `fee_floor`.
pub const FEE_PERCENT_DIVISOR: u64 = 100;

/// Hash domains — the same constants as `tidex6-confidential::note_v2`.
pub const D_CORE: u64 = 0x7469_6478_3602;
pub const D_NF: u64 = 0x7469_6478_3603;

type Field = [u8; FIELD_ELEMENT_BYTES];

/// State of one pool (one per mint). PDA `[b"pool", mint]`, also the vault's
/// authority.
#[account(zero_copy)]
#[repr(C)]
pub struct PoolState {
    pub mint: Pubkey,
    pub next_leaf_index: u64,
    pub root_ring_head: u32,
    pub bump: u8,
    pub _padding: [u8; 3],
    pub filled_subtrees: [Field; TREE_DEPTH],
    pub zero_subtrees: [Field; TREE_DEPTH],
    pub root_history: [Field; ROOT_RING_SIZE],
    /// Owner key of the treasury: every fee note is filed for it.
    pub treasury_owner_pk: Field,
    /// Smallest fee in base units.
    pub fee_floor: u64,
}

impl PoolState {
    pub const POOL_SEED_PREFIX: &'static [u8] = b"pool";
    pub const VAULT_SEED_PREFIX: &'static [u8] = b"vault";

    pub fn capacity() -> u64 {
        1u64 << TREE_DEPTH
    }

    pub fn current_root(&self) -> Field {
        self.root_history[self.root_ring_head as usize]
    }

    /// The fee on a payment of `amount`: 1% rounded up, at least the floor.
    pub fn fee_for(&self, amount: u64) -> u64 {
        amount.div_ceil(FEE_PERCENT_DIVISOR).max(self.fee_floor)
    }
}

/// One per filed note — payments and fees alike.
#[event]
pub struct DepositEvent {
    pub mint: Pubkey,
    pub leaf: Field,
    pub leaf_index: u64,
    pub new_root: Field,
    pub depositor: Pubkey,
    pub amount: u64,
    /// When the funder may take the note back; 0 — never.
    pub refund_after: i64,
}

#[event]
pub struct TransferNoteEvent {
    pub nullifier: Field,
    pub leaf_pay: Field,
    pub leaf_change: Field,
    pub leaf_fee: Field,
    pub first_leaf_index: u64,
    pub new_root: Field,
}

#[event]
pub struct WithdrawEvent {
    pub amount: u64,
    pub nullifier: Field,
    pub merkle_root: Field,
    pub recipient: Pubkey,
    pub relayer: Pubkey,
    pub relayer_fee: u64,
}

#[event]
pub struct RefundEvent {
    pub nullifier: Field,
    pub funder: Pubkey,
    pub amount: u64,
}

/// Per-note account: the sealed envelope and what `refund` needs.
/// PDA `[b"memo", leaf]`. The memo accounts of a mint are its pool's leaf
/// list — `mint` comes first so a client selects them with one filter.
#[account]
pub struct MemoAccount {
    pub mint: Pubkey,
    pub leaf: Field,
    pub depositor: Pubkey,
    pub refund_after: i64,
    pub amount: u64,
    pub leaf_index: u64,
    pub total_len: u32,
    pub written_len: u32,
    pub bump: u8,
    pub is_finalized: bool,
    pub data: Vec<u8>,
}

impl MemoAccount {
    pub const SEED_PREFIX: &'static [u8] = b"memo";
    pub const MAX_TOTAL_LEN: usize = 8192;

    pub fn space(total_len: u32) -> usize {
        8 + 32 + FIELD_ELEMENT_BYTES + 32 + 8 + 8 + 8 + 4 + 4 + 1 + 1 + 4 + total_len as usize
    }
}

/// A wallet's owner key, PDA `[b"owner", wallet]` — what senders bind its
/// v2 notes to.
#[account]
pub struct OwnerKey {
    pub owner_pk: Field,
}

impl OwnerKey {
    pub const SEED_PREFIX: &'static [u8] = b"owner";
    pub const ACCOUNT_SIZE: usize = 8 + FIELD_ELEMENT_BYTES;
}

/// Per-nullifier PDA `[b"nullifier", nullifier]`; its existence is the
/// double-spend guard for withdraw, refund and forward alike.
#[account]
pub struct NullifierRecord {
    pub nullifier: Field,
}

impl NullifierRecord {
    pub const SEED_PREFIX: &'static [u8] = b"nullifier";
    pub const ACCOUNT_SIZE: usize = 8 + FIELD_ELEMENT_BYTES;
}

// ── publish_owner_key ────────────────────────────────────────────────────

/// Only the signer's own entry is written; a replaced key does not strand
/// old notes, their spending key is unchanged.
pub fn handle_publish_owner_key(ctx: Context<PublishOwnerKey>, owner_pk: Field) -> Result<()> {
    require!(
        owner_pk != [0u8; FIELD_ELEMENT_BYTES],
        PoolError::InvalidOwnerKey
    );
    // A value outside the field fails the syscall: hash it once to find out.
    h(&owner_pk, &[0u8; FIELD_ELEMENT_BYTES]).map_err(|_| PoolError::InvalidOwnerKey)?;
    ctx.accounts.owner_key.owner_pk = owner_pk;
    Ok(())
}

// ── init_pool ────────────────────────────────────────────────────────────

/// Create the pool for `mint` with the treasury key and fee floor. Only the
/// program's upgrade authority may do it: whoever initialises the pool names
/// the treasury, and a pool initialised by a stranger would pay its fees to
/// the stranger.
pub fn handle_init_pool(
    ctx: Context<InitPool>,
    treasury_owner_pk: Field,
    fee_floor: u64,
) -> Result<()> {
    let bump = ctx.bumps.pool;
    let mint_key = ctx.accounts.mint.key();
    let mut pool = ctx.accounts.pool.load_init()?;
    pool.mint = mint_key;
    pool.bump = bump;
    pool._padding = [0u8; 3];
    pool.next_leaf_index = 0;
    pool.root_ring_head = 0;
    pool.treasury_owner_pk = treasury_owner_pk;
    pool.fee_floor = fee_floor;
    pool.filled_subtrees = [[0u8; FIELD_ELEMENT_BYTES]; TREE_DEPTH];
    pool.zero_subtrees = [[0u8; FIELD_ELEMENT_BYTES]; TREE_DEPTH];
    pool.root_history = [[0u8; FIELD_ELEMENT_BYTES]; ROOT_RING_SIZE];

    let mut zero_hash = [0u8; FIELD_ELEMENT_BYTES];
    for level in 0..TREE_DEPTH {
        pool.zero_subtrees[level] = zero_hash;
        pool.filled_subtrees[level] = zero_hash;
        zero_hash = h(&zero_hash, &zero_hash)?;
    }
    pool.root_history[0] = zero_hash;
    msg!("tidex6-pool-v2:initialized:{}", mint_key);
    Ok(())
}

// ── deposit ──────────────────────────────────────────────────────────────

/// What a depositor names; the program computes and checks the rest.
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct DepositArgs {
    /// `H(H(D_CORE, owner_pk), H(rho, aux))` of the payment.
    pub core: Field,
    pub amount: u64,
    /// Absolute unix time the funder may refund from; 0 — no refund.
    pub refund_after: i64,
    /// The payment leaf the client expects — it seeds the memo PDA. The
    /// program rebuilds it and refuses a mismatch.
    pub leaf: Field,
    /// Randomness of the fee note; its core comes from the treasury key.
    pub fee_rho: Field,
    /// The fee leaf the client expects — seeds the fee memo PDA.
    pub fee_leaf: Field,
    pub memo_total_len: u32,
    pub fee_memo_total_len: u32,
    pub memo_chunk: Vec<u8>,
}

/// Pay `amount` to the owner of `core`, and the fee to the treasury. The
/// payer is charged `amount + fee_for(amount)`.
pub fn handle_deposit(ctx: Context<Deposit>, args: DepositArgs) -> Result<()> {
    require!(args.amount > 0, PoolError::InvalidAmount);
    for total in [args.memo_total_len, args.fee_memo_total_len] {
        require!(
            (total as usize) <= MemoAccount::MAX_TOTAL_LEN,
            PoolError::InvalidMemoTotalLen
        );
    }
    require!(
        args.memo_chunk.len() <= args.memo_total_len as usize,
        PoolError::MemoChunkOverflow
    );
    let now = Clock::get()?.unix_timestamp;
    if args.refund_after != 0 {
        require!(
            args.refund_after >= now + MIN_REFUND_WINDOW
                && args.refund_after <= now + MAX_REFUND_WINDOW,
            PoolError::RefundWindowOutOfRange
        );
    }
    let payer = ctx.accounts.payer.key();

    let (fee, treasury_pk, first_leaf) = {
        let pool = ctx.accounts.pool.load()?;
        require!(
            pool.next_leaf_index + 2 <= PoolState::capacity(),
            PoolError::PoolFull
        );
        (
            pool.fee_for(args.amount),
            pool.treasury_owner_pk,
            pool.next_leaf_index,
        )
    };

    // Leaves, from what the program actually charges.
    let leaf = leaf_of(
        &args.core,
        args.amount,
        &refund_tag(&payer, args.refund_after)?,
    )?;
    require!(leaf == args.leaf, PoolError::LeafMismatch);
    let fee_core = core_of(&treasury_pk, &args.fee_rho, &[0u8; FIELD_ELEMENT_BYTES])?;
    let fee_leaf = leaf_of(&fee_core, fee, &[0u8; FIELD_ELEMENT_BYTES])?;
    require!(fee_leaf == args.fee_leaf, PoolError::LeafMismatch);

    let total = args
        .amount
        .checked_add(fee)
        .ok_or(PoolError::InvalidAmount)?;
    transfer_checked(
        CpiContext::new(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.depositor_token.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
                authority: ctx.accounts.payer.to_account_info(),
            },
        ),
        total,
        ctx.accounts.mint.decimals,
    )?;

    let (root1, root2, mint_key) = {
        let mut pool = ctx.accounts.pool.load_mut()?;
        let root1 = append_leaf(&mut pool, first_leaf, leaf)?;
        let root2 = append_leaf(&mut pool, first_leaf + 1, fee_leaf)?;
        (root1, root2, pool.mint)
    };

    let chunk_len = args.memo_chunk.len();
    {
        let memo = &mut ctx.accounts.memo;
        memo.mint = mint_key;
        memo.leaf = leaf;
        memo.depositor = payer;
        memo.refund_after = args.refund_after;
        memo.amount = args.amount;
        memo.leaf_index = first_leaf;
        memo.total_len = args.memo_total_len;
        memo.written_len = chunk_len as u32;
        memo.bump = ctx.bumps.memo;
        memo.is_finalized = chunk_len as u32 == args.memo_total_len;
        memo.data = vec![0u8; args.memo_total_len as usize];
        memo.data[..chunk_len].copy_from_slice(&args.memo_chunk);
    }
    {
        let memo = &mut ctx.accounts.fee_memo;
        memo.mint = mint_key;
        memo.leaf = fee_leaf;
        memo.depositor = payer;
        memo.refund_after = 0;
        memo.amount = fee;
        memo.leaf_index = first_leaf + 1;
        memo.total_len = args.fee_memo_total_len;
        memo.written_len = 0;
        memo.bump = ctx.bumps.fee_memo;
        memo.is_finalized = args.fee_memo_total_len == 0;
        memo.data = vec![0u8; args.fee_memo_total_len as usize];
    }

    emit!(DepositEvent {
        mint: mint_key,
        leaf,
        leaf_index: first_leaf,
        new_root: root1,
        depositor: payer,
        amount: args.amount,
        refund_after: args.refund_after,
    });
    emit!(DepositEvent {
        mint: mint_key,
        leaf: fee_leaf,
        leaf_index: first_leaf + 1,
        new_root: root2,
        depositor: payer,
        amount: fee,
        refund_after: 0,
    });
    Ok(())
}

// ── append_memo ──────────────────────────────────────────────────────────

pub fn handle_append_memo(ctx: Context<AppendMemo>, offset: u32, chunk: Vec<u8>) -> Result<()> {
    let memo = &mut ctx.accounts.memo;
    require!(!memo.is_finalized, PoolError::MemoAlreadyFinalized);
    require!(offset == memo.written_len, PoolError::MemoOffsetMismatch);
    let end = (offset as usize)
        .checked_add(chunk.len())
        .ok_or(PoolError::MemoChunkOverflow)?;
    require!(end <= memo.total_len as usize, PoolError::MemoChunkOverflow);
    memo.data[offset as usize..end].copy_from_slice(&chunk);
    memo.written_len = end as u32;
    if memo.written_len == memo.total_len {
        memo.is_finalized = true;
    }
    Ok(())
}

// ── refund ───────────────────────────────────────────────────────────────

/// Take a note back after its window, if its owner has not spent it. The
/// funder presents the note's parts; the program rebuilds the leaf with the
/// signer as funder and the recorded amount and window, and derives the
/// nullifier the owner would have published.
pub fn handle_refund(
    ctx: Context<Refund>,
    owner_pk: Field,
    rho: Field,
    aux: Field,
    nullifier: Field,
) -> Result<()> {
    let memo = &ctx.accounts.memo;
    require!(memo.refund_after != 0, PoolError::RefundDisabled);
    let now = Clock::get()?.unix_timestamp;
    require!(now >= memo.refund_after, PoolError::RefundTooEarly);

    let depositor = ctx.accounts.depositor.key();
    let core = core_of(&owner_pk, &rho, &aux)?;
    let leaf = leaf_of(
        &core,
        memo.amount,
        &refund_tag(&depositor, memo.refund_after)?,
    )?;
    require!(leaf == memo.leaf, PoolError::LeafMismatch);
    let expected = h(&h(&fr_u64(D_NF), &rho)?, &fr_u64(memo.leaf_index))?;
    require!(expected == nullifier, PoolError::NullifierMismatch);
    ctx.accounts.nullifier.nullifier = nullifier;

    let amount = memo.amount;
    pay_from_vault(
        &ctx.accounts.pool,
        &ctx.accounts.mint,
        &ctx.accounts.vault,
        ctx.accounts.depositor_token.to_account_info(),
        &ctx.accounts.token_program,
        amount,
    )?;
    emit!(RefundEvent {
        nullifier,
        funder: depositor,
        amount
    });
    Ok(())
}

// ── withdraw ─────────────────────────────────────────────────────────────

/// Withdraw a note; only the owner can build the proof. Public inputs:
/// `[root, nullifier, recipient_hi, recipient_lo, relayer_hi, relayer_lo,
/// relayer_fee, amount]`.
#[allow(clippy::too_many_arguments)]
pub fn handle_withdraw(
    ctx: Context<Withdraw>,
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: Field,
    nullifier: Field,
    amount: u64,
    relayer_fee: u64,
) -> Result<()> {
    {
        let pool = ctx.accounts.pool.load()?;
        require!(
            pool.root_history.iter().any(|r| r == &merkle_root),
            PoolError::MerkleRootNotRecent
        );
    }
    require!(relayer_fee <= amount, PoolError::InvalidRelayerFee);
    ctx.accounts.nullifier.nullifier = nullifier;

    let (recipient_hi, recipient_lo) = split_pubkey(&ctx.accounts.recipient.key().to_bytes());
    let (relayer_hi, relayer_lo) = split_pubkey(&ctx.accounts.relayer.key().to_bytes());
    let public_inputs: [Field; WITHDRAW_V2_NR_PUBLIC_INPUTS] = [
        merkle_root,
        nullifier,
        recipient_hi,
        recipient_lo,
        relayer_hi,
        relayer_lo,
        fr_u64(relayer_fee),
        fr_u64(amount),
    ];
    let mut verifier = Groth16Verifier::<{ WITHDRAW_V2_NR_PUBLIC_INPUTS }>::new(
        &proof_a,
        &proof_b,
        &proof_c,
        &public_inputs,
        &WITHDRAW_V2_VERIFYING_KEY,
    )
    .map_err(|_| PoolError::Groth16VerifierConstructFailed)?;
    verifier
        .verify()
        .map_err(|_| PoolError::Groth16VerificationFailed)?;

    let to_recipient = amount - relayer_fee;
    if to_recipient > 0 {
        pay_from_vault(
            &ctx.accounts.pool,
            &ctx.accounts.mint,
            &ctx.accounts.vault,
            ctx.accounts.recipient_token.to_account_info(),
            &ctx.accounts.token_program,
            to_recipient,
        )?;
    }
    if relayer_fee > 0 {
        pay_from_vault(
            &ctx.accounts.pool,
            &ctx.accounts.mint,
            &ctx.accounts.vault,
            ctx.accounts.relayer_token.to_account_info(),
            &ctx.accounts.token_program,
            relayer_fee,
        )?;
    }
    emit!(WithdrawEvent {
        amount,
        nullifier,
        merkle_root,
        recipient: ctx.accounts.recipient.key(),
        relayer: ctx.accounts.relayer.key(),
        relayer_fee,
    });
    Ok(())
}

// ── transfer_note ────────────────────────────────────────────────────────

/// Forward a note inside the pool: payment, change to the spender, fee to
/// the treasury. The program supplies its own treasury key and floor as
/// public inputs. No token moves.
#[allow(clippy::too_many_arguments)]
pub fn handle_transfer_note(
    ctx: Context<TransferNote>,
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: Field,
    nullifier: Field,
    leaves: [Field; 3],
    memo_lens: [u32; 3],
) -> Result<()> {
    for total in memo_lens {
        require!(
            (total as usize) <= MemoAccount::MAX_TOTAL_LEN,
            PoolError::InvalidMemoTotalLen
        );
    }
    let [leaf_pay, leaf_change, leaf_fee] = leaves;
    let (treasury_pk, fee_floor, first_leaf) = {
        let pool = ctx.accounts.pool.load()?;
        require!(
            pool.root_history.iter().any(|r| r == &merkle_root),
            PoolError::MerkleRootNotRecent
        );
        require!(
            pool.next_leaf_index + 3 <= PoolState::capacity(),
            PoolError::PoolFull
        );
        (pool.treasury_owner_pk, pool.fee_floor, pool.next_leaf_index)
    };
    ctx.accounts.nullifier.nullifier = nullifier;

    let public_inputs: [Field; TRANSFER_V2_NR_PUBLIC_INPUTS] = [
        merkle_root,
        nullifier,
        leaf_pay,
        leaf_change,
        leaf_fee,
        treasury_pk,
        fr_u64(fee_floor),
    ];
    let mut verifier = Groth16Verifier::<{ TRANSFER_V2_NR_PUBLIC_INPUTS }>::new(
        &proof_a,
        &proof_b,
        &proof_c,
        &public_inputs,
        &TRANSFER_V2_VERIFYING_KEY,
    )
    .map_err(|_| PoolError::Groth16VerifierConstructFailed)?;
    verifier
        .verify()
        .map_err(|_| PoolError::Groth16VerificationFailed)?;

    let mut pool = ctx.accounts.pool.load_mut()?;
    let mint_key = pool.mint;
    append_leaf(&mut pool, first_leaf, leaf_pay)?;
    append_leaf(&mut pool, first_leaf + 1, leaf_change)?;
    let new_root = append_leaf(&mut pool, first_leaf + 2, leaf_fee)?;
    drop(pool);

    // The outputs' envelopes: no amount and no refund recorded — both stay
    // inside the notes.
    let payer = ctx.accounts.payer.key();
    let bumps = [
        ctx.bumps.memo_pay,
        ctx.bumps.memo_change,
        ctx.bumps.memo_fee,
    ];
    for (i, memo) in [
        &mut ctx.accounts.memo_pay,
        &mut ctx.accounts.memo_change,
        &mut ctx.accounts.memo_fee,
    ]
    .into_iter()
    .enumerate()
    {
        memo.mint = mint_key;
        memo.leaf = leaves[i];
        memo.depositor = payer;
        memo.refund_after = 0;
        memo.amount = 0;
        memo.leaf_index = first_leaf + i as u64;
        memo.total_len = memo_lens[i];
        memo.written_len = 0;
        memo.bump = bumps[i];
        memo.is_finalized = memo_lens[i] == 0;
        memo.data = vec![0u8; memo_lens[i] as usize];
    }
    emit!(TransferNoteEvent {
        nullifier,
        leaf_pay,
        leaf_change,
        leaf_fee,
        first_leaf_index: first_leaf,
        new_root,
    });
    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────

/// Two-input Poseidon; an input outside the field fails here.
fn h(left: &Field, right: &Field) -> Result<Field> {
    Ok(
        hashv(Parameters::Bn254X5, Endianness::BigEndian, &[left, right])
            .map_err(|_| PoolError::PoseidonSyscallFailed)?
            .to_bytes(),
    )
}

fn core_of(owner_pk: &Field, rho: &Field, aux: &Field) -> Result<Field> {
    h(&h(&fr_u64(D_CORE), owner_pk)?, &h(rho, aux)?)
}

fn leaf_of(core: &Field, amount: u64, refund: &Field) -> Result<Field> {
    h(&h(core, &fr_u64(amount))?, refund)
}

/// `H(H(hi, lo), refund_after)` of the funder, or 0 for "no refund".
fn refund_tag(funder: &Pubkey, refund_after: i64) -> Result<Field> {
    if refund_after == 0 {
        return Ok([0u8; FIELD_ELEMENT_BYTES]);
    }
    let (hi, lo) = split_pubkey(&funder.to_bytes());
    h(&h(&hi, &lo)?, &fr_u64(refund_after as u64))
}

/// Pay `amount` from the vault, signed by the pool PDA.
fn pay_from_vault<'info>(
    pool: &AccountLoader<'info, PoolState>,
    mint: &Account<'info, anchor_spl::token::Mint>,
    vault: &Account<'info, anchor_spl::token::TokenAccount>,
    to: AccountInfo<'info>,
    token_program: &Program<'info, anchor_spl::token::Token>,
    amount: u64,
) -> Result<()> {
    let bump = pool.load()?.bump;
    let mint_key = mint.key();
    let seeds: &[&[u8]] = &[
        PoolState::POOL_SEED_PREFIX,
        mint_key.as_ref(),
        std::slice::from_ref(&bump),
    ];
    transfer_checked(
        CpiContext::new_with_signer(
            token_program.key(),
            TransferChecked {
                from: vault.to_account_info(),
                mint: mint.to_account_info(),
                to,
                authority: pool.to_account_info(),
            },
            &[seeds],
        ),
        amount,
        mint.decimals,
    )
}

fn append_leaf(pool: &mut PoolState, leaf_index: u64, leaf: Field) -> Result<Field> {
    let mut current_index = leaf_index;
    let mut current_hash = leaf;
    for level in 0..TREE_DEPTH {
        let (left, right) = if current_index & 1 == 0 {
            pool.filled_subtrees[level] = current_hash;
            (current_hash, pool.zero_subtrees[level])
        } else {
            (pool.filled_subtrees[level], current_hash)
        };
        current_hash = h(&left, &right)?;
        current_index >>= 1;
    }
    pool.next_leaf_index = pool
        .next_leaf_index
        .checked_add(1)
        .ok_or(PoolError::PoolFull)?;
    pool.root_ring_head = (pool.root_ring_head + 1) % ROOT_RING_SIZE as u32;
    let ring_index = pool.root_ring_head as usize;
    pool.root_history[ring_index] = current_hash;
    Ok(current_hash)
}

/// A `u64` as a 32-byte big-endian field element.
fn fr_u64(value: u64) -> Field {
    let mut out = [0u8; FIELD_ELEMENT_BYTES];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// A 32-byte key as two 16-byte field elements `(hi, lo)` — the circuit's
/// recipient layout (`tidex6_confidential::bytes::split_pubkey`).
fn split_pubkey(pubkey: &[u8; 32]) -> (Field, Field) {
    let mut hi = [0u8; FIELD_ELEMENT_BYTES];
    hi[16..].copy_from_slice(&pubkey[0..16]);
    let mut lo = [0u8; FIELD_ELEMENT_BYTES];
    lo[16..].copy_from_slice(&pubkey[16..32]);
    (hi, lo)
}
