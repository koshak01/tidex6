//! Confidential-pool state and instructions (ADR-015, Stage 2).
//!
//! Forked from `tidex6-verifier-v2` and upgraded to hidden arbitrary
//! amounts over an SPL/USDC token-vault:
//!
//! - value is a USDC token-vault (`anchor_spl::token::transfer_checked`),
//!   not native SOL — one pool per mint (`[b"pool", mint]`);
//! - the amount lives **inside the commitment**
//!   `Poseidon(secret, nullifier, amount)`, proved with a range check, so
//!   there are no fixed denominations;
//! - `withdraw` verifies the 8-public-input `WithdrawCircuit` with
//!   **exact recipient/relayer binding** (full 256-bit key as two 128-bit
//!   limbs — fixes GAP2) and `relayer_fee` (ADR-011);
//! - a new `transfer_note` verifies the 4-public-input JoinSplit
//!   `TransferCircuit`: it spends one note and mints two, conserving value
//!   with every amount hidden — a fully confidential internal transfer that
//!   moves no tokens (value stays in the vault, only note claims move).
//!
//! The Merkle mechanics (incremental tree, root ring buffer) and the
//! per-nullifier double-spend PDA are reused unchanged.

use anchor_lang::prelude::*;
use anchor_spl::token::{TransferChecked, transfer_checked};
use groth16_solana::groth16::Groth16Verifier;
use solana_poseidon::{Endianness, Parameters, hashv};

use crate::transfer_vk::{TRANSFER_NR_PUBLIC_INPUTS, TRANSFER_VERIFYING_KEY};
use crate::withdraw_vk::{WITHDRAW_NR_PUBLIC_INPUTS, WITHDRAW_VERIFYING_KEY};
use crate::{AppendMemo, Deposit, InitPool, Refund, Tidex6VerifierError, TransferNote, Withdraw};

/// Tree depth. 2^20 ≈ 1 048 576 leaves. Matches
/// `tidex6_confidential::withdraw::POOL_TREE_DEPTH`.
pub const TREE_DEPTH: usize = 20;

/// Number of recent Merkle roots kept in the ring buffer.
pub const ROOT_RING_SIZE: usize = 30;

/// Length in bytes of a BN254 scalar field element.
pub const FIELD_ELEMENT_BYTES: usize = 32;

/// Onchain state of a single confidential pool (one per mint).
///
/// PDA seeds `[b"pool", mint]`. Holds the Merkle frontier
/// (`filled_subtrees` / `zero_subtrees`), a ring buffer of recent roots,
/// and the mint this pool accepts. The pool PDA is also the authority of
/// the token vault.
#[account(zero_copy)]
#[repr(C)]
pub struct PoolState {
    pub mint: Pubkey,
    pub next_leaf_index: u64,
    pub root_ring_head: u32,
    pub bump: u8,
    pub _padding: [u8; 3],
    pub filled_subtrees: [[u8; FIELD_ELEMENT_BYTES]; TREE_DEPTH],
    pub zero_subtrees: [[u8; FIELD_ELEMENT_BYTES]; TREE_DEPTH],
    pub root_history: [[u8; FIELD_ELEMENT_BYTES]; ROOT_RING_SIZE],
}

impl PoolState {
    pub const POOL_SEED_PREFIX: &'static [u8] = b"pool";
    pub const VAULT_SEED_PREFIX: &'static [u8] = b"vault";

    pub fn capacity() -> u64 {
        1u64 << TREE_DEPTH
    }

    pub fn current_root(&self) -> [u8; FIELD_ELEMENT_BYTES] {
        self.root_history[self.root_ring_head as usize]
    }
}

/// Emitted by every successful `deposit` for offchain Merkle replay.
#[event]
pub struct DepositEvent {
    pub mint: Pubkey,
    pub commitment: [u8; FIELD_ELEMENT_BYTES],
    pub leaf_index: u64,
    pub new_root: [u8; FIELD_ELEMENT_BYTES],
    pub depositor: Pubkey,
}

/// Emitted by every successful `transfer_note` (JoinSplit).
#[event]
pub struct TransferNoteEvent {
    pub nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    pub commitment_out1: [u8; FIELD_ELEMENT_BYTES],
    pub commitment_out2: [u8; FIELD_ELEMENT_BYTES],
    pub leaf_index1: u64,
    pub leaf_index2: u64,
    pub new_root: [u8; FIELD_ELEMENT_BYTES],
}

/// Dedicated per-deposit account holding the ML-KEM envelope (ADR-014).
///
/// Stores the amount alongside the envelope so `refund` can return the
/// exact value without a proof (ownership is checked against the
/// commitment). `data` is allocated to `total_len` at deposit and written
/// in chunks; `depositor`/`created_ts`/`revoke_window` back the revoke.
#[account]
pub struct MemoAccount {
    pub commitment: [u8; FIELD_ELEMENT_BYTES],
    pub depositor: Pubkey,
    pub created_ts: i64,
    pub revoke_window: i64,
    pub amount: u64,
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
        8                            // Anchor discriminator
            + FIELD_ELEMENT_BYTES    // commitment
            + 32                     // depositor pubkey
            + 8                      // created_ts (i64)
            + 8                      // revoke_window (i64)
            + 8                      // amount (u64)
            + 4                      // total_len (u32)
            + 4                      // written_len (u32)
            + 1                      // bump
            + 1                      // is_finalized
            + 4 + total_len as usize // data Vec<u8> (len prefix + bytes)
    }
}

/// Per-nullifier PDA. Seeds `[b"nullifier", nullifier_hash]`. Its very
/// existence is the double-spend prevention mechanism.
#[account]
pub struct NullifierRecord {
    pub nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
}

impl NullifierRecord {
    pub const SEED_PREFIX: &'static [u8] = b"nullifier";
    pub const ACCOUNT_SIZE: usize = 8 + FIELD_ELEMENT_BYTES;
}

/// Emitted by every successful `withdraw`.
#[event]
pub struct WithdrawEvent {
    pub amount: u64,
    pub nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    pub merkle_root: [u8; FIELD_ELEMENT_BYTES],
    pub recipient: Pubkey,
    pub relayer: Pubkey,
    pub relayer_fee: u64,
}

// ──────────────────────────────────────────────────────────────────────
// init_pool
// ──────────────────────────────────────────────────────────────────────

/// Initialise a confidential pool for `mint`. Precomputes the
/// zero-subtree hashes and the empty-tree root. One pool per mint.
pub fn handle_init_pool(ctx: Context<InitPool>) -> Result<()> {
    let bump = ctx.bumps.pool;
    let mint_key = ctx.accounts.mint.key();
    let mut pool = ctx.accounts.pool.load_init()?;

    pool.mint = mint_key;
    pool.bump = bump;
    pool._padding = [0u8; 3];
    pool.next_leaf_index = 0;
    pool.root_ring_head = 0;
    pool.filled_subtrees = [[0u8; FIELD_ELEMENT_BYTES]; TREE_DEPTH];
    pool.zero_subtrees = [[0u8; FIELD_ELEMENT_BYTES]; TREE_DEPTH];
    pool.root_history = [[0u8; FIELD_ELEMENT_BYTES]; ROOT_RING_SIZE];

    let mut zero_hash = [0u8; FIELD_ELEMENT_BYTES];
    for level in 0..TREE_DEPTH {
        pool.zero_subtrees[level] = zero_hash;
        pool.filled_subtrees[level] = zero_hash;
        let next_hash = hashv(
            Parameters::Bn254X5,
            Endianness::BigEndian,
            &[&zero_hash, &zero_hash],
        )
        .map_err(|_| Tidex6VerifierError::PoseidonSyscallFailed)?;
        zero_hash = next_hash.to_bytes();
    }
    pool.root_history[0] = zero_hash;

    msg!("tidex6-cpool:initialized:{}", mint_key);
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// deposit
// ──────────────────────────────────────────────────────────────────────

/// Deposit a hidden-amount note. Transfers `amount` USDC from the
/// depositor's token account into the vault, appends
/// `commitment = Poseidon(secret, nullifier, amount)` to the tree, and
/// opens the dedicated ML-KEM memo account (ADR-014).
///
/// The amount is visible at this boundary (a plain SPL transfer), but the
/// note hides it inside the commitment; later `transfer_note` JoinSplits
/// break the amount linkage so the eventual withdraw need not match.
pub fn handle_deposit(
    ctx: Context<Deposit>,
    commitment: [u8; FIELD_ELEMENT_BYTES],
    amount: u64,
    memo_total_len: u32,
    revoke_window: i64,
    memo_chunk: Vec<u8>,
) -> Result<()> {
    require!(amount > 0, Tidex6VerifierError::InvalidAmount);
    require!(
        (memo_total_len as usize) <= MemoAccount::MAX_TOTAL_LEN,
        Tidex6VerifierError::InvalidMemoTotalLen
    );
    require!(
        memo_chunk.len() <= memo_total_len as usize,
        Tidex6VerifierError::MemoChunkOverflow
    );

    let next_leaf_index = {
        let pool = ctx.accounts.pool.load()?;
        require!(
            pool.next_leaf_index < PoolState::capacity(),
            Tidex6VerifierError::PoolFull
        );
        pool.next_leaf_index
    };

    // Transfer `amount` USDC from the depositor into the vault.
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
        amount,
        ctx.accounts.mint.decimals,
    )?;

    // Merkle append.
    let mut pool = ctx.accounts.pool.load_mut()?;
    let leaf_index = next_leaf_index;
    let new_root = append_leaf(&mut pool, leaf_index, commitment)?;
    let mint_key = pool.mint;
    drop(pool);

    // Memo account (ADR-014).
    let now = Clock::get()?.unix_timestamp;
    let chunk_len = memo_chunk.len();
    {
        let memo = &mut ctx.accounts.memo;
        memo.commitment = commitment;
        memo.depositor = ctx.accounts.payer.key();
        memo.created_ts = now;
        memo.revoke_window = revoke_window;
        memo.amount = amount;
        memo.total_len = memo_total_len;
        memo.written_len = chunk_len as u32;
        memo.bump = ctx.bumps.memo;
        memo.is_finalized = chunk_len as u32 == memo_total_len;
        memo.data = vec![0u8; memo_total_len as usize];
        memo.data[..chunk_len].copy_from_slice(&memo_chunk);
    }

    msg!(
        "tidex6-cpool-deposit:{}:{}:{}",
        leaf_index,
        crate::encode_hex(commitment),
        crate::encode_hex(new_root),
    );
    emit!(DepositEvent {
        mint: mint_key,
        commitment,
        leaf_index,
        new_root,
        depositor: ctx.accounts.payer.key(),
    });
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// append_memo
// ──────────────────────────────────────────────────────────────────────

pub fn handle_append_memo(ctx: Context<AppendMemo>, offset: u32, chunk: Vec<u8>) -> Result<()> {
    let memo = &mut ctx.accounts.memo;
    require!(
        !memo.is_finalized,
        Tidex6VerifierError::MemoAlreadyFinalized
    );
    require!(
        offset == memo.written_len,
        Tidex6VerifierError::MemoOffsetMismatch
    );
    let end = (offset as usize)
        .checked_add(chunk.len())
        .ok_or(Tidex6VerifierError::MemoChunkOverflow)?;
    require!(
        end <= memo.total_len as usize,
        Tidex6VerifierError::MemoChunkOverflow
    );
    memo.data[offset as usize..end].copy_from_slice(&chunk);
    memo.written_len = end as u32;
    if memo.written_len == memo.total_len {
        memo.is_finalized = true;
    }
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// refund (revoke)
// ──────────────────────────────────────────────────────────────────────

/// Reclaim a never-withdrawn deposit. The depositor presents
/// `(secret, nullifier, amount)` proving `Poseidon(secret, nullifier,
/// amount) == commitment`. If the revoke window elapsed and the note was
/// never withdrawn, `amount` USDC is returned from the vault and the note
/// is permanently spent.
pub fn handle_refund(
    ctx: Context<Refund>,
    commitment: [u8; FIELD_ELEMENT_BYTES],
    secret: [u8; FIELD_ELEMENT_BYTES],
    nullifier: [u8; FIELD_ELEMENT_BYTES],
    nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    amount: u64,
) -> Result<()> {
    // 1. Ownership: Poseidon(secret, nullifier, amount) == commitment.
    let amount_fr = fr_bytes_from_u64(amount);
    let computed_commitment = hashv(
        Parameters::Bn254X5,
        Endianness::BigEndian,
        &[&secret, &nullifier, &amount_fr],
    )
    .map_err(|_| Tidex6VerifierError::PoseidonSyscallFailed)?
    .to_bytes();
    require!(
        computed_commitment == commitment,
        Tidex6VerifierError::RefundCommitmentMismatch
    );

    // 2. nullifier_hash == Poseidon(nullifier).
    let computed_nh = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&nullifier])
        .map_err(|_| Tidex6VerifierError::PoseidonSyscallFailed)?
        .to_bytes();
    require!(
        computed_nh == nullifier_hash,
        Tidex6VerifierError::RefundNullifierMismatch
    );

    // 3. Amount must match what was deposited.
    require!(
        ctx.accounts.memo.amount == amount,
        Tidex6VerifierError::RefundCommitmentMismatch
    );

    // 4. Revoke window must have elapsed (0 = irrevocable).
    let revoke_window = ctx.accounts.memo.revoke_window;
    require!(revoke_window > 0, Tidex6VerifierError::RefundDisabled);
    let now = Clock::get()?.unix_timestamp;
    require!(
        now - ctx.accounts.memo.created_ts >= revoke_window,
        Tidex6VerifierError::RefundTooEarly
    );

    // 5. Mark the note permanently spent (nullifier PDA created via init).
    ctx.accounts.nullifier.nullifier_hash = nullifier_hash;

    // 6. Return `amount` USDC from the vault via the pool-PDA signer.
    let pool_bump = ctx.accounts.pool.load()?.bump;
    let mint_key = ctx.accounts.mint.key();
    let pool_seeds: &[&[u8]] = &[
        PoolState::POOL_SEED_PREFIX,
        mint_key.as_ref(),
        std::slice::from_ref(&pool_bump),
    ];
    let signer = &[pool_seeds];
    transfer_checked(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.key(),
            TransferChecked {
                from: ctx.accounts.vault.to_account_info(),
                mint: ctx.accounts.mint.to_account_info(),
                to: ctx.accounts.depositor_token.to_account_info(),
                authority: ctx.accounts.pool.to_account_info(),
            },
            signer,
        ),
        amount,
        ctx.accounts.mint.decimals,
    )?;

    msg!(
        "tidex6-cpool-refund:{}:{}",
        amount,
        crate::encode_hex(nullifier_hash)
    );
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// withdraw
// ──────────────────────────────────────────────────────────────────────

/// Withdraw a hidden-amount note. Verifies the 8-public-input
/// `WithdrawCircuit` proof against `WITHDRAW_VERIFYING_KEY`, then pays
/// `(amount - relayer_fee)` USDC to the recipient and `relayer_fee` to the
/// relayer from the vault. Public-input order (load-bearing):
/// `[merkle_root, nullifier_hash, recipient_hi, recipient_lo,
///   relayer_hi, relayer_lo, relayer_fee, amount]`.
#[allow(clippy::too_many_arguments)]
pub fn handle_withdraw(
    ctx: Context<Withdraw>,
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: [u8; FIELD_ELEMENT_BYTES],
    nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    amount: u64,
    relayer_fee: u64,
) -> Result<()> {
    // 1. Root recency.
    let (root_accepted, pool_bump) = {
        let pool = ctx.accounts.pool.load()?;
        let accepted = pool.root_history.iter().any(|entry| entry == &merkle_root);
        (accepted, pool.bump)
    };
    require!(root_accepted, Tidex6VerifierError::MerkleRootNotRecent);

    // 2. Fee bound.
    require!(
        relayer_fee <= amount,
        Tidex6VerifierError::InvalidRelayerFee
    );

    // 3. Record nullifier (PDA already init'd → double-spend fails earlier).
    ctx.accounts.nullifier.nullifier_hash = nullifier_hash;

    // 4. Exact binding: full 256-bit recipient/relayer keys as two limbs.
    let (recipient_hi, recipient_lo) = split_pubkey(&ctx.accounts.recipient.key().to_bytes());
    let (relayer_hi, relayer_lo) = split_pubkey(&ctx.accounts.relayer.key().to_bytes());
    let relayer_fee_fr = fr_bytes_from_u64(relayer_fee);
    let amount_fr = fr_bytes_from_u64(amount);

    // 5. Groth16 verify (8 public inputs).
    let public_inputs: [[u8; 32]; WITHDRAW_NR_PUBLIC_INPUTS] = [
        merkle_root,
        nullifier_hash,
        recipient_hi,
        recipient_lo,
        relayer_hi,
        relayer_lo,
        relayer_fee_fr,
        amount_fr,
    ];
    let mut verifier = Groth16Verifier::<{ WITHDRAW_NR_PUBLIC_INPUTS }>::new(
        &proof_a,
        &proof_b,
        &proof_c,
        &public_inputs,
        &WITHDRAW_VERIFYING_KEY,
    )
    .map_err(|_| Tidex6VerifierError::Groth16VerifierConstructFailed)?;
    verifier
        .verify()
        .map_err(|_| Tidex6VerifierError::Groth16VerificationFailed)?;

    // 6. Pay out from the vault via the pool-PDA signer.
    let mint_key = ctx.accounts.mint.key();
    let pool_seeds: &[&[u8]] = &[
        PoolState::POOL_SEED_PREFIX,
        mint_key.as_ref(),
        std::slice::from_ref(&pool_bump),
    ];
    let signer = &[pool_seeds];
    let recipient_amount = amount
        .checked_sub(relayer_fee)
        .ok_or(Tidex6VerifierError::InvalidRelayerFee)?;

    if recipient_amount > 0 {
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.key(),
                TransferChecked {
                    from: ctx.accounts.vault.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.recipient_token.to_account_info(),
                    authority: ctx.accounts.pool.to_account_info(),
                },
                signer,
            ),
            recipient_amount,
            ctx.accounts.mint.decimals,
        )?;
    }
    if relayer_fee > 0 {
        transfer_checked(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.key(),
                TransferChecked {
                    from: ctx.accounts.vault.to_account_info(),
                    mint: ctx.accounts.mint.to_account_info(),
                    to: ctx.accounts.relayer_token.to_account_info(),
                    authority: ctx.accounts.pool.to_account_info(),
                },
                signer,
            ),
            relayer_fee,
            ctx.accounts.mint.decimals,
        )?;
    }

    msg!(
        "tidex6-cpool-withdraw:{}:{}:{}:{}",
        amount,
        crate::encode_hex(nullifier_hash),
        ctx.accounts.relayer.key(),
        relayer_fee
    );
    emit!(WithdrawEvent {
        amount,
        nullifier_hash,
        merkle_root,
        recipient: ctx.accounts.recipient.key(),
        relayer: ctx.accounts.relayer.key(),
        relayer_fee,
    });
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// transfer_note (JoinSplit — fully confidential internal transfer)
// ──────────────────────────────────────────────────────────────────────

/// Spend one note and mint two, conserving value with every amount
/// hidden. Verifies the 4-public-input JoinSplit `TransferCircuit`, burns
/// the input note's nullifier, and appends the two output commitments to
/// the tree. No tokens move — value stays in the vault; only note claims
/// change hands. This is where amount linkage is broken: a deposit and a
/// later withdraw need not share a value.
/// Public-input order: `[merkle_root, nullifier_hash, commitment_out1,
/// commitment_out2]`.
#[allow(clippy::too_many_arguments)]
pub fn handle_transfer_note(
    ctx: Context<TransferNote>,
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: [u8; FIELD_ELEMENT_BYTES],
    nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    commitment_out1: [u8; FIELD_ELEMENT_BYTES],
    commitment_out2: [u8; FIELD_ELEMENT_BYTES],
) -> Result<()> {
    // 1. Root recency + capacity for two new leaves.
    {
        let pool = ctx.accounts.pool.load()?;
        let accepted = pool.root_history.iter().any(|entry| entry == &merkle_root);
        require!(accepted, Tidex6VerifierError::MerkleRootNotRecent);
        require!(
            pool.next_leaf_index + 1 < PoolState::capacity(),
            Tidex6VerifierError::PoolFull
        );
    }

    // 2. Record nullifier (double-spend fails at init).
    ctx.accounts.nullifier.nullifier_hash = nullifier_hash;

    // 3. Groth16 verify (4 public inputs).
    let public_inputs: [[u8; 32]; TRANSFER_NR_PUBLIC_INPUTS] = [
        merkle_root,
        nullifier_hash,
        commitment_out1,
        commitment_out2,
    ];
    let mut verifier = Groth16Verifier::<{ TRANSFER_NR_PUBLIC_INPUTS }>::new(
        &proof_a,
        &proof_b,
        &proof_c,
        &public_inputs,
        &TRANSFER_VERIFYING_KEY,
    )
    .map_err(|_| Tidex6VerifierError::Groth16VerifierConstructFailed)?;
    verifier
        .verify()
        .map_err(|_| Tidex6VerifierError::Groth16VerificationFailed)?;

    // 4. Append both output commitments.
    let mut pool = ctx.accounts.pool.load_mut()?;
    let leaf_index1 = pool.next_leaf_index;
    append_leaf(&mut pool, leaf_index1, commitment_out1)?;
    let leaf_index2 = pool.next_leaf_index;
    let new_root = append_leaf(&mut pool, leaf_index2, commitment_out2)?;
    drop(pool);

    msg!(
        "tidex6-cpool-transfer:{}:{}:{}:{}",
        leaf_index1,
        crate::encode_hex(commitment_out1),
        leaf_index2,
        crate::encode_hex(commitment_out2),
    );
    emit!(TransferNoteEvent {
        nullifier_hash,
        commitment_out1,
        commitment_out2,
        leaf_index1,
        leaf_index2,
        new_root,
    });
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// helpers
// ──────────────────────────────────────────────────────────────────────

/// Append a single leaf at `leaf_index`, walk the tree to the new root,
/// push it into the ring buffer, and bump `next_leaf_index`. Returns the
/// new root. Shared by `deposit` and `transfer_note`.
fn append_leaf(
    pool: &mut PoolState,
    leaf_index: u64,
    commitment: [u8; FIELD_ELEMENT_BYTES],
) -> Result<[u8; FIELD_ELEMENT_BYTES]> {
    let mut current_index = leaf_index;
    let mut current_hash = commitment;
    for level in 0..TREE_DEPTH {
        let (left, right) = if current_index & 1 == 0 {
            pool.filled_subtrees[level] = current_hash;
            (current_hash, pool.zero_subtrees[level])
        } else {
            (pool.filled_subtrees[level], current_hash)
        };
        let parent = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&left, &right])
            .map_err(|_| Tidex6VerifierError::PoseidonSyscallFailed)?;
        current_hash = parent.to_bytes();
        current_index >>= 1;
    }
    pool.next_leaf_index = pool
        .next_leaf_index
        .checked_add(1)
        .ok_or(Tidex6VerifierError::PoolFull)?;
    pool.root_ring_head = (pool.root_ring_head + 1) % ROOT_RING_SIZE as u32;
    let ring_index = pool.root_ring_head as usize;
    pool.root_history[ring_index] = current_hash;
    Ok(current_hash)
}

/// Encode a `u64` as a 32-byte big-endian BN254 scalar (low 64 bits).
fn fr_bytes_from_u64(value: u64) -> [u8; FIELD_ELEMENT_BYTES] {
    let mut out = [0u8; FIELD_ELEMENT_BYTES];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Split a 32-byte pubkey into two field elements `(hi, lo)` by 16-byte
/// halves (big-endian), each < 2^128 < BN254 modulus — injective, no
/// collisions. Fixes GAP2: matches `tidex6_confidential::bytes::split_pubkey`.
fn split_pubkey(pubkey: &[u8; 32]) -> ([u8; FIELD_ELEMENT_BYTES], [u8; FIELD_ELEMENT_BYTES]) {
    let mut hi = [0u8; FIELD_ELEMENT_BYTES];
    hi[16..].copy_from_slice(&pubkey[0..16]);
    let mut lo = [0u8; FIELD_ELEMENT_BYTES];
    lo[16..].copy_from_slice(&pubkey[16..32]);
    (hi, lo)
}
