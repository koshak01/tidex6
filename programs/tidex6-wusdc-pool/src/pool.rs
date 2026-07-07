//! wUSDC verify-only pool state and instructions (ADR-015).
//!
//! Hides the LINKAGE deposit↔withdrawal over Token-2022 CT wUSDC. Unlike the
//! SOL verifier this pool **moves no asset** — the confidential wUSDC is held
//! in a separate CT account and moved by the relayer after the pool approves a
//! withdrawal. The pool only:
//!   - `deposit(commitment)` — appends `commitment = Poseidon(secret, nullifier)`
//!     to the Merkle tree and opens the ML-KEM memo account (ADR-014);
//!   - `withdraw(proof, ...)` — verifies the 5-public-input `WithdrawCircuit`
//!     (reused VK, GAP2 as-is for MVP), burns the nullifier PDA, and emits
//!     `WithdrawApproved` for the relayer to move wUSDC to the recipient;
//!   - `refund(...)` — revoke: burns the nullifier and emits `RefundApproved`.
//!
//! The amount lives entirely in the CT wUSDC layer (hidden), so it never
//! appears here. The Merkle mechanics and per-nullifier PDA are reused.

use anchor_lang::prelude::*;
use groth16_solana::groth16::Groth16Verifier;
use solana_poseidon::{hashv, Endianness, Parameters};

use crate::withdraw_vk::{WITHDRAW_NR_PUBLIC_INPUTS, WITHDRAW_VERIFYING_KEY};
use crate::{AppendMemo, Deposit, InitPool, Refund, Tidex6VerifierError, Withdraw};

pub const TREE_DEPTH: usize = 20;
pub const ROOT_RING_SIZE: usize = 30;
pub const FIELD_ELEMENT_BYTES: usize = 32;

/// BN254 scalar field modulus (big-endian) for pubkey reduction.
pub const BN254_MODULUS_BE: [u8; FIELD_ELEMENT_BYTES] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Singleton wUSDC pool state (one pool). PDA seeds `[b"wusdc-pool"]`.
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
    pub const POOL_SEED_PREFIX: &'static [u8] = b"wusdc-pool";

    pub fn capacity() -> u64 {
        1u64 << TREE_DEPTH
    }

    pub fn current_root(&self) -> [u8; FIELD_ELEMENT_BYTES] {
        self.root_history[self.root_ring_head as usize]
    }
}

/// Emitted by every `deposit` for offchain Merkle replay + relayer indexing.
#[event]
pub struct DepositEvent {
    pub commitment: [u8; FIELD_ELEMENT_BYTES],
    pub leaf_index: u64,
    pub new_root: [u8; FIELD_ELEMENT_BYTES],
    pub depositor: Pubkey,
}

/// Emitted on a verified `withdraw`. The relayer reads this and moves the
/// confidential wUSDC from the pool CT account to `recipient`.
#[event]
pub struct WithdrawApproved {
    pub nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    pub merkle_root: [u8; FIELD_ELEMENT_BYTES],
    pub recipient: Pubkey,
    pub relayer: Pubkey,
    pub relayer_fee: u64,
}

/// Emitted on a `refund` (revoke). The relayer returns the wUSDC to depositor.
#[event]
pub struct RefundApproved {
    pub nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    pub depositor: Pubkey,
}

/// ML-KEM memo account (ADR-014). No amount stored — the amount is confidential
/// in the CT layer. Keeps depositor + timestamps for the revoke window.
#[account]
pub struct MemoAccount {
    pub commitment: [u8; FIELD_ELEMENT_BYTES],
    pub depositor: Pubkey,
    pub created_ts: i64,
    pub revoke_window: i64,
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
        8 + FIELD_ELEMENT_BYTES + 32 + 8 + 8 + 4 + 4 + 1 + 1 + 4 + total_len as usize
    }
}

/// Per-nullifier PDA. Seeds `[b"nullifier", nullifier_hash]`.
#[account]
pub struct NullifierRecord {
    pub nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
}

impl NullifierRecord {
    pub const SEED_PREFIX: &'static [u8] = b"nullifier";
    pub const ACCOUNT_SIZE: usize = 8 + FIELD_ELEMENT_BYTES;
}

// ──────────────────────────────────────────────────────────────────────
// init_pool
// ──────────────────────────────────────────────────────────────────────

pub fn handle_init_pool(ctx: Context<InitPool>, mint: Pubkey) -> Result<()> {
    let bump = ctx.bumps.pool;
    let mut pool = ctx.accounts.pool.load_init()?;
    pool.mint = mint;
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
    msg!("tidex6-wpool:initialized:{}", mint);
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// deposit — append commitment, open memo. Moves no asset.
// ──────────────────────────────────────────────────────────────────────

pub fn handle_deposit(
    ctx: Context<Deposit>,
    commitment: [u8; FIELD_ELEMENT_BYTES],
    memo_total_len: u32,
    revoke_window: i64,
    memo_chunk: Vec<u8>,
) -> Result<()> {
    require!(
        (memo_total_len as usize) <= MemoAccount::MAX_TOTAL_LEN,
        Tidex6VerifierError::InvalidMemoTotalLen
    );
    require!(
        memo_chunk.len() <= memo_total_len as usize,
        Tidex6VerifierError::MemoChunkOverflow
    );

    let leaf_index = {
        let pool = ctx.accounts.pool.load()?;
        require!(
            pool.next_leaf_index < PoolState::capacity(),
            Tidex6VerifierError::PoolFull
        );
        pool.next_leaf_index
    };

    let mut pool = ctx.accounts.pool.load_mut()?;
    let new_root = append_leaf(&mut pool, leaf_index, commitment)?;
    drop(pool);

    let now = Clock::get()?.unix_timestamp;
    let chunk_len = memo_chunk.len();
    {
        let memo = &mut ctx.accounts.memo;
        memo.commitment = commitment;
        memo.depositor = ctx.accounts.payer.key();
        memo.created_ts = now;
        memo.revoke_window = revoke_window;
        memo.total_len = memo_total_len;
        memo.written_len = chunk_len as u32;
        memo.bump = ctx.bumps.memo;
        memo.is_finalized = chunk_len as u32 == memo_total_len;
        memo.data = vec![0u8; memo_total_len as usize];
        memo.data[..chunk_len].copy_from_slice(&memo_chunk);
    }

    msg!(
        "tidex6-wpool-deposit:{}:{}:{}",
        leaf_index,
        crate::encode_hex(commitment),
        crate::encode_hex(new_root),
    );
    emit!(DepositEvent {
        commitment,
        leaf_index,
        new_root,
        depositor: ctx.accounts.payer.key(),
    });
    Ok(())
}

pub fn handle_append_memo(ctx: Context<AppendMemo>, offset: u32, chunk: Vec<u8>) -> Result<()> {
    let memo = &mut ctx.accounts.memo;
    require!(!memo.is_finalized, Tidex6VerifierError::MemoAlreadyFinalized);
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
// refund (revoke) — burn nullifier, emit event. Moves no asset.
// ──────────────────────────────────────────────────────────────────────

pub fn handle_refund(
    ctx: Context<Refund>,
    commitment: [u8; FIELD_ELEMENT_BYTES],
    secret: [u8; FIELD_ELEMENT_BYTES],
    nullifier: [u8; FIELD_ELEMENT_BYTES],
    nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
) -> Result<()> {
    // Ownership: Poseidon(secret, nullifier) == commitment (ADR-001).
    let computed = hashv(
        Parameters::Bn254X5,
        Endianness::BigEndian,
        &[&secret, &nullifier],
    )
    .map_err(|_| Tidex6VerifierError::PoseidonSyscallFailed)?
    .to_bytes();
    require!(
        computed == commitment,
        Tidex6VerifierError::RefundCommitmentMismatch
    );
    let computed_nh = hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&nullifier])
        .map_err(|_| Tidex6VerifierError::PoseidonSyscallFailed)?
        .to_bytes();
    require!(
        computed_nh == nullifier_hash,
        Tidex6VerifierError::RefundNullifierMismatch
    );

    let revoke_window = ctx.accounts.memo.revoke_window;
    require!(revoke_window > 0, Tidex6VerifierError::RefundDisabled);
    let now = Clock::get()?.unix_timestamp;
    require!(
        now - ctx.accounts.memo.created_ts >= revoke_window,
        Tidex6VerifierError::RefundTooEarly
    );

    ctx.accounts.nullifier.nullifier_hash = nullifier_hash;
    msg!("tidex6-wpool-refund:{}", crate::encode_hex(nullifier_hash));
    emit!(RefundApproved {
        nullifier_hash,
        depositor: ctx.accounts.depositor.key(),
    });
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// withdraw — verify proof, burn nullifier, emit. Moves no asset.
// ──────────────────────────────────────────────────────────────────────

pub fn handle_withdraw(
    ctx: Context<Withdraw>,
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: [u8; FIELD_ELEMENT_BYTES],
    nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    relayer_fee: u64,
) -> Result<()> {
    // 1. Root recency.
    let root_accepted = {
        let pool = ctx.accounts.pool.load()?;
        pool.root_history.iter().any(|entry| entry == &merkle_root)
    };
    require!(root_accepted, Tidex6VerifierError::MerkleRootNotRecent);

    // 2. Record nullifier (PDA init'd → double-spend fails earlier).
    ctx.accounts.nullifier.nullifier_hash = nullifier_hash;

    // 3. Bind recipient/relayer/fee (reused 5-input VK, reduce_mod as in v2).
    let recipient_fr = reduce_mod_bn254(&ctx.accounts.recipient.key().to_bytes());
    let relayer_fr = reduce_mod_bn254(&ctx.accounts.relayer.key().to_bytes());
    let relayer_fee_fr = fr_bytes_from_u64(relayer_fee);

    // 4. Groth16 verify (5 public inputs).
    let public_inputs: [[u8; 32]; WITHDRAW_NR_PUBLIC_INPUTS] = [
        merkle_root,
        nullifier_hash,
        recipient_fr,
        relayer_fr,
        relayer_fee_fr,
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

    // 5. Approve — relayer moves the confidential wUSDC off this event.
    msg!(
        "tidex6-wpool-withdraw:{}:{}:{}",
        crate::encode_hex(nullifier_hash),
        ctx.accounts.recipient.key(),
        relayer_fee
    );
    emit!(WithdrawApproved {
        nullifier_hash,
        merkle_root,
        recipient: ctx.accounts.recipient.key(),
        relayer: ctx.accounts.relayer.key(),
        relayer_fee,
    });
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────
// helpers
// ──────────────────────────────────────────────────────────────────────

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

fn fr_bytes_from_u64(value: u64) -> [u8; FIELD_ELEMENT_BYTES] {
    let mut out = [0u8; FIELD_ELEMENT_BYTES];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

fn reduce_mod_bn254(bytes: &[u8; FIELD_ELEMENT_BYTES]) -> [u8; FIELD_ELEMENT_BYTES] {
    let mut result = *bytes;
    while ge_be_32(&result, &BN254_MODULUS_BE) {
        sub_be_32_in_place(&mut result, &BN254_MODULUS_BE);
    }
    result
}

fn ge_be_32(a: &[u8; FIELD_ELEMENT_BYTES], b: &[u8; FIELD_ELEMENT_BYTES]) -> bool {
    for index in 0..FIELD_ELEMENT_BYTES {
        if a[index] > b[index] {
            return true;
        }
        if a[index] < b[index] {
            return false;
        }
    }
    true
}

fn sub_be_32_in_place(a: &mut [u8; FIELD_ELEMENT_BYTES], b: &[u8; FIELD_ELEMENT_BYTES]) {
    let mut borrow: i16 = 0;
    for index in (0..FIELD_ELEMENT_BYTES).rev() {
        let difference = a[index] as i16 - b[index] as i16 - borrow;
        if difference < 0 {
            a[index] = (difference + 256) as u8;
            borrow = 1;
        } else {
            a[index] = difference as u8;
            borrow = 0;
        }
    }
}
