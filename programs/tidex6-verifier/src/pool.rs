//! Production shielded-pool state and instructions.
//!
//! This module implements the `init_pool` and `deposit` flow that the
//! Day-5 work in tidex6 closes: a minimal Anchor program that accepts
//! commitments, updates an onchain Merkle tree using the
//! `solana-poseidon` syscall, stores a ring buffer of recent roots,
//! and emits a deposit event. It mirrors the offchain
//! `tidex6_core::merkle::MerkleTree` but uses the native BN254
//! Poseidon syscall instead of `light-poseidon` so the tree update is
//! computed onchain with a bounded compute-unit cost.
//!
//! Withdrawal is deliberately NOT implemented here yet — that
//! requires the ZK circuits from Days 6–10. The Day-5 scope is the
//! deposit half of the flow end-to-end on devnet.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{Transfer, transfer};
use solana_poseidon::{Endianness, Parameters, hashv};

use crate::{Deposit, InitPool, Tidex6VerifierError};

/// Tree depth used by the MVP shielded pool. Matches
/// `tidex6_core::merkle::DEFAULT_DEPTH`. 2^20 ≈ 1 048 576 leaves.
pub const TREE_DEPTH: usize = 20;

/// Number of recent Merkle roots kept in the ring buffer. A
/// withdrawal proof can reference any of these, so a depositor has
/// some slack to generate a proof before the root drifts. Tornado
/// Cash uses 30; we follow the same convention.
pub const ROOT_RING_SIZE: usize = 30;

/// Length in bytes of a BN254 scalar field element — the unit used
/// for commitments, nullifiers, and Merkle roots.
pub const FIELD_ELEMENT_BYTES: usize = 32;

/// Onchain state of a single shielded pool instance.
///
/// Stored as a PDA with seeds `[b"pool", denomination.to_le_bytes()]`
/// so each denomination has exactly one pool. The state includes
/// everything needed to recompute the Merkle root after a deposit
/// without recomputing the entire tree:
///
/// - `filled_subtrees[level]` holds the hash of the most recently
///   committed left-subtree at that level (the Tornado append-only
///   trick).
/// - `zero_subtrees[level]` holds the hash of an all-zero subtree of
///   that height, precomputed once at init time so deposits do not
///   have to recompute it.
/// - `root_history` is a ring buffer of the last `ROOT_RING_SIZE`
///   roots, and `root_ring_head` is the index of the most recent
///   entry.
///
/// Stored as `#[account(zero_copy)]` because the total size is
/// ~2.2 KB, which would blow the Solana BPF stack on initialisation
/// if Anchor had to zero the struct on the stack first. Zero-copy
/// mode reads and writes the account data directly.
#[account(zero_copy)]
#[repr(C)]
pub struct PoolState {
    pub denomination: u64,
    pub next_leaf_index: u64,
    pub root_ring_head: u32,
    pub bump: u8,
    pub _padding: [u8; 3],
    pub filled_subtrees: [[u8; FIELD_ELEMENT_BYTES]; TREE_DEPTH],
    pub zero_subtrees: [[u8; FIELD_ELEMENT_BYTES]; TREE_DEPTH],
    pub root_history: [[u8; FIELD_ELEMENT_BYTES]; ROOT_RING_SIZE],
}

impl PoolState {
    /// Seed prefix used in both the pool state PDA and the vault PDA.
    pub const POOL_SEED_PREFIX: &'static [u8] = b"pool";
    pub const VAULT_SEED_PREFIX: &'static [u8] = b"vault";

    /// Maximum number of leaves this pool can ever hold.
    pub fn capacity() -> u64 {
        1u64 << TREE_DEPTH
    }

    /// Current root, i.e. the most recent entry in the ring buffer.
    pub fn current_root(&self) -> [u8; FIELD_ELEMENT_BYTES] {
        self.root_history[self.root_ring_head as usize]
    }
}

/// Emitted by every successful `deposit` so offchain indexers can
/// rebuild the Merkle tree from chain history.
#[event]
pub struct DepositEvent {
    pub denomination: u64,
    pub commitment: [u8; FIELD_ELEMENT_BYTES],
    pub leaf_index: u64,
    pub new_root: [u8; FIELD_ELEMENT_BYTES],
}

/// Initialise a new shielded pool for `denomination` lamports per
/// deposit. Pre-computes the zero-subtree hashes at every level and
/// sets the initial root to the empty-tree root. Fails if a pool
/// for this denomination already exists.
pub fn handle_init_pool(ctx: Context<InitPool>, denomination: u64) -> Result<()> {
    require!(denomination > 0, Tidex6VerifierError::InvalidDenomination);

    let bump = ctx.bumps.pool;
    let mut pool = ctx.accounts.pool.load_init()?;

    pool.denomination = denomination;
    pool.bump = bump;
    pool._padding = [0u8; 3];
    pool.next_leaf_index = 0;
    pool.root_ring_head = 0;
    pool.filled_subtrees = [[0u8; FIELD_ELEMENT_BYTES]; TREE_DEPTH];
    pool.zero_subtrees = [[0u8; FIELD_ELEMENT_BYTES]; TREE_DEPTH];
    pool.root_history = [[0u8; FIELD_ELEMENT_BYTES]; ROOT_RING_SIZE];

    // Precompute zero-subtree hashes from leaf level up. At level 0
    // the empty leaf is all zeros; at every subsequent level it is
    // the Poseidon hash of two copies of the previous level.
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

    // The final `zero_hash` is the root of an all-zero tree at
    // depth `TREE_DEPTH` — the empty-pool root.
    pool.root_history[0] = zero_hash;

    msg!("tidex6-pool:initialized:{}", denomination);
    Ok(())
}

/// Deposit a commitment into the pool. Transfers `denomination`
/// lamports from the payer to the pool vault, appends the commitment
/// at `next_leaf_index`, walks the Merkle tree upward to compute the
/// new root using the onchain Poseidon syscall, pushes the new root
/// into the ring buffer, and emits a `DepositEvent` for offchain
/// indexers.
pub fn handle_deposit(ctx: Context<Deposit>, commitment: [u8; FIELD_ELEMENT_BYTES]) -> Result<()> {
    // Read the denomination and capacity check with a short-lived
    // immutable borrow, then drop it before we initiate the transfer
    // CPI so we do not hold two live borrows into account data at
    // the same time.
    let (denomination, next_leaf_index) = {
        let pool = ctx.accounts.pool.load()?;
        require!(
            pool.next_leaf_index < PoolState::capacity(),
            Tidex6VerifierError::PoolFull
        );
        (pool.denomination, pool.next_leaf_index)
    };

    // Transfer SOL from the payer into the vault PDA. The vault is
    // system-owned so we go through the system program. CpiContext::
    // new in Anchor 1.0 takes the target program_id as a Pubkey
    // rather than an AccountInfo.
    transfer(
        CpiContext::new(
            ctx.accounts.system_program.key(),
            Transfer {
                from: ctx.accounts.payer.to_account_info(),
                to: ctx.accounts.vault.to_account_info(),
            },
        ),
        denomination,
    )?;

    // Re-open the pool for mutation and walk up the tree.
    let mut pool = ctx.accounts.pool.load_mut()?;

    let leaf_index = next_leaf_index;
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

    let denomination_copy = pool.denomination;
    drop(pool);

    msg!(
        "tidex6-deposit:{}:{}",
        leaf_index,
        crate::encode_hex(current_hash)
    );
    emit!(DepositEvent {
        denomination: denomination_copy,
        commitment,
        leaf_index,
        new_root: current_hash,
    });

    Ok(())
}
