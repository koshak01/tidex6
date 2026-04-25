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
use groth16_solana::groth16::Groth16Verifier;
use solana_poseidon::{Endianness, Parameters, hashv};

use crate::withdraw_vk::{WITHDRAW_NR_PUBLIC_INPUTS, WITHDRAW_VERIFYING_KEY};
use crate::{Deposit, InitPool, Tidex6VerifierError, Withdraw};

/// Tree depth used by the MVP shielded pool. Matches
/// `tidex6_core::merkle::DEFAULT_DEPTH`. 2^20 ≈ 1 048 576 leaves.
pub const TREE_DEPTH: usize = 20;

/// Number of recent Merkle roots kept in the ring buffer. A
/// withdrawal proof can reference any of these, so a depositor has
/// some slack to generate a proof before the root drifts. Tornado
/// Cash uses 30; we follow the same convention.
pub const ROOT_RING_SIZE: usize = 30;

/// BN254 scalar field modulus encoded big-endian. Used to reduce
/// an arbitrary 32-byte value (e.g. a Solana pubkey) into a valid
/// field-element encoding before handing it to the Groth16
/// verifier. Matches the constant in
/// `tidex6_core::types::BN254_SCALAR_FIELD_MODULUS_BE`.
pub const BN254_MODULUS_BE: [u8; FIELD_ELEMENT_BYTES] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

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
///
/// `memo_payload` carries the Shielded Memo bytes from
/// `tidex6_core::memo::MemoPayload::to_bytes` — the concatenation of
/// `ephemeral_pk || iv || tag || ciphertext`. The verifier stores
/// the bytes verbatim and does not interpret them; the accountant
/// scanner on the client side is what decides whether any given
/// payload decrypts under a given auditor secret key.
#[event]
pub struct DepositEvent {
    pub denomination: u64,
    pub commitment: [u8; FIELD_ELEMENT_BYTES],
    pub leaf_index: u64,
    pub new_root: [u8; FIELD_ELEMENT_BYTES],
    /// Raw Shielded Memo bytes — fixed-prefix `ephemeral_pk || iv || tag`
    /// followed by the AES-GCM ciphertext. The verifier enforces the
    /// overall length against `MEMO_PAYLOAD_MIN_LEN` / `MEMO_PAYLOAD_MAX_LEN`
    /// to keep transaction size bounded but does not parse or
    /// cryptographically validate the contents.
    pub memo_payload: Vec<u8>,
}

/// Minimum size, in bytes, of a `memo_payload` accepted by
/// [`handle_deposit`]. ADR-012 envelope wire-format minimum:
///
///     header (4)                          // version + flags + cipher_len
///   + ciphertext block (28 + plaintext)   // 12 nonce + 16 tag + 0 bytes
///   + recipient wrap-K slot (60)
///   = 92 bytes
///
/// This is the floor for an envelope with *empty* plaintext and no
/// auditor slot — i.e. the smallest legal `MemoEnvelope::to_bytes`
/// output. Setting the bound any higher than this would break the
/// recipient-only mode for short memos (e.g. a 7-byte "test" memo
/// produces a 99-byte envelope, which an over-eager 152-byte floor
/// would reject as `InvalidMemoPayloadLength`). Caught live on
/// 2026-04-25 against `tidex6.com` after the previous tighter bound
/// rejected every short recipient-only memo on chain.
pub const MEMO_PAYLOAD_MIN_LEN: usize = 92;

/// Maximum size, in bytes, of a `memo_payload`. ADR-012 ceiling:
///
///     header (4)
///   + ciphertext (28 + 256 plaintext)     // max plaintext
///   + recipient wrap (60)
///   + optional auditor wrap (92)
///   = 440 bytes
///
/// Rounded up to 512 for headroom; enforced on-chain so a malformed
/// or absurdly large instruction cannot bloat the transaction
/// beyond what a single deposit ought to cost.
pub const MEMO_PAYLOAD_MAX_LEN: usize = 512;

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
/// into the ring buffer, and emits a `DepositEvent` carrying the
/// commitment and the Shielded Memo payload for offchain indexers.
///
/// `memo_payload` is passed through verbatim into the event; the
/// verifier only checks the byte-length bounds so neither a missing
/// memo nor an oversized one can corrupt the Merkle update.
pub fn handle_deposit(
    ctx: Context<Deposit>,
    commitment: [u8; FIELD_ELEMENT_BYTES],
    memo_payload: Vec<u8>,
) -> Result<()> {
    require!(
        memo_payload.len() >= MEMO_PAYLOAD_MIN_LEN && memo_payload.len() <= MEMO_PAYLOAD_MAX_LEN,
        crate::Tidex6VerifierError::InvalidMemoPayloadLength
    );
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

    // The log line is parsed offchain by tidex6-indexer to
    // replay the full Merkle tree from chain history. Format:
    //   tidex6-deposit:<leaf_index>:<commitment_hex>:<new_root_hex>:<memo_hex>
    // The memo trailer is lowercase hex of the raw `memo_payload`
    // bytes — the indexer decodes it back into a `MemoPayload` for
    // the accountant scanner without having to re-parse the Anchor
    // event's base64 blob.
    msg!(
        "tidex6-deposit:{}:{}:{}:{}",
        leaf_index,
        crate::encode_hex(commitment),
        crate::encode_hex(current_hash),
        crate::encode_hex_bytes(&memo_payload),
    );
    emit!(DepositEvent {
        denomination: denomination_copy,
        commitment,
        leaf_index,
        new_root: current_hash,
        memo_payload,
    });

    Ok(())
}

/// Handle a withdraw request. Verifies a Groth16 proof of
/// `WithdrawCircuit<20>` against the hardcoded `WITHDRAW_VERIFYING_KEY`
/// and, on success, transfers `(denomination - relayer_fee)` lamports
/// from the pool vault to the recipient account and `relayer_fee`
/// lamports to the relayer account. The nullifier PDA is created
/// during the instruction via Anchor's `init` constraint, so a
/// double-spend fails at the account-initialisation step before any
/// Groth16 work happens.
///
/// `relayer_fee` was added in ADR-011. The reference `tidex6-relayer`
/// service passes zero; any third-party relayer may pass a non-zero
/// value bounded by the pool denomination. The circuit binds the
/// specific `(recipient, relayer_address, relayer_fee)` tuple, so a
/// front-runner rewriting any of those fields in the submitted
/// transaction invalidates the proof.
pub fn handle_withdraw(
    ctx: Context<Withdraw>,
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: [u8; FIELD_ELEMENT_BYTES],
    nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    relayer_fee: u64,
) -> Result<()> {
    // 1. Sanity-check that the claimed Merkle root is present in
    //    the pool's recent-root ring buffer.
    let (denomination, root_accepted, vault_bump) = {
        let pool = ctx.accounts.pool.load()?;
        let mut accepted = false;
        for entry in pool.root_history.iter() {
            if entry == &merkle_root {
                accepted = true;
                break;
            }
        }
        (pool.denomination, accepted, ctx.bumps.vault)
    };
    require!(root_accepted, Tidex6VerifierError::MerkleRootNotRecent);

    // 2. ADR-011: the relayer fee must not exceed the pool
    //    denomination. If it did, the handler would underflow when
    //    computing the recipient amount; rejecting here keeps the
    //    arithmetic obviously safe.
    require!(
        relayer_fee <= denomination,
        Tidex6VerifierError::InvalidRelayerFee
    );

    // 3. The nullifier PDA was initialised via the `init` attribute
    //    in the account constraints, so if we reach this point the
    //    nullifier_hash seed has never been used before. Record the
    //    hash inside it for offchain observability.
    ctx.accounts.nullifier.nullifier_hash = nullifier_hash;

    // 4. Reduce the recipient and relayer pubkeys to BN254 scalars.
    //    The prover used the same reduction offchain when building
    //    the witness. `relayer_fee` is encoded as a 32-byte
    //    big-endian field element via `fr_bytes_from_u64`; since
    //    every u64 is below the BN254 modulus no explicit reduction
    //    is needed.
    let recipient_raw = ctx.accounts.recipient.key().to_bytes();
    let recipient_fr = reduce_mod_bn254(&recipient_raw);

    let relayer_raw = ctx.accounts.relayer.key().to_bytes();
    let relayer_fr = reduce_mod_bn254(&relayer_raw);

    let relayer_fee_fr = fr_bytes_from_u64(relayer_fee);

    // 5. Run the Groth16 verifier against the hardcoded VK.
    //    Public-input order, fixed by ADR-011, matches the order
    //    committed to in `tidex6_circuits::withdraw::prove_withdraw`.
    let public_inputs: [[u8; 32]; 5] = [
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

    // 6. Transfer `(denomination - relayer_fee)` lamports from the
    //    vault PDA to the recipient and `relayer_fee` to the relayer
    //    via two system-program CPIs with the same seeded signer
    //    (the vault is a system-owned PDA). Zero-value transfers are
    //    skipped to save compute units and to avoid any system-program
    //    edge case around zero-lamport moves.
    let denomination_bytes: [u8; 8] = denomination.to_le_bytes();
    let vault_signer_seeds: &[&[u8]] = &[
        PoolState::VAULT_SEED_PREFIX,
        &denomination_bytes,
        std::slice::from_ref(&vault_bump),
    ];
    let signer_seeds = &[vault_signer_seeds];

    let recipient_amount = denomination
        .checked_sub(relayer_fee)
        .ok_or(Tidex6VerifierError::InvalidRelayerFee)?;

    if recipient_amount > 0 {
        transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.key(),
                Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.recipient.to_account_info(),
                },
                signer_seeds,
            ),
            recipient_amount,
        )?;
    }

    if relayer_fee > 0 {
        transfer(
            CpiContext::new_with_signer(
                ctx.accounts.system_program.key(),
                Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.relayer.to_account_info(),
                },
                signer_seeds,
            ),
            relayer_fee,
        )?;
    }

    // 7. Log line, indexer-parseable. ADR-011 widens the prior
    //    3-field format to a 5-field one:
    //      tidex6-withdraw:<denomination>:<nullifier_hex>:<relayer_base58>:<relayer_fee>
    //    The offchain log parser accepts both the legacy 2-trailer
    //    format and this 4-trailer one; see indexer rebuild logic.
    msg!(
        "tidex6-withdraw:{}:{}:{}:{}",
        denomination,
        crate::encode_hex(nullifier_hash),
        ctx.accounts.relayer.key(),
        relayer_fee
    );
    emit!(WithdrawEvent {
        denomination,
        nullifier_hash,
        merkle_root,
        recipient: ctx.accounts.recipient.key(),
        relayer: ctx.accounts.relayer.key(),
        relayer_fee,
    });

    Ok(())
}

/// Encode a `u64` as a 32-byte big-endian canonical BN254 scalar
/// representation, matching the encoding used offchain by
/// `tidex6_circuits::withdraw::relayer_fee_bytes_from_u64`. The top
/// 192 bits are zero; the low 64 bits carry `value` in big-endian
/// order. Since every `u64` is smaller than the BN254 modulus the
/// result is already canonical — no explicit reduction required.
fn fr_bytes_from_u64(value: u64) -> [u8; FIELD_ELEMENT_BYTES] {
    let mut out = [0u8; FIELD_ELEMENT_BYTES];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Reduce an arbitrary 32-byte big-endian value into the canonical
/// representation of a BN254 scalar field element. Repeated
/// subtraction of the modulus; the input is at most ~5× the
/// modulus (since 2^256 / BN254_MODULUS ≈ 5.3) so the loop runs at
/// most 5 iterations — cheap in compute units.
fn reduce_mod_bn254(bytes: &[u8; FIELD_ELEMENT_BYTES]) -> [u8; FIELD_ELEMENT_BYTES] {
    let mut result = *bytes;
    while ge_be_32(&result, &BN254_MODULUS_BE) {
        sub_be_32_in_place(&mut result, &BN254_MODULUS_BE);
    }
    result
}

/// Big-endian 32-byte `>=` comparison.
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

/// Big-endian 32-byte in-place subtraction: `a -= b`. Assumes
/// `a >= b`, which the caller guarantees via `ge_be_32`.
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

/// Per-nullifier PDA. Seeds `[b"nullifier", nullifier_hash]`. The
/// only data is the nullifier hash itself (stored redundantly for
/// offchain observability — the seeds already encode it). Created
/// during the `withdraw` instruction and never closed; its
/// existence is the double-spend prevention mechanism.
#[account]
pub struct NullifierRecord {
    pub nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
}

impl NullifierRecord {
    /// Seed prefix used for the per-nullifier PDA.
    pub const SEED_PREFIX: &'static [u8] = b"nullifier";

    /// Statically known account size: Anchor discriminator (8 bytes)
    /// plus a single 32-byte field.
    pub const ACCOUNT_SIZE: usize = 8 + FIELD_ELEMENT_BYTES;
}

/// Emitted by every successful `withdraw`. Offchain indexers use
/// it to track SOL outflow from the pool.
///
/// `relayer` and `relayer_fee` were added in ADR-011. The indexer
/// reads them to show which relayer processed a given withdraw and
/// how the payout was split between the recipient and the relayer.
#[event]
pub struct WithdrawEvent {
    pub denomination: u64,
    pub nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    pub merkle_root: [u8; FIELD_ELEMENT_BYTES],
    pub recipient: Pubkey,
    /// The account that submitted the transaction and received the
    /// relayer fee (ADR-011).
    pub relayer: Pubkey,
    /// Lamports transferred from the pool vault to `relayer` as the
    /// relayer's compensation. Zero when the user self-submitted the
    /// withdraw or when the reference `relayer.tidex6.com` service
    /// processed it (policy: no fee).
    pub relayer_fee: u64,
}
