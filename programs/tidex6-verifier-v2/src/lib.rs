// Anchor macros emit cfg values for `target_os = "solana"` and
// `feature = "anchor-debug"` that are not in rustc's default check list.
// These are part of Anchor's internal feature gating and are not bugs.
#![allow(unexpected_cfgs)]
// Anchor's `#[program]` macro generates code that uses `use super::*`
// to bring account-context types into scope inside the program module,
// and contains control-flow shapes that trip clippy's
// `diverging_sub_expression` lint. Both are internal to the macro and
// not under our control, so we silence them crate-wide.
#![allow(clippy::wildcard_imports, clippy::diverging_sub_expression)]

//! tidex6-verifier-v2 — post-quantum shielded pool (ADR-014).
//!
//! A fresh, separate program from the immutable v1 verifier
//! (`2qEm…cU9C`). The `WithdrawCircuit<20>` verifying key, the Merkle
//! mechanics, the per-nullifier double-spend PDA and the relayer
//! fee-in-circuit (ADR-011) are **reused unchanged** — so this program
//! needs **no new trusted-setup ceremony**. What changes is the deposit
//! path: the ML-KEM-768 envelope (~1.2 KB, too large for a transaction)
//! is stored in a **dedicated account** written in chunks, carrying a
//! per-reader slot for the auditor(s), regulator(s) and the stealth
//! recipient. A new `refund` instruction implements the 30-day revoke:
//! if a note is never withdrawn, the depositor reclaims it.
//!
//! See `docs/release/adr/ADR-014-mlkem-memo-account.md`.

use anchor_lang::prelude::*;

mod pool;
mod withdraw_vk;

pub use pool::{
    DepositEvent, FIELD_ELEMENT_BYTES, MemoAccount, NullifierRecord, PoolState, ROOT_RING_SIZE,
    TREE_DEPTH, WithdrawEvent,
};
// Re-export the withdraw VK so offchain crates (notably
// `tidex6-relayer`) can verify Groth16 proofs against exactly the
// same verifying key the on-chain program uses.
pub use withdraw_vk::{WITHDRAW_NR_PUBLIC_INPUTS, WITHDRAW_VERIFYING_KEY};

declare_id!("CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd");

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "tidex6-verifier-v2",
    project_url: "https://github.com/koshak01/tidex6",
    contacts: "email:koshak01@users.noreply.github.com",
    policy: "https://github.com/koshak01/tidex6/blob/master/SECURITY.md",
    preferred_languages: "en,ru",
    source_code: "https://github.com/koshak01/tidex6",
    auditors: "Unaudited - see docs/release/security.md for threat model"
}

#[program]
pub mod tidex6_verifier_v2 {
    use super::*;

    /// Initialise a new shielded pool for the given denomination.
    /// Delegates to `pool::handle_init_pool`. Reused unchanged from v1.
    pub fn init_pool(context: Context<InitPool>, denomination: u64) -> Result<()> {
        pool::handle_init_pool(context, denomination)
    }

    /// Deposit `commitment` into the pool and open the dedicated
    /// ML-KEM memo account.
    ///
    /// Transfers `denomination` lamports into the vault, appends the
    /// commitment to the onchain Merkle tree, and creates the memo
    /// account at PDA `[b"memo", commitment]` sized for `memo_total_len`
    /// bytes. The first chunk of the envelope is written here; the rest
    /// arrives via [`append_memo`]. The depositor pubkey and the current
    /// unix timestamp are recorded for the 30-day revoke.
    ///
    /// The verifier never parses the envelope — it stores opaque bytes.
    /// `memo_total_len` is bounded so a caller cannot allocate an absurd
    /// account.
    /// `revoke_window` is the per-deposit revoke period in seconds: the
    /// depositor may `refund` this deposit only after
    /// `created_ts + revoke_window`. A value of `0` makes the deposit
    /// **irrevocable** — refund is permanently disabled for it. The
    /// depositor, not the protocol, chooses this per deposit.
    pub fn deposit(
        context: Context<Deposit>,
        commitment: [u8; FIELD_ELEMENT_BYTES],
        memo_total_len: u32,
        revoke_window: i64,
        memo_chunk: Vec<u8>,
    ) -> Result<()> {
        pool::handle_deposit(context, commitment, memo_total_len, revoke_window, memo_chunk)
    }

    /// Append the next chunk of the ML-KEM envelope to a memo account
    /// opened by [`deposit`]. Writes at `offset`, advances the
    /// written-length cursor, and flips `is_finalized` once the account
    /// is full. Only the original depositor may append, and only while
    /// the account is not yet finalized.
    pub fn append_memo(
        context: Context<AppendMemo>,
        commitment: [u8; FIELD_ELEMENT_BYTES],
        offset: u32,
        chunk: Vec<u8>,
    ) -> Result<()> {
        // `commitment` is consumed by the AppendMemo accounts' PDA seed
        // (`#[instruction(commitment)]`); the handler body does not use it.
        let _ = commitment;
        pool::handle_append_memo(context, offset, chunk)
    }

    /// 30-day revoke. Reclaim a never-withdrawn deposit.
    ///
    /// The depositor presents `(secret, nullifier)` proving ownership of
    /// the note via `Poseidon(secret, nullifier) == commitment` (a plain
    /// onchain syscall, not a ZK proof). If 30 days have passed since the
    /// deposit and the note's nullifier PDA still does not exist (never
    /// withdrawn), the deposit is returned from the vault to the
    /// depositor and the nullifier PDA is created so the note can never
    /// be withdrawn afterwards. The memo account is closed, its rent
    /// refunded to the depositor.
    pub fn refund(
        context: Context<Refund>,
        commitment: [u8; FIELD_ELEMENT_BYTES],
        secret: [u8; FIELD_ELEMENT_BYTES],
        nullifier: [u8; FIELD_ELEMENT_BYTES],
        nullifier_hash: [u8; FIELD_ELEMENT_BYTES],
    ) -> Result<()> {
        pool::handle_refund(context, commitment, secret, nullifier, nullifier_hash)
    }

    /// Withdraw a previously-deposited note. Reused unchanged from v1
    /// (ADR-011): `WithdrawCircuit<20>` Groth16 proof with five public
    /// inputs `(merkle_root, nullifier_hash, recipient, relayer, fee)`.
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

/// Encode 32 bytes as a lowercase hexadecimal string.
///
/// Deliberately avoids pulling in the `hex` crate so that the program
/// dependency graph stays as small as possible.
fn encode_hex(bytes: [u8; 32]) -> String {
    encode_hex_bytes(&bytes)
}

/// Variable-length variant of [`encode_hex`], used for the
/// `tidex6-v2-deposit` indexer log line.
fn encode_hex_bytes(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_CHARS[(byte >> 4) as usize] as char);
        out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Accounts for `init_pool`. Reused unchanged from v1.
#[derive(Accounts)]
#[instruction(denomination: u64)]
pub struct InitPool<'info> {
    #[account(
        init,
        payer = payer,
        space = PoolState::DISCRIMINATOR.len() + std::mem::size_of::<PoolState>(),
        seeds = [PoolState::POOL_SEED_PREFIX, &denomination.to_le_bytes()],
        bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    /// CHECK: system-owned vault PDA, deterministic seed.
    #[account(
        init,
        payer = payer,
        space = 0,
        seeds = [PoolState::VAULT_SEED_PREFIX, &denomination.to_le_bytes()],
        bump,
        owner = anchor_lang::system_program::ID,
    )]
    pub vault: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Accounts for `deposit`. Adds the dedicated memo account (PDA
/// `[b"memo", commitment]`) created here and sized for the whole
/// envelope; the first chunk is written by the handler.
#[derive(Accounts)]
#[instruction(commitment: [u8; FIELD_ELEMENT_BYTES], memo_total_len: u32)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX, &pool.load()?.denomination.to_le_bytes()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    /// CHECK: system-owned vault PDA derived from the pool denomination.
    #[account(
        mut,
        seeds = [PoolState::VAULT_SEED_PREFIX, &pool.load()?.denomination.to_le_bytes()],
        bump,
    )]
    pub vault: UncheckedAccount<'info>,

    /// The dedicated ML-KEM memo account for this commitment. Sized for
    /// the full envelope up front; written in chunks (this one + later
    /// `append_memo` calls).
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

/// Accounts for `append_memo`. The memo account is re-derived from the
/// commitment so a caller cannot write into a different deposit's memo.
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

/// Accounts for `refund` (30-day revoke). Reclaims the deposit and
/// permanently blocks the note by creating its nullifier PDA.
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
        seeds = [PoolState::POOL_SEED_PREFIX, &pool.load()?.denomination.to_le_bytes()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    /// CHECK: system-owned vault PDA derived from the pool denomination.
    #[account(
        mut,
        seeds = [PoolState::VAULT_SEED_PREFIX, &pool.load()?.denomination.to_le_bytes()],
        bump,
    )]
    pub vault: UncheckedAccount<'info>,

    /// The memo account opened at deposit. Closed on refund, rent back
    /// to the depositor. `has_one = depositor` ties it to the signer.
    #[account(
        mut,
        close = depositor,
        seeds = [MemoAccount::SEED_PREFIX, &commitment],
        bump = memo.bump,
        has_one = depositor,
    )]
    pub memo: Account<'info, MemoAccount>,

    /// The per-nullifier PDA. Created here so that after a refund the
    /// note's nullifier_hash is permanently spent — a later withdraw of
    /// the same note fails at `init`.
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

/// Accounts for `withdraw`. Reused unchanged from v1 (ADR-011).
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
        seeds = [PoolState::POOL_SEED_PREFIX, &pool.load()?.denomination.to_le_bytes()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    /// CHECK: system-owned vault PDA derived from the pool denomination.
    #[account(
        mut,
        seeds = [PoolState::VAULT_SEED_PREFIX, &pool.load()?.denomination.to_le_bytes()],
        bump,
    )]
    pub vault: UncheckedAccount<'info>,

    /// The per-nullifier PDA. Created here; double-spend attempts
    /// fail at `init` before any Groth16 work runs.
    #[account(
        init,
        payer = payer,
        space = NullifierRecord::ACCOUNT_SIZE,
        seeds = [NullifierRecord::SEED_PREFIX, &nullifier_hash],
        bump,
    )]
    pub nullifier: Account<'info, NullifierRecord>,

    /// CHECK: recipient is any system account, bound to the proof as a
    /// public input (front-run resistant).
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    /// CHECK: relayer is any system account, bound to the proof as the
    /// fourth public input (ADR-011).
    #[account(mut)]
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
    #[msg("Pool denomination must be greater than zero.")]
    InvalidDenomination,
    #[msg("Pool is full; no more deposits can be accepted into this tree.")]
    PoolFull,
    #[msg("The supplied Merkle root is not in the pool's recent-root ring buffer.")]
    MerkleRootNotRecent,
    #[msg("Relayer fee must not exceed the pool denomination.")]
    InvalidRelayerFee,
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
