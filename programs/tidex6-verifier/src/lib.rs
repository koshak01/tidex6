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

//! tidex6-verifier — onchain Groth16 verifier and Day-1 primitive validation.
//!
//! In the MVP this program starts as the validation harness for the
//! Day-1 Validation Checklist from `docs/release/security.md` section 3.
//! Its instructions exercise the onchain primitives that the rest of the
//! framework will later depend on: the Poseidon syscall, the `alt_bn128`
//! syscalls, and the `groth16-solana` verification crate.
//!
//! Once the primitives are proven to work onchain, this program grows
//! into the full `tidex6-verifier` described in the project brief:
//! a singleton, non-upgradeable Groth16 verifier that integrator
//! programs call via CPI. See `docs/release/adr/ADR-005-non-upgradeable-verifier.md`.

use anchor_lang::prelude::*;
use groth16_solana::groth16::Groth16Verifier;
use solana_poseidon::{Endianness, Parameters, hashv};

mod groth16_test_vectors;
mod pool;
mod withdraw_vk;

use groth16_test_vectors::{PUBLIC_INPUTS, VERIFYING_KEY};
pub use pool::{
    DepositEvent, FIELD_ELEMENT_BYTES, NullifierRecord, PoolState, ROOT_RING_SIZE, TREE_DEPTH,
    WithdrawEvent,
};
// Re-export the withdraw VK so offchain crates (notably
// `tidex6-relayer`) can verify Groth16 proofs against exactly the
// same verifying key the on-chain program uses.
pub use withdraw_vk::{WITHDRAW_NR_PUBLIC_INPUTS, WITHDRAW_VERIFYING_KEY};

declare_id!("2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C");

#[cfg(not(feature = "no-entrypoint"))]
solana_security_txt::security_txt! {
    name: "tidex6-verifier",
    project_url: "https://github.com/koshak01/tidex6",
    contacts: "email:koshak01@users.noreply.github.com",
    policy: "https://github.com/koshak01/tidex6/blob/master/SECURITY.md",
    preferred_languages: "en,ru",
    source_code: "https://github.com/koshak01/tidex6",
    auditors: "Unaudited - see docs/release/security.md for threat model"
}

#[program]
pub mod tidex6_verifier {
    use super::*;

    /// Compute `Poseidon(inputs)` onchain and emit the 32-byte result in
    /// a program log. The client fetches the log, decodes the bytes, and
    /// compares them against the offchain `tidex6_core::poseidon` output.
    ///
    /// This is the onchain half of Day-1 Validation Checklist item 1:
    /// byte-for-byte equivalence between `light-poseidon::new_circom` and
    /// the onchain `sol_poseidon` syscall.
    ///
    /// Accepts between 1 and 12 inputs, each 32 bytes, in big-endian
    /// encoding. Values that exceed the BN254 scalar field modulus are
    /// rejected by the syscall itself with a descriptive error.
    pub fn hash_poseidon(context: Context<HashPoseidon>, inputs: Vec<[u8; 32]>) -> Result<()> {
        let _ = context;

        require!(
            !inputs.is_empty() && inputs.len() <= 12,
            Tidex6VerifierError::UnsupportedInputCount
        );

        let slices: Vec<&[u8]> = inputs.iter().map(|slice| slice.as_slice()).collect();
        let hash = hashv(Parameters::Bn254X5, Endianness::BigEndian, &slices)
            .map_err(|_| Tidex6VerifierError::PoseidonSyscallFailed)?;

        // Log the hash as a hex string with a known prefix so the Day-1
        // validation harness can parse it out of the transaction logs
        // without needing Anchor event decoding. This keeps the client
        // side simple and avoids a base64 + discriminator dance.
        let bytes = hash.to_bytes();
        msg!("tidex6-day1-poseidon:{}", encode_hex(bytes));

        Ok(())
    }

    /// Verify a Groth16 proof onchain against the hardcoded
    /// `VERIFYING_KEY` and `PUBLIC_INPUTS` from the upstream
    /// `groth16-solana` test suite. The caller passes the three proof
    /// components `(proof_a, proof_b, proof_c)` in the serialization
    /// expected by `groth16-solana`: `proof_a` must already be negated
    /// offchain, `proof_b` and `proof_c` are passed through verbatim.
    ///
    /// This is Day-1 Validation Checklist item 2 (Groth16 pipeline
    /// smoke test) and item 3 (alt_bn128 syscall availability) in a
    /// single instruction: a successful `Groth16Verifier::verify()`
    /// proves that `alt_bn128_addition`, `alt_bn128_multiplication`,
    /// and `alt_bn128_pairing` syscalls are all active on the target
    /// cluster.
    ///
    /// Logs `tidex6-day1-groth16:VALID` on success or
    /// `tidex6-day1-groth16:INVALID` on failure. Also logs
    /// `tidex6-day1-alt_bn128:OK` because a successful pairing result
    /// transitively validates Gate 3.
    /// Initialise a new shielded pool for the given denomination.
    /// Delegates to `pool::handle_init_pool`. See `pool.rs` and
    /// ADR-002 for the full rationale.
    pub fn init_pool(context: Context<InitPool>, denomination: u64) -> Result<()> {
        pool::handle_init_pool(context, denomination)
    }

    /// Deposit `commitment` into the pool, transferring
    /// `denomination` lamports from the payer into the vault PDA,
    /// updating the onchain Merkle root, and storing the Shielded
    /// Memo payload in the emitted `DepositEvent`.
    ///
    /// `memo_payload` must be the binary wire format produced by
    /// `tidex6_core::memo::MemoPayload::to_bytes` — concatenation
    /// of `ephemeral_pk || iv || tag || ciphertext`. The verifier
    /// does not attempt to decrypt or validate the memo
    /// cryptographically; it only enforces length bounds so an
    /// integrator program cannot inflate the instruction data
    /// beyond what a single deposit should cost.
    pub fn deposit(
        context: Context<Deposit>,
        commitment: [u8; FIELD_ELEMENT_BYTES],
        memo_payload: Vec<u8>,
    ) -> Result<()> {
        pool::handle_deposit(context, commitment, memo_payload)
    }

    /// Withdraw a previously-deposited note. The caller supplies a
    /// Groth16 `WithdrawCircuit<20>` proof plus the five public
    /// inputs committed to at proving time:
    ///
    /// 1. `merkle_root` — one of the recent roots from the pool's
    ///    ring buffer.
    /// 2. `nullifier_hash` — goes into a fresh per-nullifier PDA
    ///    that prevents double-spend.
    /// 3. `recipient` — the account that receives the withdrawn SOL
    ///    minus the relayer fee. Passed implicitly via
    ///    `ctx.accounts.recipient`; reduced onchain to a BN254
    ///    scalar before verification.
    /// 4. `relayer_address` — the account that receives the relayer
    ///    fee and is the fee-payer of this transaction. Passed
    ///    implicitly via `ctx.accounts.relayer`; reduced onchain to a
    ///    BN254 scalar. Added in ADR-011 so a front-runner cannot
    ///    swap the relayer in mempool to steal the fee.
    /// 5. `relayer_fee` — the SOL amount the verifier transfers from
    ///    the vault to `relayer_address`. Passed explicitly as the
    ///    `relayer_fee` instruction argument; the circuit binds the
    ///    specific value.
    ///
    /// The reference `tidex6-relayer` service always sets
    /// `relayer_fee = 0` and uses a single hardcoded pubkey for
    /// `relayer_address`; any third-party relayer may pick their
    /// own values.
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

    pub fn verify_test_proof(
        context: Context<VerifyTestProof>,
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
    ) -> Result<()> {
        let _ = context;

        let mut verifier =
            Groth16Verifier::<9>::new(&proof_a, &proof_b, &proof_c, &PUBLIC_INPUTS, &VERIFYING_KEY)
                .map_err(|_| Tidex6VerifierError::Groth16VerifierConstructFailed)?;

        match verifier.verify() {
            Ok(()) => {
                msg!("tidex6-day1-groth16:VALID");
                msg!("tidex6-day1-alt_bn128:OK");
                Ok(())
            }
            Err(_) => {
                msg!("tidex6-day1-groth16:INVALID");
                Err(Tidex6VerifierError::Groth16VerificationFailed.into())
            }
        }
    }
}

/// Encode 32 bytes as a lowercase hexadecimal string.
///
/// Deliberately avoids pulling in the `hex` crate so that the program
/// dependency graph stays as small as possible. Runs in O(64) with
/// negligible compute-unit cost.
fn encode_hex(bytes: [u8; 32]) -> String {
    encode_hex_bytes(&bytes)
}

/// Variable-length variant of [`encode_hex`], used for the memo
/// trailer in the `tidex6-deposit` log line. Same hex alphabet and
/// same compute profile — just walks any slice rather than a fixed
/// 32-byte array.
fn encode_hex_bytes(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_CHARS[(byte >> 4) as usize] as char);
        out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Accounts required by `hash_poseidon`.
///
/// The instruction is pure compute — it does not touch any program-owned
/// state, so the only required account is the fee payer. A future
/// production version will require a configuration PDA instead, but for
/// the Day-1 validation harness the minimum surface is correct.
#[derive(Accounts)]
pub struct HashPoseidon<'info> {
    pub payer: Signer<'info>,
}

/// Accounts for `init_pool`. Creates the `PoolState` PDA for a
/// given denomination and its companion vault PDA. Both seeds are
/// derived from the denomination so there is exactly one pool per
/// denomination on any given cluster.
///
/// `pool` uses `AccountLoader` because `PoolState` is a zero-copy
/// account — see the type definition in `pool.rs` for the rationale.
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

    /// CHECK: the vault is a system-owned PDA created here with a
    /// deterministic seed; lamports flow in via the system program
    /// and out via a seeded signer at withdrawal time. No further
    /// account-level validation is needed.
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

/// Accounts for `deposit`. The pool PDA and vault PDA are both
/// re-derived from the pool's denomination field at runtime so the
/// caller cannot confuse one denomination for another.
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        mut,
        seeds = [PoolState::POOL_SEED_PREFIX, &pool.load()?.denomination.to_le_bytes()],
        bump = pool.load()?.bump,
    )]
    pub pool: AccountLoader<'info, PoolState>,

    /// CHECK: vault is a known-seed system-owned PDA derived from
    /// the same denomination as `pool`. SOL flows into it via the
    /// system program.
    #[account(
        mut,
        seeds = [PoolState::VAULT_SEED_PREFIX, &pool.load()?.denomination.to_le_bytes()],
        bump,
    )]
    pub vault: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Accounts required by `verify_test_proof`. Same minimum surface as
/// `HashPoseidon` — pure compute, no program-owned state.
#[derive(Accounts)]
pub struct VerifyTestProof<'info> {
    pub payer: Signer<'info>,
}

/// Accounts for `withdraw`. The caller must pass the pool and its
/// companion vault, the nullifier PDA (created fresh — a second
/// attempt to use the same nullifier_hash fails the `init`), the
/// recipient account that will receive the main payout, the
/// `relayer` account that will receive the relayer fee (`relayer_fee`
/// lamports) and is the fee-payer of this transaction, and the
/// payer that funds the nullifier PDA rent.
///
/// `#[instruction(...)]` pulls in the same raw arguments the
/// handler receives so the nullifier PDA seed can reference
/// `nullifier_hash`. `proof_a`, `proof_b`, `proof_c`, `merkle_root`
/// and `relayer_fee` are unused at the account-constraint level —
/// they are only referenced inside the handler — but Anchor
/// requires every instruction argument ahead of `nullifier_hash` to
/// appear in the `#[instruction(...)]` list.
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

    /// CHECK: vault is a known-seed system-owned PDA derived from
    /// the same denomination as `pool`. Payout flows out of it via
    /// a seeded signer system-program CPI.
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

    /// CHECK: the recipient is any system account. Its pubkey is
    /// reduced modulo the BN254 scalar field and bound to the
    /// proof as a public input, so a front-runner who swaps this
    /// field invalidates the proof.
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,

    /// CHECK: the relayer account is any system account — typically
    /// the hot wallet of `relayer.tidex6.com` or a third-party
    /// relayer service. Its pubkey is reduced modulo the BN254
    /// scalar field and bound to the proof as the fourth public
    /// input (ADR-011), so a front-runner who swaps this field
    /// invalidates the proof.
    #[account(mut)]
    pub relayer: UncheckedAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum Tidex6VerifierError {
    #[msg("Unsupported Poseidon input count: must be between 1 and 12.")]
    UnsupportedInputCount,
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
    #[msg("Shielded Memo payload length is outside the accepted bounds.")]
    InvalidMemoPayloadLength,
    #[msg("Relayer fee must not exceed the pool denomination.")]
    InvalidRelayerFee,
}
