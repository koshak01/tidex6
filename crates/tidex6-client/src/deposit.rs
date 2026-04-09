//! [`DepositBuilder`] — builder for a single shielded deposit.
//!
//! The builder is produced by [`PrivatePool::deposit`] and is
//! always consumed by [`DepositBuilder::send`] (non-chaining —
//! you cannot stage, inspect and then send; once `.send()` is
//! called the builder is gone). This is deliberate: a deposit
//! touches money, so the API is explicit and one-shot.

use std::rc::Rc;

use anchor_client::anchor_lang::prelude::Pubkey;
use anchor_client::anchor_lang::system_program;
use anyhow::{Context, Result, anyhow};
use solana_keypair::Keypair;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use solana_transaction_status::option_serializer::OptionSerializer;

use tidex6_core::note::DepositNote;
use tidex6_verifier::accounts as verifier_accounts;
use tidex6_verifier::instruction as verifier_instruction;

use crate::pool::PrivatePool;

/// Consumable builder for a deposit transaction.
///
/// Build via [`PrivatePool::deposit`], finish with `.send()`.
pub struct DepositBuilder<'a> {
    pool: &'a PrivatePool,
    payer: &'a Keypair,
    note: Option<DepositNote>,
}

impl<'a> DepositBuilder<'a> {
    pub(crate) fn new(pool: &'a PrivatePool, payer: &'a Keypair) -> Self {
        Self {
            pool,
            payer,
            note: None,
        }
    }

    /// Supply a caller-constructed `DepositNote`. Optional — if
    /// not set, `.send()` generates a fresh random note via
    /// `DepositNote::random`. Useful for tests that need
    /// deterministic notes.
    pub fn note(mut self, note: DepositNote) -> Self {
        self.note = Some(note);
        self
    }

    /// Send the deposit transaction.
    ///
    /// Behaviour:
    ///
    /// 1. If the pool has never been initialised on this cluster,
    ///    send an `init_pool` transaction first. The caller pays
    ///    the rent for both the `PoolState` PDA and the vault.
    /// 2. Generate a fresh `DepositNote` (unless one was supplied
    ///    via [`DepositBuilder::note`]).
    /// 3. Send the `deposit` transaction. The pool updates its
    ///    Merkle tree on-chain via the `sol_poseidon` syscall and
    ///    logs `tidex6-deposit:<leaf>:<commitment>:<root>` for the
    ///    indexer.
    /// 4. Parse the leaf index out of the transaction logs and
    ///    return it alongside the signature and the note the
    ///    caller should keep.
    ///
    /// Returns `(signature, note, leaf_index)`. The note must be
    /// preserved offline for the recipient to later redeem it.
    pub fn send(self) -> Result<(Signature, DepositNote, u64)> {
        let program = self.pool.program_handle(self.payer)?;
        let payer_pubkey = {
            use anchor_client::Signer;
            <Keypair as Signer>::pubkey(self.payer)
        };

        // Initialise the pool on first use.
        let denomination_lamports = self.pool.denomination().lamports();
        let rpc = program.rpc();
        let needs_init = rpc
            .get_account(&self.pool.pool_pda())
            .map(|account| account.data.is_empty())
            .unwrap_or(true);

        if needs_init {
            program
                .request()
                .accounts(verifier_accounts::InitPool {
                    pool: self.pool.pool_pda(),
                    vault: self.pool.vault_pda(),
                    payer: payer_pubkey,
                    system_program: system_program::ID,
                })
                .args(verifier_instruction::InitPool {
                    denomination: denomination_lamports,
                })
                .signer(self.payer)
                .send()
                .context("init_pool transaction failed to confirm")?;
        }

        // Generate or use the caller-supplied note.
        let note = match self.note {
            Some(note) => note,
            None => DepositNote::random(self.pool.denomination())
                .context("failed to generate a random deposit note")?,
        };
        let commitment = note.commitment();

        let signature = program
            .request()
            .accounts(verifier_accounts::Deposit {
                pool: self.pool.pool_pda(),
                vault: self.pool.vault_pda(),
                payer: payer_pubkey,
                system_program: system_program::ID,
            })
            .args(verifier_instruction::Deposit {
                commitment: commitment.to_bytes(),
            })
            .signer(self.payer)
            .send()
            .context("deposit transaction failed to confirm")?;

        // Pull the leaf index out of the transaction logs.
        let leaf_index = fetch_leaf_index(&program, &signature)?;

        Ok((signature, note, leaf_index))
    }
}

/// Fetch a transaction and parse its
/// `tidex6-deposit:<leaf>:<commitment>:<root>` log line.
fn fetch_leaf_index(
    program: &anchor_client::Program<Rc<Keypair>>,
    signature: &Signature,
) -> Result<u64> {
    let rpc = program.rpc();
    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(anchor_client::CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };

    let tx = rpc
        .get_transaction_with_config(signature, config)
        .context("get_transaction_with_config RPC call failed")?;
    let meta = tx
        .transaction
        .meta
        .as_ref()
        .ok_or_else(|| anyhow!("transaction meta is missing"))?;
    let logs: &[String] = match &meta.log_messages {
        OptionSerializer::Some(logs) => logs,
        _ => return Err(anyhow!("transaction meta has no log messages")),
    };

    const PREFIX: &str = "Program log: tidex6-deposit:";
    for line in logs {
        let Some(payload) = line.strip_prefix(PREFIX) else {
            continue;
        };
        let leaf_index_str = payload
            .split(':')
            .next()
            .ok_or_else(|| anyhow!("deposit log line is empty"))?;
        return leaf_index_str
            .parse::<u64>()
            .context("deposit log leaf index is not a number");
    }

    Err(anyhow!(
        "no tidex6-deposit log line in transaction:\n{}",
        logs.join("\n")
    ))
}

// Anchor client re-exports Pubkey under `anchor_lang::prelude`, so
// the `Pubkey` import above is the canonical one even though we do
// not use it directly — several doctests reference it for clarity.
#[allow(dead_code)]
type _PubkeyAlias = Pubkey;
