//! [`DepositBuilder`] — builder for a single shielded deposit.
//!
//! The builder is produced by [`PrivatePool::deposit`] and is
//! always consumed by [`DepositBuilder::send`] (non-chaining —
//! you cannot stage, inspect and then send; once `.send()` is
//! called the builder is gone). This is deliberate: a deposit
//! touches money, so the API is explicit and one-shot.
//!
//! Shielded Memo: set both [`DepositBuilder::with_auditor`] and
//! [`DepositBuilder::with_memo`] to attach an encrypted memo to the
//! deposit. The memo is encrypted under the auditor's Baby Jubjub
//! public key and passed to the onchain verifier program as a
//! regular instruction argument — the verifier stores the binary
//! payload in the emitted `DepositEvent` and in the program log
//! line, so the offchain indexer and accountant scanner can
//! retrieve it without needing a separate transport channel. See
//! ADR-007 (feature design) and ADR-010 rev.2 (why memo lives
//! inside the verifier program) for the rationale.

use std::rc::Rc;

use anchor_client::anchor_lang::prelude::Pubkey;
use anchor_client::anchor_lang::system_program;
use anyhow::{Context, Result, anyhow};
use solana_keypair::Keypair;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use solana_transaction_status::option_serializer::OptionSerializer;

use tidex6_core::elgamal::AuditorPublicKey;
use tidex6_core::memo::MemoPayload;
use tidex6_core::note::DepositNote;
use tidex6_verifier::accounts as verifier_accounts;
use tidex6_verifier::instruction as verifier_instruction;

use crate::pool::PrivatePool;

/// Outcome of a successful deposit. Grouping the fields into a struct
/// leaves room to add new optional signals without breaking every
/// call site.
#[derive(Debug, Clone)]
pub struct DepositOutcome {
    /// Signature of the confirmed deposit transaction.
    pub signature: Signature,
    /// The note the depositor must preserve offline to later redeem.
    pub note: DepositNote,
    /// Leaf index assigned by the verifier program.
    pub leaf_index: u64,
    /// Base64 encoding of the Shielded Memo payload that was sent
    /// to the verifier as part of the `deposit` instruction. Useful
    /// for the flight harness, for debugging, and for rebuilding
    /// the exact string the indexer will later surface. `None` if
    /// no memo was configured on the builder (in the MVP flow CLI
    /// always configures one, but the SDK keeps the field optional
    /// for integrators who build their own flows).
    pub memo_base64: Option<String>,
}

/// Consumable builder for a deposit transaction.
///
/// Build via [`PrivatePool::deposit`], finish with `.send()`.
pub struct DepositBuilder<'a> {
    pool: &'a PrivatePool,
    payer: &'a Keypair,
    note: Option<DepositNote>,
    auditor_pk: Option<AuditorPublicKey>,
    memo_plaintext: Option<String>,
}

impl<'a> DepositBuilder<'a> {
    pub(crate) fn new(pool: &'a PrivatePool, payer: &'a Keypair) -> Self {
        Self {
            pool,
            payer,
            note: None,
            auditor_pk: None,
            memo_plaintext: None,
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

    /// Address any memo attached to this deposit to the given auditor.
    ///
    /// The auditor's public key is published out of band (Telegram,
    /// email, QR code — whatever Lena and Kai agreed on). This builder
    /// does not validate that the auditor will actually have custody
    /// of the corresponding secret key; that is social.
    pub fn with_auditor(mut self, auditor_pk: AuditorPublicKey) -> Self {
        self.auditor_pk = Some(auditor_pk);
        self
    }

    /// Attach a human-readable memo to this deposit.
    ///
    /// The plaintext must be at most [`tidex6_core::memo::MAX_PLAINTEXT_LEN`]
    /// bytes and is encrypted under the auditor set via
    /// [`Self::with_auditor`]. Calling `.with_memo` without
    /// `.with_auditor` is a usage error and will return an error
    /// from `.send()` — we do not silently ship an unencrypted memo.
    pub fn with_memo(mut self, text: impl Into<String>) -> Self {
        self.memo_plaintext = Some(text.into());
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
    /// 3. Assemble a single transaction containing the `deposit`
    ///    instruction and, if a memo was configured, an SPL Memo
    ///    Program instruction carrying the encrypted payload.
    /// 4. Parse the leaf index out of the transaction logs and
    ///    return it alongside the signature, the note, and the
    ///    base64 memo (if any).
    ///
    /// Returns [`DepositOutcome`]. The `note` must be preserved
    /// offline for the recipient to later redeem it.
    pub fn send(self) -> Result<DepositOutcome> {
        if self.memo_plaintext.is_some() && self.auditor_pk.is_none() {
            return Err(anyhow!(
                "DepositBuilder::with_memo requires DepositBuilder::with_auditor; \
                 refusing to send an unencrypted memo"
            ));
        }

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

        // Generate or use the caller-supplied note. When a memo is
        // configured we stamp it into the note as well, so whoever
        // later receives the note file (parents, in the flagship
        // story) sees the same "Rent March 2026" text Kai sees after
        // decrypting the onchain SPL Memo.
        let note = match self.note {
            Some(note) => {
                // Caller supplied an explicit note. If they also set
                // a memo on the builder, overwrite whatever was on
                // the note with the fresh one — the builder is the
                // single source of truth for this send.
                match self.memo_plaintext.as_deref() {
                    Some(memo) => note
                        .with_memo(memo)
                        .context("memo rejected by DepositNote")?,
                    None => note,
                }
            }
            None => {
                let fresh = DepositNote::random(self.pool.denomination())
                    .context("failed to generate a random deposit note")?;
                match self.memo_plaintext.as_deref() {
                    Some(memo) => fresh
                        .with_memo(memo)
                        .context("memo rejected by DepositNote")?,
                    None => fresh,
                }
            }
        };
        let commitment = note.commitment();

        // Build the memo payload up front so its error (too-long
        // plaintext, CSPRNG failure) surfaces before the tx is built.
        // The payload is the binary wire format — the verifier
        // requires the raw bytes, not the base64 transport form.
        let memo_payload_bytes: Vec<u8> = match (&self.auditor_pk, &self.memo_plaintext) {
            (Some(pk), Some(text)) => MemoPayload::encrypt(pk, text.as_bytes())
                .context("failed to encrypt the Shielded Memo payload")?
                .to_bytes(),
            (Some(_), None) | (None, Some(_)) => {
                // `.with_memo` without `.with_auditor` is caught
                // earlier in `.send()` via an explicit error.
                // `.with_auditor` without `.with_memo` is a CLI
                // ergonomics concession — the caller forgot to
                // pass memo text. We require memo on-chain now, so
                // fall through to the empty-caller-memo branch to
                // signal this as a builder misuse.
                return Err(anyhow!(
                    "DepositBuilder: configure both .with_auditor() and .with_memo() \
                     — Shielded Memo is mandatory in the onchain verifier"
                ));
            }
            (None, None) => {
                // Caller did not configure a memo. The onchain
                // verifier requires `memo_payload`, so we cannot
                // silently send an empty `Vec<u8>` — the program
                // would reject on length bounds. Refuse here with
                // a clear diagnostic instead of bouncing off the
                // chain.
                return Err(anyhow!(
                    "DepositBuilder: Shielded Memo is mandatory; call \
                     .with_auditor(auditor_pk).with_memo(text) before .send()"
                ));
            }
        };
        let memo_base64 = MemoPayload::from_bytes(&memo_payload_bytes)
            .expect("payload we just serialised must re-parse")
            .to_base64();

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
                memo_payload: memo_payload_bytes,
            })
            .signer(self.payer)
            .send()
            .context("deposit transaction failed to confirm")?;

        // Pull the leaf index out of the transaction logs.
        let leaf_index = fetch_leaf_index(&program, &signature)?;

        Ok(DepositOutcome {
            signature,
            note,
            leaf_index,
            memo_base64: Some(memo_base64),
        })
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

/// Re-exported from anchor for documentation linking.
#[allow(dead_code)]
type _PubkeyAlias = Pubkey;
