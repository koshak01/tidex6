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

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;

use tidex6_core::elgamal::AuditorPublicKey;
use tidex6_core::memo::{MemoEnvelope, placeholder_envelope_for_anonymous, validate_memo_charset};
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
    /// Explicit opt-out: caller does not have an auditor and just
    /// wants to deposit without selective disclosure. The on-chain
    /// verifier still requires *some* memo bytes (length-bounded by
    /// ADR-012), so we attach a placeholder envelope that nobody can
    /// decrypt — generated via `tidex6_core::memo::placeholder_envelope_for_anonymous`.
    skip_memo: bool,
}

impl<'a> DepositBuilder<'a> {
    pub(crate) fn new(pool: &'a PrivatePool, payer: &'a Keypair) -> Self {
        Self {
            pool,
            payer,
            note: None,
            auditor_pk: None,
            memo_plaintext: None,
            skip_memo: false,
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

    /// Explicit opt-out from Shielded Memo: deposit without an
    /// auditor and without a human memo. The on-chain verifier still
    /// requires `memo_payload` bytes of valid length, so the builder
    /// substitutes a placeholder payload (encrypted under an
    /// ephemeral key dropped immediately, so the bytes are
    /// indistinguishable from a real memo but cryptographically
    /// undecryptable by anyone).
    ///
    /// Use when the depositor has no accountant in the loop — for
    /// example a self-payroll or a one-off self-test. Mutually
    /// exclusive with `.with_auditor` / `.with_memo`; if both paths
    /// are configured, `.send()` returns an error.
    pub fn without_memo(mut self) -> Self {
        self.skip_memo = true;
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
        // Memo and auditor are independent fields. Three valid modes:
        //   1. (memo, auditor) — memo plaintext goes into the note for
        //      the recipient AND is encrypted onchain for the auditor.
        //   2. (memo only)     — memo plaintext goes into the note for
        //      the recipient. Onchain we ship a placeholder payload
        //      because there is no auditor key to encrypt for. The
        //      recipient still reads the memo from the note file.
        //   3. (neither)       — anonymous deposit. Placeholder onchain,
        //      no memo in the note.
        //
        // The fourth combination — auditor without memo — is a usage
        // error: nothing to encrypt for them.
        if self.auditor_pk.is_some() && self.memo_plaintext.is_none() {
            return Err(anyhow!(
                "DepositBuilder::with_auditor without .with_memo() — there \
                 is no plaintext to encrypt for the auditor"
            ));
        }
        if self.skip_memo && (self.auditor_pk.is_some() || self.memo_plaintext.is_some()) {
            return Err(anyhow!(
                "DepositBuilder::without_memo is mutually exclusive with \
                 .with_auditor() / .with_memo(); pick one path"
            ));
        }

        // ADR-012 v2.5.9: charset whitelist (Latin + Cyrillic). Reject
        // emoji and CJK at the SDK boundary so the user gets a clear
        // error before we burn a transaction. The padded-plaintext
        // budget is fixed at MAX_PLAINTEXT_LEN bytes; multi-byte
        // emoji would otherwise eat the slot 4-bytes-per-glyph and
        // surprise users when their 60-char emoji message gets
        // refused for "PlaintextTooLong" deeper in the encrypt path.
        if let Some(ref text) = self.memo_plaintext {
            validate_memo_charset(text)
                .with_context(|| "memo contains an unsupported character (Latin + Cyrillic only)")?;
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

        // Generate or use the caller-supplied note. Per ADR-012 the
        // note is opaque and never carries a memo — the plaintext
        // lives only in the on-chain envelope, encrypted under a key
        // derived from the note's own secret material.
        let note = match self.note {
            Some(note) => note,
            None => DepositNote::random(self.pool.denomination())
                .context("failed to generate a random deposit note")?,
        };
        let commitment = note.commitment();

        // ADR-012: build an envelope-encrypted memo. Key derivation
        // is deterministic from the note's own material so the
        // recipient can always decrypt, and the auditor slot is
        // populated only when an auditor key is configured.
        let note_secret_bytes: &[u8; 32] = note.secret().as_bytes();
        let note_nullifier_bytes: &[u8; 32] = note.nullifier().as_bytes();
        let memo_payload_bytes: Vec<u8> = match (&self.auditor_pk, &self.memo_plaintext) {
            // (memo + auditor) — envelope with both wrap-K slots.
            (Some(pk), Some(text)) => MemoEnvelope::encrypt_for_recipient_and_auditor(
                text.as_bytes(),
                note_secret_bytes,
                note_nullifier_bytes,
                pk,
            )
            .context("failed to build recipient+auditor memo envelope")?
            .to_bytes(),
            // (memo only) — envelope readable only by the note holder.
            (None, Some(text)) => MemoEnvelope::encrypt_for_recipient_only(
                text.as_bytes(),
                note_secret_bytes,
                note_nullifier_bytes,
            )
            .context("failed to build recipient-only memo envelope")?
            .to_bytes(),
            // (auditor only) — caught earlier as an error.
            (Some(_), None) => unreachable!("validated at the top of send()"),
            // (neither) — anonymous deposit. Ship a random placeholder
            // envelope so the on-chain bytes are indistinguishable in
            // shape from real memos.
            (None, None) => {
                if self.skip_memo {
                    placeholder_envelope_for_anonymous()
                        .context("failed to build placeholder envelope")?
                } else {
                    return Err(anyhow!(
                        "DepositBuilder: configure .with_memo(text) for a \
                         memo-to-recipient deposit, or .without_memo() for \
                         an anonymous deposit"
                    ));
                }
            }
        };
        let memo_base64 = BASE64_STD.encode(&memo_payload_bytes);

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
