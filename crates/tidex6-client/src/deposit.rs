//! [`DepositBuilder`] — v2 shielded deposit (ADR-014).
//!
//! Stealth model: the recipient is named by their **ML-KEM-768 public
//! key**, never by a Solana address. The deposit builds a multi-slot
//! envelope ([`tidex6_core::envelope`]) sealing the note's spend
//! material for the recipient and (optionally) the memo+amount for one
//! or more auditors, then stores it in a dedicated memo account written
//! in chunks (`deposit` + `append_memo`). The note itself is **never
//! handed over** — the recipient scans the chain, decrypts their slot,
//! and withdraws on their own.
//!
//! The depositor also picks a per-deposit `revoke_window` (seconds;
//! `0` = irrevocable): if the note is never withdrawn within it, the
//! depositor can `refund`.

use anchor_client::Instruction;
use anchor_client::anchor_lang::prelude::Pubkey;
use anchor_client::anchor_lang::system_program;
use anyhow::{Context, Result, anyhow};
use solana_keypair::Keypair;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use solana_transaction_status::option_serializer::OptionSerializer;

use tidex6_core::envelope;
use tidex6_core::memo::validate_memo_charset;
use tidex6_core::note::DepositNote;
use tidex6_core::pqc::PqcPublicKey;
use tidex6_verifier_v2::accounts as verifier_accounts;
use tidex6_verifier_v2::instruction as verifier_instruction;

use crate::pool::PrivatePool;

/// Maximum envelope bytes carried per transaction. Conservative: leaves
/// headroom for the commitment, the length/offset/revoke args, the
/// accounts and Anchor framing under the 1232-byte transaction limit.
const MEMO_CHUNK_LEN: usize = 800;

/// Outcome of a successful deposit.
#[derive(Debug, Clone)]
pub struct DepositOutcome {
    /// Signature of the confirmed `deposit` transaction (chunk 0).
    pub signature: Signature,
    /// The note. In the stealth flow the depositor does **not** send
    /// this anywhere — it is returned only so non-stealth callers and
    /// tests can keep it. The recipient recovers an equivalent note
    /// from the on-chain envelope.
    pub note: DepositNote,
    /// Leaf index assigned by the verifier program.
    pub leaf_index: u64,
    /// The dedicated memo-account PDA holding the ML-KEM envelope.
    pub memo_account: Pubkey,
}

/// Consumable builder for a v2 deposit. Build via
/// [`PrivatePool::deposit`], finish with `.send()`.
pub struct DepositBuilder<'a> {
    pool: &'a PrivatePool,
    payer: &'a Keypair,
    note: Option<DepositNote>,
    recipient_pqc: Option<PqcPublicKey>,
    auditor_pqcs: Vec<PqcPublicKey>,
    memo_plaintext: Option<String>,
    revoke_window_secs: i64,
}

impl<'a> DepositBuilder<'a> {
    pub(crate) fn new(pool: &'a PrivatePool, payer: &'a Keypair) -> Self {
        Self {
            pool,
            payer,
            note: None,
            recipient_pqc: None,
            auditor_pqcs: Vec::new(),
            memo_plaintext: None,
            revoke_window_secs: 0,
        }
    }

    /// Supply a caller-constructed note instead of generating a fresh
    /// random one. Mostly for tests needing determinism.
    pub fn note(mut self, note: DepositNote) -> Self {
        self.note = Some(note);
        self
    }

    /// Required. The stealth recipient's ML-KEM-768 public key. The
    /// note's spend material is sealed for this key; the recipient
    /// scans the chain and withdraws themselves.
    pub fn to_recipient(mut self, recipient_pqc: PqcPublicKey) -> Self {
        self.recipient_pqc = Some(recipient_pqc);
        self
    }

    /// Add an auditor (or regulator) ML-KEM public key. Each gets an
    /// envelope slot carrying `denomination + memo` only — they can see
    /// but not spend. Call multiple times for multiple auditors.
    pub fn with_auditor(mut self, auditor_pqc: PqcPublicKey) -> Self {
        self.auditor_pqcs.push(auditor_pqc);
        self
    }

    /// Attach a human-readable memo (Latin + Cyrillic only). Visible to
    /// the recipient and to every auditor slot.
    pub fn with_memo(mut self, text: impl Into<String>) -> Self {
        self.memo_plaintext = Some(text.into());
        self
    }

    /// Per-deposit revoke window in seconds. `0` (the default) makes the
    /// deposit irrevocable. After `revoke_window` seconds, if the note
    /// was never withdrawn, the depositor can `refund`.
    pub fn revoke_after(mut self, secs: i64) -> Self {
        self.revoke_window_secs = secs;
        self
    }

    /// Send the deposit: build the envelope, create the memo account
    /// with chunk 0, and append the remaining chunks.
    pub fn send(self) -> Result<DepositOutcome> {
        let recipient_pqc = self
            .recipient_pqc
            .clone()
            .ok_or_else(|| anyhow!("deposit requires .to_recipient(ml_kem_pubkey)"))?;

        if let Some(ref text) = self.memo_plaintext {
            validate_memo_charset(text).with_context(
                || "memo contains an unsupported character (Latin + Cyrillic only)",
            )?;
        }
        let memo_bytes: Vec<u8> = self
            .memo_plaintext
            .as_deref()
            .unwrap_or("")
            .as_bytes()
            .to_vec();

        let program = self.pool.program_handle(self.payer)?;
        let payer_pubkey = {
            use anchor_client::Signer;
            <Keypair as Signer>::pubkey(self.payer)
        };
        let denomination_lamports = self.pool.denomination().lamports();

        // Initialise the pool on first use.
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
        let commitment = note.commitment().to_bytes();

        // Build the multi-slot ML-KEM envelope (ADR-014).
        let envelope_bytes = envelope::build(
            &recipient_pqc,
            note.secret().as_bytes(),
            note.nullifier().as_bytes(),
            denomination_lamports,
            &memo_bytes,
            &self.auditor_pqcs,
        )
        .context("failed to build ML-KEM envelope")?;
        let total_len = envelope_bytes.len() as u32;
        let memo_account = self.pool.memo_pda(&commitment);

        // Deposit transaction carries chunk 0 and opens the memo account.
        let chunk0_end = MEMO_CHUNK_LEN.min(envelope_bytes.len());
        let chunk0 = envelope_bytes[..chunk0_end].to_vec();
        let signature = program
            .request()
            .accounts(verifier_accounts::Deposit {
                pool: self.pool.pool_pda(),
                vault: self.pool.vault_pda(),
                memo: memo_account,
                payer: payer_pubkey,
                system_program: system_program::ID,
            })
            .args(verifier_instruction::Deposit {
                commitment,
                memo_total_len: total_len,
                revoke_window: self.revoke_window_secs,
                memo_chunk: chunk0,
            })
            .signer(self.payer)
            .send()
            .context("deposit transaction failed to confirm")?;

        // Append the remaining envelope chunks.
        let mut offset = chunk0_end;
        while offset < envelope_bytes.len() {
            let end = (offset + MEMO_CHUNK_LEN).min(envelope_bytes.len());
            let chunk = envelope_bytes[offset..end].to_vec();
            program
                .request()
                .accounts(verifier_accounts::AppendMemo {
                    memo: memo_account,
                    depositor: payer_pubkey,
                })
                .args(verifier_instruction::AppendMemo {
                    commitment,
                    offset: offset as u32,
                    chunk,
                })
                .signer(self.payer)
                .send()
                .with_context(|| format!("append_memo transaction failed at offset {offset}"))?;
            offset = end;
        }

        let leaf_index = fetch_leaf_index(&program.rpc(), &signature)?;

        Ok(DepositOutcome {
            signature,
            note,
            leaf_index,
            memo_account,
        })
    }
}

/// Outcome of a [`PrivatePool::deposit_raw`]. Same as [`DepositOutcome`]
/// but carries no note — the caller (e.g. the browser wasm-prover) built
/// the note locally and keeps it; the server never saw the secret.
#[derive(Debug, Clone)]
pub struct DepositRawOutcome {
    pub signature: Signature,
    pub leaf_index: u64,
    pub memo_account: Pubkey,
}

impl PrivatePool {
    /// Submit a deposit whose `commitment` and ML-KEM `envelope_bytes`
    /// were built elsewhere — the browser generated the note and sealed
    /// the envelope, so the server pays and submits but never sees the
    /// secret material. Mirrors [`DepositBuilder::send`] minus
    /// note/envelope generation. Used by the web solana-service.
    pub fn deposit_raw(
        &self,
        payer: &Keypair,
        commitment: [u8; 32],
        envelope_bytes: Vec<u8>,
        revoke_window_secs: i64,
    ) -> Result<DepositRawOutcome> {
        let program = self.program_handle(payer)?;
        let payer_pubkey = {
            use anchor_client::Signer;
            <Keypair as Signer>::pubkey(payer)
        };
        let denomination_lamports = self.denomination().lamports();

        // Initialise the pool on first use.
        let rpc = program.rpc();
        let needs_init = rpc
            .get_account(&self.pool_pda())
            .map(|account| account.data.is_empty())
            .unwrap_or(true);
        if needs_init {
            program
                .request()
                .accounts(verifier_accounts::InitPool {
                    pool: self.pool_pda(),
                    vault: self.vault_pda(),
                    payer: payer_pubkey,
                    system_program: system_program::ID,
                })
                .args(verifier_instruction::InitPool {
                    denomination: denomination_lamports,
                })
                .signer(payer)
                .send()
                .context("init_pool transaction failed to confirm")?;
        }

        let memo_account = self.memo_pda(&commitment);
        let total_len = envelope_bytes.len() as u32;

        // Deposit transaction carries chunk 0 and opens the memo account.
        let chunk0_end = MEMO_CHUNK_LEN.min(envelope_bytes.len());
        let chunk0 = envelope_bytes[..chunk0_end].to_vec();
        let signature = program
            .request()
            .accounts(verifier_accounts::Deposit {
                pool: self.pool_pda(),
                vault: self.vault_pda(),
                memo: memo_account,
                payer: payer_pubkey,
                system_program: system_program::ID,
            })
            .args(verifier_instruction::Deposit {
                commitment,
                memo_total_len: total_len,
                revoke_window: revoke_window_secs,
                memo_chunk: chunk0,
            })
            .signer(payer)
            .send()
            .context("deposit transaction failed to confirm")?;

        // Append the remaining envelope chunks.
        let mut offset = chunk0_end;
        while offset < envelope_bytes.len() {
            let end = (offset + MEMO_CHUNK_LEN).min(envelope_bytes.len());
            let chunk = envelope_bytes[offset..end].to_vec();
            program
                .request()
                .accounts(verifier_accounts::AppendMemo {
                    memo: memo_account,
                    depositor: payer_pubkey,
                })
                .args(verifier_instruction::AppendMemo {
                    commitment,
                    offset: offset as u32,
                    chunk,
                })
                .signer(payer)
                .send()
                .with_context(|| format!("append_memo transaction failed at offset {offset}"))?;
            offset = end;
        }

        let leaf_index = fetch_leaf_index(&program.rpc(), &signature)?;

        Ok(DepositRawOutcome {
            signature,
            leaf_index,
            memo_account,
        })
    }
}

/// One Solana account reference in a serialisable instruction recipe.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IxAccount {
    /// base58 account pubkey.
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

/// One instruction as a recipe the browser rebuilds with `@solana/web3.js`.
/// `data_hex` is Anchor's borsh-encoded instruction data (8-byte
/// discriminator + args) — already a `Vec<u8>`, no serialisation needed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IxRecipe {
    /// base58 program id.
    pub program_id: String,
    pub accounts: Vec<IxAccount>,
    pub data_hex: String,
}

/// An unsigned deposit plan: a list of transactions, each a list of
/// instruction recipes. The browser assembles each transaction with
/// web3.js, sets fee-payer = the depositor and a recent blockhash, signs
/// them all with Phantom, and submits **in order** — `append_memo`
/// instructions depend on the memo account opened by the first (deposit)
/// transaction. No wire serialisation happens server-side: web3.js builds
/// and serialises the transactions in the browser.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DepositPlan {
    pub transactions: Vec<Vec<IxRecipe>>,
}

impl PrivatePool {
    /// Build the instruction recipe for a v2 deposit paid by
    /// `payer_pubkey` — the depositor's own wallet. The browser turns
    /// this into web3.js transactions, has Phantom sign + send them, and
    /// funds the deposit with the depositor's own SOL. The relayer that
    /// calls this never signs and never funds the deposit (correctness,
    /// not just privacy — the depositor's SOL must fund the pool).
    pub fn build_deposit_plan(
        &self,
        payer_pubkey: Pubkey,
        commitment: [u8; 32],
        envelope_bytes: Vec<u8>,
        revoke_window_secs: i64,
    ) -> Result<DepositPlan> {
        // program_handle needs a Keypair for the Anchor Client, but we
        // only call `.instructions()` (never `.send()`), so the signer is
        // never used — the account fields carry `payer_pubkey`.
        let throwaway = Keypair::new();
        let program = self.program_handle(&throwaway)?;
        let rpc = program.rpc();
        let denomination_lamports = self.denomination().lamports();

        let needs_init = rpc
            .get_account(&self.pool_pda())
            .map(|account| account.data.is_empty())
            .unwrap_or(true);

        let memo_account = self.memo_pda(&commitment);
        let total_len = envelope_bytes.len() as u32;
        let chunk0_end = MEMO_CHUNK_LEN.min(envelope_bytes.len());

        // tx0: optional init_pool, then the deposit that opens the memo.
        let mut tx0_ixs: Vec<Instruction> = Vec::new();
        if needs_init {
            tx0_ixs.extend(
                program
                    .request()
                    .accounts(verifier_accounts::InitPool {
                        pool: self.pool_pda(),
                        vault: self.vault_pda(),
                        payer: payer_pubkey,
                        system_program: system_program::ID,
                    })
                    .args(verifier_instruction::InitPool {
                        denomination: denomination_lamports,
                    })
                    .instructions(),
            );
        }
        tx0_ixs.extend(
            program
                .request()
                .accounts(verifier_accounts::Deposit {
                    pool: self.pool_pda(),
                    vault: self.vault_pda(),
                    memo: memo_account,
                    payer: payer_pubkey,
                    system_program: system_program::ID,
                })
                .args(verifier_instruction::Deposit {
                    commitment,
                    memo_total_len: total_len,
                    revoke_window: revoke_window_secs,
                    memo_chunk: envelope_bytes[..chunk0_end].to_vec(),
                })
                .instructions(),
        );

        // One append_memo tx per remaining chunk.
        let mut tx_ix_sets: Vec<Vec<Instruction>> = vec![tx0_ixs];
        let mut offset = chunk0_end;
        while offset < envelope_bytes.len() {
            let end = (offset + MEMO_CHUNK_LEN).min(envelope_bytes.len());
            tx_ix_sets.push(
                program
                    .request()
                    .accounts(verifier_accounts::AppendMemo {
                        memo: memo_account,
                        depositor: payer_pubkey,
                    })
                    .args(verifier_instruction::AppendMemo {
                        commitment,
                        offset: offset as u32,
                        chunk: envelope_bytes[offset..end].to_vec(),
                    })
                    .instructions(),
            );
            offset = end;
        }

        let transactions = tx_ix_sets
            .iter()
            .map(|ixs| ixs.iter().map(ix_to_recipe).collect())
            .collect();
        Ok(DepositPlan { transactions })
    }
}

/// Convert an Anchor-built [`Instruction`] into a browser-rebuildable
/// recipe. `data` is already borsh bytes; we only hex-encode it.
fn ix_to_recipe(ix: &Instruction) -> IxRecipe {
    IxRecipe {
        program_id: ix.program_id.to_string(),
        accounts: ix
            .accounts
            .iter()
            .map(|meta| IxAccount {
                pubkey: meta.pubkey.to_string(),
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            })
            .collect(),
        data_hex: hex::encode(&ix.data),
    }
}

/// Fetch a transaction and parse its
/// `tidex6-v2-deposit:<leaf>:<commitment>:<root>` log line.
fn fetch_leaf_index(rpc: &RpcClient, signature: &Signature) -> Result<u64> {
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

    const PREFIX: &str = "Program log: tidex6-v2-deposit:";
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
        "no tidex6-v2-deposit log line in transaction:\n{}",
        logs.join("\n")
    ))
}
