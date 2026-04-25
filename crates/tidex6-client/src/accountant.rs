//! Accountant-side scanner: find and decrypt every memo addressed
//! to a given auditor secret key.
//!
//! This module is the kernel of both the `tidex6 accountant scan`
//! CLI command and the backend of the `/accountant/` page on
//! tidex6.com. Keeping it inside the SDK rather than the CLI means
//! every integrator — the official CLI, the web server, a custom
//! desktop tool — runs identical decryption logic and therefore
//! sees identical ledger output.
//!
//! # Algorithm
//!
//! 1. Ask the indexer for every `DepositRecord` the pool has ever
//!    seen. The indexer already filters failed transactions, sorts
//!    by leaf index, and extracts the SPL Memo payload from each
//!    deposit's companion instruction.
//! 2. For every record with a non-empty `memo_base64`, try to
//!    decrypt under the supplied `AuditorSecretKey`.
//! 3. On authentication-tag success, record the decrypted plaintext
//!    plus the metadata we already have (leaf index, denomination,
//!    timestamp, signature). On failure, skip silently — that memo
//!    is for some other auditor.
//!
//! The "filter for free" trick documented in `tidex6_core::memo`
//! keeps this loop cheap: AES-GCM rejects the wrong key in constant
//! time, so scanning ten thousand memos costs about ten thousand
//! ECDH operations plus ten thousand tag-check misses — roughly a
//! couple of seconds on a laptop.
//!
//! # What this module does *not* do
//!
//! - It does not validate memo plaintext schema. The plaintext is
//!   returned as raw bytes; the caller decides whether to parse it
//!   as JSON, text, CSV, or an invoice reference.
//! - It does not correlate a memo with a specific recipient wallet.
//!   That correlation only exists if Lena included a recipient
//!   label inside the plaintext memo itself.

use anchor_client::anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use tidex6_core::elgamal::AuditorSecretKey;
use tidex6_core::memo::MemoEnvelope;
use tidex6_indexer::{DepositRecord, PoolIndexer};

/// One entry in the reconstructed ledger returned by
/// [`AccountantScanner::scan`].
#[derive(Clone, Debug)]
pub struct AccountantEntry {
    /// Leaf index of the deposit in the pool's Merkle tree.
    pub leaf_index: u64,
    /// Lowercase hex of the deposit commitment. Lets the caller
    /// cross-reference with on-chain tooling if needed.
    pub commitment_hex: String,
    /// Transaction signature carrying the deposit and its memo.
    pub signature: String,
    /// Unix timestamp of the deposit block, if the RPC reported it.
    pub block_time: Option<i64>,
    /// Decrypted plaintext bytes. Typically a short UTF-8 note like
    /// `"Rent March 2026"`; always treated as bytes here so no
    /// encoding assumption is baked in.
    pub plaintext: Vec<u8>,
}

impl AccountantEntry {
    /// Best-effort UTF-8 decoding of the plaintext. Returns a lossy
    /// string rather than `None` because the accountant UI should
    /// always show *something* — unexpected bytes are the caller's
    /// signal that the entry was encoded differently than the usual
    /// text memo and deserves closer inspection.
    pub fn plaintext_lossy(&self) -> String {
        String::from_utf8_lossy(&self.plaintext).into_owned()
    }
}

/// Scanner driver. Owns a [`PoolIndexer`] and an auditor secret
/// for the duration of one scan.
pub struct AccountantScanner<'a> {
    indexer: PoolIndexer,
    auditor_sk: &'a AuditorSecretKey,
}

impl<'a> AccountantScanner<'a> {
    /// Build a scanner for one pool, one auditor.
    pub fn new(
        rpc_url: impl Into<String>,
        pool_pda: Pubkey,
        auditor_sk: &'a AuditorSecretKey,
    ) -> Self {
        Self {
            indexer: PoolIndexer::new(rpc_url, pool_pda),
            auditor_sk,
        }
    }

    /// Run the scan end-to-end and return every entry the auditor
    /// can decrypt.
    ///
    /// This is a single-shot, blocking call: it fetches the full
    /// pool history in chronological order and tries decryption on
    /// every memo. For a pool with tens of thousands of memos this
    /// is fast enough for a desktop CLI; beyond that, wrap the
    /// underlying [`PoolIndexer`] in a caching layer and call
    /// [`AccountantScanner::scan_from_history`] with the pre-fetched
    /// list.
    pub fn scan(&self) -> Result<Vec<AccountantEntry>> {
        let history = self
            .indexer
            .fetch_deposit_history()
            .context("failed to fetch pool deposit history")?;
        Ok(self.scan_from_history(&history))
    }

    /// Decryption-only path for callers who already have the deposit
    /// history in hand (the web service batches this across many
    /// auditors, and the flight harness uses it to run without a
    /// second RPC round trip).
    pub fn scan_from_history(&self, history: &[DepositRecord]) -> Vec<AccountantEntry> {
        let mut out = Vec::new();
        for record in history {
            let Some(memo_b64) = record.memo_base64.as_deref() else {
                continue;
            };
            // ADR-012: on-chain bytes are a MemoEnvelope. The auditor
            // slot is optional; envelopes without it (anonymous
            // deposits or recipient-only memos) silently skip here.
            let Ok(bytes) = BASE64_STD.decode(memo_b64) else {
                continue;
            };
            let Ok(envelope) = MemoEnvelope::from_bytes(&bytes) else {
                continue;
            };
            match envelope.decrypt_with_auditor(self.auditor_sk) {
                Ok(Some(plaintext)) => {
                    out.push(AccountantEntry {
                        leaf_index: record.leaf_index,
                        commitment_hex: record.commitment.to_hex(),
                        signature: record.signature.clone(),
                        block_time: record.block_time,
                        plaintext,
                    });
                }
                // No auditor slot, or slot not addressed to this key
                // — the dominant case. Skip silently (the "filter for
                // free" trick).
                Ok(None) => {}
                // Malformed inputs: skip rather than fail the whole
                // scan so a stray bad entry does not hide valid ones.
                Err(_) => {}
            }
        }
        out
    }
}
