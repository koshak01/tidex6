//! Accountant-side scanner (v2, ADR-014): find and decrypt every memo
//! account whose auditor slot is addressed to a given ML-KEM secret.
//!
//! Unlike v1 (which read the SPL-memo / log payload via the indexer),
//! v2 stores each envelope in a dedicated `MemoAccount` PDA. The scanner
//! therefore pulls every memo account of the v2 program with
//! `getProgramAccounts`, decodes it, and tries
//! [`tidex6_core::envelope::open_as_auditor`] on each. The ML-KEM
//! `decapsulate` + AEAD tag is the "addressed to me" filter — a foreign
//! slot simply fails to decrypt and is skipped.
//!
//! The recipient (stealth) scan is the symmetric operation with
//! [`tidex6_core::envelope::open_as_recipient`]; see
//! [`RecipientScanner`].

use anchor_client::anchor_lang::prelude::Pubkey;
use anchor_client::anchor_lang::{AccountDeserialize, Discriminator};
use anyhow::{Context, Result};
use solana_account_decoder_client_types::UiAccountEncoding;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::config::{RpcAccountInfoConfig, RpcProgramAccountsConfig};
use solana_rpc_client_api::filter::{Memcmp, RpcFilterType};

use tidex6_core::envelope;
use tidex6_core::pqc::PqcSecretKey;
use tidex6_verifier_v2::MemoAccount;

/// One entry in the reconstructed ledger returned by
/// [`AccountantScanner::scan`].
#[derive(Clone, Debug)]
pub struct AccountantEntry {
    /// Lowercase hex of the deposit commitment.
    pub commitment_hex: String,
    /// The memo-account PDA the entry was decoded from.
    pub memo_account: Pubkey,
    /// Deposit amount in lamports (revealed to the auditor).
    pub denomination: u64,
    /// Decrypted memo plaintext bytes.
    pub plaintext: Vec<u8>,
}

impl AccountantEntry {
    /// Best-effort UTF-8 decoding of the memo.
    pub fn plaintext_lossy(&self) -> String {
        String::from_utf8_lossy(&self.plaintext).into_owned()
    }
}

/// Build the `getProgramAccounts` config that selects only finalized
/// `MemoAccount`s by their Anchor discriminator.
fn memo_accounts_config() -> RpcProgramAccountsConfig {
    RpcProgramAccountsConfig {
        filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
            0,
            MemoAccount::DISCRIMINATOR.to_vec(),
        ))]),
        account_config: RpcAccountInfoConfig {
            encoding: Some(UiAccountEncoding::Base64),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Decode a raw account into a [`MemoAccount`], or `None` if it is not
/// one (discriminator already filtered, but data may be truncated).
fn decode_memo(data: &[u8]) -> Option<MemoAccount> {
    MemoAccount::try_deserialize(&mut &data[..]).ok()
}

/// Auditor scanner: owns an RPC client and an auditor ML-KEM secret.
pub struct AccountantScanner<'a> {
    rpc: RpcClient,
    program_id: Pubkey,
    auditor_secret: &'a PqcSecretKey,
}

impl<'a> AccountantScanner<'a> {
    /// Build a scanner for the v2 program and one auditor secret.
    pub fn new(
        rpc_url: impl Into<String>,
        program_id: Pubkey,
        auditor_secret: &'a PqcSecretKey,
    ) -> Self {
        Self {
            rpc: RpcClient::new(rpc_url.into()),
            program_id,
            auditor_secret,
        }
    }

    /// Fetch every memo account and return the ones whose auditor slot
    /// decrypts under this secret.
    #[allow(deprecated)] // get_program_accounts_with_config: ui-variant would change the decode path
    pub fn scan(&self) -> Result<Vec<AccountantEntry>> {
        let accounts = self
            .rpc
            .get_program_accounts_with_config(&self.program_id, memo_accounts_config())
            .context("getProgramAccounts for memo accounts failed")?;

        let mut out = Vec::new();
        for (pubkey, account) in accounts {
            let Some(memo) = decode_memo(&account.data) else {
                continue;
            };
            if !memo.is_finalized {
                continue;
            }
            match envelope::open_as_auditor(&memo.data, self.auditor_secret) {
                Ok(Some(view)) => out.push(AccountantEntry {
                    commitment_hex: hex::encode(memo.commitment),
                    memo_account: pubkey,
                    denomination: view.denomination,
                    plaintext: view.memo,
                }),
                // No auditor slot for this key, or malformed — skip.
                Ok(None) => {}
                Err(_) => {}
            }
        }
        Ok(out)
    }
}

/// What a recipient recovers when scanning for their own payments: the
/// note's spend material plus the memo and amount. Enough to withdraw
/// without ever having been handed the note (stealth, A9).
#[derive(Clone, Debug)]
pub struct RecipientEntry {
    /// Lowercase hex of the deposit commitment.
    pub commitment_hex: String,
    /// The memo-account PDA the entry was decoded from.
    pub memo_account: Pubkey,
    /// Deposit amount in lamports — read from the memo account (the
    /// recipient slot itself does not carry it), needed to reconstruct
    /// the `DepositNote` and pick the right pool to withdraw from.
    pub denomination: u64,
    /// Note secret material — feed into a `DepositNote` to withdraw.
    pub secret: [u8; 32],
    pub nullifier: [u8; 32],
    /// Decrypted memo plaintext bytes.
    pub plaintext: Vec<u8>,
}

/// Recipient (stealth) scanner: symmetric to [`AccountantScanner`] but
/// opens the recipient slot, recovering the note's spend material.
pub struct RecipientScanner<'a> {
    rpc: RpcClient,
    program_id: Pubkey,
    recipient_secret: &'a PqcSecretKey,
}

impl<'a> RecipientScanner<'a> {
    /// Build a scanner for the v2 program and one recipient secret.
    pub fn new(
        rpc_url: impl Into<String>,
        program_id: Pubkey,
        recipient_secret: &'a PqcSecretKey,
    ) -> Self {
        Self {
            rpc: RpcClient::new(rpc_url.into()),
            program_id,
            recipient_secret,
        }
    }

    /// Fetch every memo account and return the ones whose recipient slot
    /// decrypts under this secret — i.e. the payments addressed to me.
    #[allow(deprecated)] // get_program_accounts_with_config: ui-variant would change the decode path
    pub fn scan(&self) -> Result<Vec<RecipientEntry>> {
        let accounts = self
            .rpc
            .get_program_accounts_with_config(&self.program_id, memo_accounts_config())
            .context("getProgramAccounts for memo accounts failed")?;

        let mut out = Vec::new();
        for (pubkey, account) in accounts {
            let Some(memo) = decode_memo(&account.data) else {
                continue;
            };
            if !memo.is_finalized {
                continue;
            }
            match envelope::open_as_recipient(&memo.data, self.recipient_secret) {
                Ok(Some(view)) => out.push(RecipientEntry {
                    commitment_hex: hex::encode(memo.commitment),
                    memo_account: pubkey,
                    denomination: memo.denomination,
                    secret: view.secret,
                    nullifier: view.nullifier,
                    plaintext: view.memo,
                }),
                Ok(None) => {}
                Err(_) => {}
            }
        }
        Ok(out)
    }
}
