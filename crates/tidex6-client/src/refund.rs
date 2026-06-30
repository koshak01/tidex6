//! [`RefundBuilder`] — 30-day revoke (ADR-014).
//!
//! Produced by [`PrivatePool::refund`]. The depositor presents the note
//! they kept locally; the builder proves ownership on-chain (the
//! verifier checks `Poseidon(secret, nullifier) == commitment`), and if
//! the deposit's `revoke_window` has elapsed and the note was never
//! withdrawn, the deposit is returned and the note is permanently
//! spent. No ZK proof, no relayer — a plain signed instruction.

use anchor_client::anchor_lang::prelude::Pubkey;
use anchor_client::anchor_lang::system_program;
use anyhow::{Context, Result, anyhow};
use solana_keypair::Keypair;
use solana_signature::Signature;

use tidex6_core::note::DepositNote;
use tidex6_verifier_v2::accounts as verifier_accounts;
use tidex6_verifier_v2::instruction as verifier_instruction;

use crate::pool::PrivatePool;

/// Consumable builder for a refund (revoke) transaction.
pub struct RefundBuilder<'a> {
    pool: &'a PrivatePool,
    payer: &'a Keypair,
    note: Option<DepositNote>,
}

impl<'a> RefundBuilder<'a> {
    pub(crate) fn new(pool: &'a PrivatePool, payer: &'a Keypair) -> Self {
        Self {
            pool,
            payer,
            note: None,
        }
    }

    /// The note to reclaim. Required — the depositor kept it locally at
    /// deposit time precisely for this.
    pub fn note(mut self, note: DepositNote) -> Self {
        self.note = Some(note);
        self
    }

    /// Send the refund. The signer must be the original depositor; the
    /// reclaimed deposit and the memo-account rent both return to them.
    pub fn send(self) -> Result<Signature> {
        let note = self
            .note
            .ok_or_else(|| anyhow!("refund requires a note; call .note(note) first"))?;
        if note.denomination() != self.pool.denomination() {
            return Err(anyhow!(
                "note denomination {} does not match pool denomination {}",
                note.denomination(),
                self.pool.denomination()
            ));
        }

        let program = self.pool.program_handle(self.payer)?;
        let payer_pubkey = {
            use anchor_client::Signer;
            <Keypair as Signer>::pubkey(self.payer)
        };

        let commitment = note.commitment().to_bytes();
        let secret = *note.secret().as_bytes();
        let nullifier = *note.nullifier().as_bytes();
        let nullifier_hash = *note
            .nullifier()
            .derive_hash()
            .context("derive nullifier hash")?
            .as_bytes();

        let memo_pda = self.pool.memo_pda(&commitment);
        let (nullifier_pda, _bump) =
            Pubkey::find_program_address(&[b"nullifier", &nullifier_hash], &self.pool.program_id());

        let signature = program
            .request()
            .accounts(verifier_accounts::Refund {
                pool: self.pool.pool_pda(),
                vault: self.pool.vault_pda(),
                memo: memo_pda,
                nullifier: nullifier_pda,
                depositor: payer_pubkey,
                system_program: system_program::ID,
            })
            .args(verifier_instruction::Refund {
                commitment,
                secret,
                nullifier,
                nullifier_hash,
            })
            .signer(self.payer)
            .send()
            .context("refund transaction failed to confirm")?;

        Ok(signature)
    }
}
