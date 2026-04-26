//! [`PrivatePool`] — the top-level SDK handle for one shielded
//! pool on one cluster.
//!
//! A `PrivatePool` is:
//!   1. A cached `anchor-client::Program` handle against the
//!      `tidex6-verifier` program ID.
//!   2. A pair of derived PDAs — the `PoolState` account and its
//!      companion vault — for the specific denomination.
//!   3. A lazily-populated `PoolIndexer` for Merkle tree
//!      reconstruction (only built once the caller actually needs
//!      to withdraw).
//!
//! The handle itself is cheap to construct (no network I/O) and
//! cheap to clone — everything behind it is `Arc` or `Copy`. The
//! heavy work happens in `DepositBuilder::send` and
//! `WithdrawBuilder::send`.

use std::rc::Rc;

use anchor_client::anchor_lang::prelude::Pubkey;
use anchor_client::{Client, Cluster, CommitmentConfig};
use anyhow::{Context, Result, anyhow};
use solana_keypair::Keypair;

use tidex6_core::note::Denomination;
use tidex6_indexer::PoolIndexer;
use tidex6_verifier::PoolState;

use crate::deposit::DepositBuilder;
use crate::withdraw::WithdrawBuilder;

/// One shielded pool, scoped to one Solana cluster and one
/// denomination. Create one of these at dapp startup and reuse it
/// across every deposit / withdraw call.
pub struct PrivatePool {
    cluster: Cluster,
    denomination: Denomination,
    pool_pda: Pubkey,
    vault_pda: Pubkey,
    program_id: Pubkey,
}

impl PrivatePool {
    /// Build a pool handle for the given cluster and denomination.
    ///
    /// This does not make any network calls. The pool PDA and
    /// vault PDA are derived deterministically from the program
    /// ID and the denomination lamports value, and the Anchor
    /// client only opens a connection the first time it is
    /// actually used.
    pub fn connect(cluster: Cluster, denomination: Denomination) -> Result<Self> {
        let program_id = tidex6_verifier::ID;
        let denomination_lamports = denomination.lamports();

        let (pool_pda, _) = Pubkey::find_program_address(
            &[
                PoolState::POOL_SEED_PREFIX,
                &denomination_lamports.to_le_bytes(),
            ],
            &program_id,
        );
        let (vault_pda, _) = Pubkey::find_program_address(
            &[
                PoolState::VAULT_SEED_PREFIX,
                &denomination_lamports.to_le_bytes(),
            ],
            &program_id,
        );

        Ok(Self {
            cluster,
            denomination,
            pool_pda,
            vault_pda,
            program_id,
        })
    }

    /// Return the Solana cluster this pool is bound to.
    pub fn cluster(&self) -> &Cluster {
        &self.cluster
    }

    /// Return the denomination this pool accepts.
    pub fn denomination(&self) -> Denomination {
        self.denomination
    }

    /// Return the pool state PDA.
    pub fn pool_pda(&self) -> Pubkey {
        self.pool_pda
    }

    /// Return the vault PDA (holds user SOL while it is shielded).
    pub fn vault_pda(&self) -> Pubkey {
        self.vault_pda
    }

    /// Return the program ID the pool is bound to. Currently
    /// always equals `tidex6_verifier::ID`, exposed for symmetry.
    pub fn program_id(&self) -> Pubkey {
        self.program_id
    }

    /// Build an `anchor-client::Program` handle for `tidex6-verifier`
    /// using `payer` as the signer. The returned handle is short
    /// lived — rebuild it per operation rather than caching across
    /// calls, because Anchor's Client holds the signer internally.
    pub(crate) fn program_handle(
        &self,
        payer: &Keypair,
    ) -> Result<anchor_client::Program<Rc<Keypair>>> {
        let payer_handle = Rc::new(clone_keypair(payer));
        let client = Client::new_with_options(
            self.cluster.clone(),
            payer_handle,
            CommitmentConfig::confirmed(),
        );
        client
            .program(self.program_id)
            .context("construct Anchor program handle")
    }

    /// Build a fresh `PoolIndexer` bound to this pool's PDA and
    /// the current cluster's RPC URL. Used by the withdraw builder
    /// to rebuild the offchain Merkle tree, and by external
    /// integrators (e.g. tidex6-web's WASM withdraw flow) that need
    /// to fetch a Merkle path for a commitment without going through
    /// `WithdrawBuilder::send`.
    pub fn indexer(&self) -> PoolIndexer {
        PoolIndexer::new(self.cluster.url(), self.pool_pda)
    }

    /// Read the pool's current `next_leaf_index` by decoding the
    /// zero-copy layout of the PDA account. Returns `None` if the
    /// pool has not been initialised yet.
    pub fn next_leaf_index(&self, payer: &Keypair) -> Result<Option<u64>> {
        let program = self.program_handle(payer)?;
        let rpc = program.rpc();
        let Ok(account) = rpc.get_account(&self.pool_pda) else {
            return Ok(None);
        };
        if account.data.is_empty() {
            return Ok(None);
        }
        let data = &account.data[8..]; // skip Anchor discriminator
        if data.len() < 16 {
            return Err(anyhow!("pool account data too short: {} bytes", data.len()));
        }
        let next_leaf_index = u64::from_le_bytes(
            data[8..16]
                .try_into()
                .expect("next_leaf_index slice is 8 bytes"),
        );
        Ok(Some(next_leaf_index))
    }

    /// Start building a deposit. `payer` is the fee payer and the
    /// account whose SOL is debited.
    pub fn deposit<'a>(&'a self, payer: &'a Keypair) -> DepositBuilder<'a> {
        DepositBuilder::new(self, payer)
    }

    /// Start building a withdraw.
    pub fn withdraw<'a>(&'a self, payer: &'a Keypair) -> WithdrawBuilder<'a> {
        WithdrawBuilder::new(self, payer)
    }
}

/// Clone a Keypair by round-tripping through its byte form.
/// Solana's `Keypair` intentionally does not implement `Clone` —
/// this helper is the documented workaround.
pub(crate) fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::try_from(keypair.to_bytes().as_slice())
        .expect("round-tripping a Keypair through its byte form is infallible")
}
