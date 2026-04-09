//! [`WithdrawBuilder`] — builder for a single shielded withdrawal.
//!
//! Mirror of [`crate::deposit::DepositBuilder`] for the spend
//! side. Produced by [`PrivatePool::withdraw`], consumed by
//! [`WithdrawBuilder::send`]. Under the hood the builder:
//!
//! 1. Rebuilds the offchain Merkle tree from chain history via
//!    [`tidex6_indexer::PoolIndexer`]. On a pool with thousands of
//!    deposits this is the slowest step (one RPC call per tx).
//! 2. Loads the cached `WithdrawCircuit<20>` proving key unless
//!    the caller supplied their own via
//!    [`WithdrawBuilder::proving_key`].
//! 3. Generates a Groth16 proof with `prove_withdraw`.
//! 4. Converts the proof into the `groth16-solana` byte layout.
//! 5. Derives the per-nullifier PDA and submits the `withdraw`
//!    transaction.

use std::fs;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use anchor_client::anchor_lang::prelude::Pubkey;
use anchor_client::anchor_lang::system_program;
use anyhow::{Context, Result, anyhow};
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use solana_keypair::Keypair;
use solana_signature::Signature;

use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::withdraw::{WITHDRAW_TREE_DEPTH, WithdrawWitness, prove_withdraw};
use tidex6_core::note::DepositNote;
use tidex6_core::types::Commitment;
use tidex6_verifier::accounts as verifier_accounts;
use tidex6_verifier::instruction as verifier_instruction;

use crate::pool::PrivatePool;

/// Consumable builder for a withdraw transaction.
pub struct WithdrawBuilder<'a> {
    pool: &'a PrivatePool,
    payer: &'a Keypair,
    note: Option<DepositNote>,
    recipient: Option<Pubkey>,
    proving_key: Option<Arc<ProvingKey<Bn254>>>,
    pk_path: Option<PathBuf>,
}

impl<'a> WithdrawBuilder<'a> {
    pub(crate) fn new(pool: &'a PrivatePool, payer: &'a Keypair) -> Self {
        Self {
            pool,
            payer,
            note: None,
            recipient: None,
            proving_key: None,
            pk_path: None,
        }
    }

    /// Set the note to redeem. Required.
    pub fn note(mut self, note: DepositNote) -> Self {
        self.note = Some(note);
        self
    }

    /// Set the recipient account that will receive the payout.
    /// Required.
    pub fn to(mut self, recipient: Pubkey) -> Self {
        self.recipient = Some(recipient);
        self
    }

    /// Supply a pre-loaded proving key. Use this to avoid
    /// deserialising the ~50 MB PK on every withdraw when the
    /// caller is going to do several in a row. Pass
    /// `Arc::clone(&pk)` so multiple withdraws share the same
    /// object.
    pub fn proving_key(mut self, pk: Arc<ProvingKey<Bn254>>) -> Self {
        self.proving_key = Some(pk);
        self
    }

    /// Override the default PK file path. Useful for tests that
    /// load the PK from a non-default artifact directory, and for
    /// CLI tools running from a working directory other than the
    /// workspace root.
    pub fn proving_key_path(mut self, path: PathBuf) -> Self {
        self.pk_path = Some(path);
        self
    }

    /// Send the withdraw transaction. Returns the tx signature.
    pub fn send(self) -> Result<Signature> {
        let note = self
            .note
            .ok_or_else(|| anyhow!("withdraw requires a note; call .note(note) first"))?;
        let recipient = self
            .recipient
            .ok_or_else(|| anyhow!("withdraw requires a recipient; call .to(pubkey) first"))?;
        if note.denomination() != self.pool.denomination() {
            return Err(anyhow!(
                "note denomination {} does not match pool denomination {}",
                note.denomination(),
                self.pool.denomination()
            ));
        }

        // Load or reuse the proving key.
        let pk = match self.proving_key {
            Some(pk) => pk,
            None => {
                let path = match self.pk_path {
                    Some(path) => path,
                    None => default_pk_path()?,
                };
                Arc::new(load_pk_from_disk(&path)?)
            }
        };

        // Rebuild the offchain Merkle tree from chain history.
        let indexer = self.pool.indexer();
        let (tree, merkle_root) = indexer
            .rebuild_tree(WITHDRAW_TREE_DEPTH)
            .context("rebuild offchain Merkle tree from program logs")?;

        // Find the leaf index for our commitment.
        let commitment = Commitment::from_bytes(note.commitment().to_bytes());
        let leaf_index = indexer
            .find_leaf_index(&commitment)
            .context("find leaf index for commitment")?
            .ok_or_else(|| {
                anyhow!(
                    "commitment {} not found in pool history — note not yet on-chain",
                    commitment.to_hex()
                )
            })?;

        let merkle_proof = tree
            .proof(leaf_index)
            .context("build merkle proof for leaf")?;

        let nullifier_hash = note
            .nullifier()
            .derive_hash()
            .context("derive nullifier hash")?;

        // Build the circuit witness.
        let sibling_byte_arrays: Vec<[u8; 32]> = merkle_proof
            .siblings
            .iter()
            .map(|c| *c.as_bytes())
            .collect();
        if sibling_byte_arrays.len() != WITHDRAW_TREE_DEPTH {
            return Err(anyhow!(
                "Merkle proof depth {} does not match WITHDRAW_TREE_DEPTH {}",
                sibling_byte_arrays.len(),
                WITHDRAW_TREE_DEPTH
            ));
        }
        let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] =
            std::array::from_fn(|i| &sibling_byte_arrays[i]);

        let mut path_indices = [false; WITHDRAW_TREE_DEPTH];
        for (i, bit) in path_indices.iter_mut().enumerate() {
            *bit = (leaf_index >> i) & 1 == 1;
        }

        let recipient_bytes = recipient.to_bytes();
        let merkle_root_bytes: [u8; 32] = merkle_root.to_bytes();
        let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
            secret: note.secret().as_bytes(),
            nullifier: note.nullifier().as_bytes(),
            path_siblings: sibling_refs,
            path_indices,
            merkle_root: &merkle_root_bytes,
            nullifier_hash: nullifier_hash.as_bytes(),
            recipient: &recipient_bytes,
        };

        // Deterministic prover RNG for reproducibility. The proof
        // is still zero-knowledge because the witness itself
        // contains fresh secret material from the depositor.
        let mut rng = StdRng::seed_from_u64(0xc1_10_0b_a5_u64);
        let (proof, _public_inputs) =
            prove_withdraw::<WITHDRAW_TREE_DEPTH, _>(&pk, witness, &mut rng).context("prove")?;

        // Convert the proof to the byte layout the onchain
        // `groth16-solana` verifier expects.
        let solana_bytes =
            groth16_to_solana_bytes(&proof, &pk.vk).context("convert proof to solana bytes")?;
        let Groth16SolanaBytes {
            proof_a,
            proof_b,
            proof_c,
            ..
        } = &solana_bytes;

        // Derive the per-nullifier PDA and send the withdraw tx.
        let program = self.pool.program_handle(self.payer)?;
        let payer_pubkey = {
            use anchor_client::Signer;
            <Keypair as Signer>::pubkey(self.payer)
        };
        let (nullifier_pda, _bump) = Pubkey::find_program_address(
            &[b"nullifier", nullifier_hash.as_bytes()],
            &self.pool.program_id(),
        );

        let signature = program
            .request()
            .accounts(verifier_accounts::Withdraw {
                pool: self.pool.pool_pda(),
                vault: self.pool.vault_pda(),
                nullifier: nullifier_pda,
                recipient,
                payer: payer_pubkey,
                system_program: system_program::ID,
            })
            .args(verifier_instruction::Withdraw {
                proof_a: *proof_a,
                proof_b: *proof_b,
                proof_c: *proof_c,
                merkle_root: merkle_root_bytes,
                nullifier_hash: *nullifier_hash.as_bytes(),
            })
            .signer(self.payer)
            .send()
            .context("withdraw transaction failed to confirm")?;

        Ok(signature)
    }
}

/// Compute the default location for the cached `WithdrawCircuit<20>`
/// proving key. Walks up from `CARGO_MANIFEST_DIR` until it finds
/// the workspace root.
fn default_pk_path() -> Result<PathBuf> {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut current = start.clone();
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.exists() {
            let text = fs::read_to_string(&candidate).unwrap_or_default();
            if text.contains("[workspace]") {
                return Ok(current.join("crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin"));
            }
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => {
                return Err(anyhow!(
                    "could not find workspace root starting from {}",
                    start.display()
                ));
            }
        }
    }
}

/// Deserialise a cached `WithdrawCircuit<20>` proving key from
/// disk. The PK was generated once by `gen_withdraw_vk` with a
/// fixed seed so its bytes are reproducible across machines.
fn load_pk_from_disk(path: &PathBuf) -> Result<ProvingKey<Bn254>> {
    let bytes =
        fs::read(path).with_context(|| format!("read proving key from {}", path.display()))?;
    ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&bytes[..])
        .map_err(|err| anyhow!("deserialize proving key: {err}"))
}

// Keep `Rc` in the use-list even though it is only referenced in
// the type of `program_handle` — without this the import is
// considered unused by rustc.
#[allow(dead_code)]
type _RcAlias = Rc<()>;
