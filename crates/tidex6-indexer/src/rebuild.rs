//! Pool history scanner and offchain Merkle tree rebuilder.
//!
//! Usage pattern:
//!
//! ```ignore
//! use anchor_client::anchor_lang::prelude::Pubkey;
//! use tidex6_indexer::PoolIndexer;
//!
//! let indexer = PoolIndexer::new("https://api.devnet.solana.com", pool_pda);
//! let history = indexer.fetch_deposit_history()?;
//! let (tree, _root) = indexer.rebuild_tree(20)?;
//! // tree.proof(leaf_index) — ready for the withdraw circuit
//! ```
//!
//! The indexer walks `getSignaturesForAddress` for the pool PDA
//! from newest to oldest (the Solana API only supports this
//! direction), collects every signature the pool account touched,
//! fetches each transaction and scans its program logs for the
//! `tidex6-deposit:<leaf>:<commitment>:<root>` line. Each parsed
//! entry becomes one `DepositRecord`. The records are then sorted
//! by `leaf_index` ascending — the only ground-truth ordering,
//! since the onchain program assigns leaf indices strictly
//! sequentially regardless of tx scheduling.

use std::str::FromStr;

use anchor_client::CommitmentConfig;
use anchor_client::anchor_lang::prelude::Pubkey;
use solana_rpc_client::rpc_client::{GetConfirmedSignaturesForAddress2Config, RpcClient};
use solana_rpc_client_api::client_error::Error as RpcError;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_transaction_status::option_serializer::OptionSerializer;
use solana_transaction_status::{EncodedTransaction, UiMessage, UiTransactionEncoding};

use tidex6_core::merkle::{MerkleError, MerkleTree};
use tidex6_core::types::{Commitment, MerkleRoot};

/// One reconstructed deposit. The onchain program assigns
/// `leaf_index` atomically inside `handle_deposit`, so this is the
/// single source of truth for ordering even if the RPC returns
/// signatures in a different order than the leaves were inserted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DepositRecord {
    /// Position of this deposit in the append-only Merkle tree.
    pub leaf_index: u64,
    /// The commitment that was inserted as this leaf.
    pub commitment: Commitment,
    /// The Merkle root the onchain program reported after inserting
    /// this leaf. Useful for cross-checking: after replaying the
    /// same sequence offchain, our `MerkleTree.root()` should match
    /// `onchain_root` for the last record.
    pub onchain_root: MerkleRoot,
    /// Transaction signature that carried the deposit. Printed in
    /// CLI output and used for debugging, not load-bearing.
    pub signature: String,
    /// If this deposit carried a Shielded Memo, the raw base64
    /// string decoded out of the companion SPL Memo instruction.
    /// Decryption is the caller's job — the indexer deliberately
    /// stays crypto-agnostic so it can be reused by tooling that
    /// only cares about commitments.
    pub memo_base64: Option<String>,
    /// Unix timestamp reported by the cluster for this deposit's
    /// block, in seconds since the epoch. `None` when the RPC has
    /// not yet caught up with a block-time for the slot (rare).
    pub block_time: Option<i64>,
}

/// Errors produced while reconstructing pool history.
#[derive(Debug, thiserror::Error)]
pub enum IndexerError {
    /// Failed to talk to the Solana RPC endpoint.
    #[error("RPC call failed: {0}")]
    Rpc(String),

    /// A deposit log line was malformed or truncated.
    #[error("malformed deposit log line: {0}")]
    MalformedLog(String),

    /// Two deposit records reported the same leaf index — the
    /// onchain program would never emit this, so the reconstruction
    /// cannot proceed.
    #[error("duplicate leaf index {0} in pool history")]
    DuplicateLeafIndex(u64),

    /// Replaying the deposits into an offchain Merkle tree failed
    /// (e.g., the tree was full or Poseidon hashing errored out).
    #[error("offchain merkle replay failed: {0}")]
    MerkleReplay(#[from] MerkleError),
}

/// Walks the transaction history of one shielded pool PDA and
/// reconstructs the full offchain Merkle tree from program logs.
pub struct PoolIndexer {
    rpc_url: String,
    pool_pda: Pubkey,
}

impl PoolIndexer {
    /// Construct an indexer for a specific pool. The indexer uses
    /// its own RPC client (configured with `confirmed` commitment)
    /// so it does not share state with anchor-client's program
    /// handle.
    pub fn new(rpc_url: impl Into<String>, pool_pda: Pubkey) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            pool_pda,
        }
    }

    fn rpc(&self) -> RpcClient {
        RpcClient::new_with_commitment(self.rpc_url.clone(), CommitmentConfig::confirmed())
    }

    /// Fetch every deposit this pool has ever received, in
    /// `leaf_index`-ascending order.
    ///
    /// Pagination: `get_signatures_for_address` returns at most
    /// 1000 signatures per call and only in reverse-chronological
    /// order. We page backwards using `before = oldest_seen` until
    /// an empty page comes back, then sort by leaf_index ascending.
    /// For an MVP shielded pool with fewer than a few thousand
    /// deposits this is fine; a larger deployment would persist
    /// the history to a database and only replay the suffix.
    pub fn fetch_deposit_history(&self) -> Result<Vec<DepositRecord>, IndexerError> {
        let rpc = self.rpc();

        let mut records: Vec<DepositRecord> = Vec::new();
        let mut before: Option<solana_signature::Signature> = None;

        loop {
            let config = GetConfirmedSignaturesForAddress2Config {
                before,
                until: None,
                limit: Some(1000),
                commitment: Some(CommitmentConfig::confirmed()),
            };

            let page = rpc
                .get_signatures_for_address_with_config(&self.pool_pda, config)
                .map_err(|err: RpcError| IndexerError::Rpc(err.to_string()))?;

            if page.is_empty() {
                break;
            }

            // Remember the oldest signature in this page so the
            // next iteration continues strictly older than it.
            let oldest_signature_str = page
                .last()
                .map(|entry| entry.signature.clone())
                .expect("non-empty page has a last element");

            for entry in page {
                // Skip failed transactions — they never emit the
                // deposit log line and would produce phantom
                // entries.
                if entry.err.is_some() {
                    continue;
                }

                let signature = solana_signature::Signature::from_str(&entry.signature)
                    .map_err(|err| IndexerError::MalformedLog(format!("signature parse: {err}")))?;
                let Some(record) = self.fetch_and_parse_one(&rpc, &signature)? else {
                    continue;
                };
                records.push(record);
            }

            before = Some(
                solana_signature::Signature::from_str(&oldest_signature_str)
                    .map_err(|err| IndexerError::MalformedLog(format!("signature parse: {err}")))?,
            );
        }

        // Sort by leaf_index ascending — the only ground-truth
        // ordering.
        records.sort_by_key(|record| record.leaf_index);

        // Detect duplicate leaf indices (would indicate a bug or
        // RPC double-count).
        for window in records.windows(2) {
            if window[0].leaf_index == window[1].leaf_index {
                return Err(IndexerError::DuplicateLeafIndex(window[0].leaf_index));
            }
        }

        Ok(records)
    }

    /// Fetch a single transaction by signature and try to extract
    /// its deposit log line. Returns `Ok(None)` if the transaction
    /// is not a deposit (no matching log prefix), which is the
    /// common case for init_pool and withdraw transactions that
    /// also touch the pool PDA.
    fn fetch_and_parse_one(
        &self,
        rpc: &RpcClient,
        signature: &solana_signature::Signature,
    ) -> Result<Option<DepositRecord>, IndexerError> {
        let config = RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::Json),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        };

        let tx = rpc
            .get_transaction_with_config(signature, config)
            .map_err(|err: RpcError| IndexerError::Rpc(err.to_string()))?;

        let block_time = tx.block_time;

        let Some(meta) = tx.transaction.meta.as_ref() else {
            return Ok(None);
        };
        let logs: &[String] = match &meta.log_messages {
            OptionSerializer::Some(logs) => logs,
            _ => return Ok(None),
        };

        let Some((leaf_index, commitment, root)) = parse_deposit_log(logs) else {
            return Ok(None);
        };

        // Scan the transaction's instructions for an SPL Memo
        // Program instruction carrying the companion Shielded Memo.
        // Returns the first one found if any — our DepositBuilder
        // only ever attaches a single memo per deposit.
        let memo_base64 = extract_memo_instruction(&tx.transaction.transaction);

        Ok(Some(DepositRecord {
            leaf_index,
            commitment: Commitment::from_bytes(commitment),
            onchain_root: MerkleRoot::from_bytes(root),
            signature: signature.to_string(),
            memo_base64,
            block_time,
        }))
    }

    /// Replay every deposit in pool history into a fresh offchain
    /// `MerkleTree`. Returns the rebuilt tree plus its current root
    /// (identical to the most recent onchain root for that pool).
    ///
    /// The caller should compare this root against the pool's
    /// `root_history` ring buffer before generating a withdraw
    /// proof — if they mismatch, the indexer missed a deposit and
    /// the proof would be rejected onchain.
    pub fn rebuild_tree(&self, depth: usize) -> Result<(MerkleTree, MerkleRoot), IndexerError> {
        let history = self.fetch_deposit_history()?;
        let mut tree = MerkleTree::new(depth)?;
        let mut root = tree.root();

        for record in &history {
            let (inserted_index, new_root) = tree.insert(record.commitment)?;
            if inserted_index != record.leaf_index {
                return Err(IndexerError::MalformedLog(format!(
                    "replay mismatch: expected leaf_index {}, tree gave {}",
                    record.leaf_index, inserted_index
                )));
            }
            root = new_root;
        }

        Ok((tree, root))
    }

    /// Find the `leaf_index` for a specific commitment by scanning
    /// the full deposit history. Returns `None` if the commitment
    /// has never been seen — meaning either the note is fake or
    /// the indexer is behind and needs another pass.
    pub fn find_leaf_index(&self, commitment: &Commitment) -> Result<Option<u64>, IndexerError> {
        let history = self.fetch_deposit_history()?;
        Ok(history
            .into_iter()
            .find(|record| record.commitment == *commitment)
            .map(|record| record.leaf_index))
    }
}

/// Parse the `tidex6-deposit:<leaf_index>:<commitment_hex>:<root_hex>`
/// log line out of a transaction's program-log output. Returns
/// `None` if the log line is not present (e.g., this tx is not a
/// deposit), `Some((leaf, commitment, root))` on a match.
fn parse_deposit_log(logs: &[String]) -> Option<(u64, [u8; 32], [u8; 32])> {
    const PREFIX: &str = "Program log: tidex6-deposit:";

    for line in logs {
        let Some(payload) = line.strip_prefix(PREFIX) else {
            continue;
        };
        let mut parts = payload.split(':');
        let leaf_str = parts.next()?;
        let commitment_hex = parts.next()?;
        let root_hex = parts.next()?;

        let leaf_index = leaf_str.trim().parse::<u64>().ok()?;
        let commitment_bytes = hex::decode(commitment_hex.trim()).ok()?;
        let commitment: [u8; 32] = commitment_bytes.try_into().ok()?;
        let root_bytes = hex::decode(root_hex.trim()).ok()?;
        let root: [u8; 32] = root_bytes.try_into().ok()?;

        return Some((leaf_index, commitment, root));
    }

    None
}

/// Base58-encoded SPL Memo Program ID. Compared as a string against
/// each account key in the parsed JSON transaction rather than
/// round-tripping through a `Pubkey` type, which would pull in yet
/// another solana-program version from anchor-client.
const SPL_MEMO_PROGRAM_ID_BASE58: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/// Pull the base64 memo payload out of a transaction's instruction
/// list by locating the first instruction whose program is SPL Memo
/// and base58-decoding its `data` field.
///
/// Returns `None` if the transaction has no memo instruction, is not
/// encoded as JSON (our indexer requests JSON), or the decoded bytes
/// are not valid UTF-8 (which would indicate a non-tidex6 memo from
/// some other program coincidentally touching the pool).
fn extract_memo_instruction(encoded: &EncodedTransaction) -> Option<String> {
    let EncodedTransaction::Json(ui_tx) = encoded else {
        return None;
    };
    let UiMessage::Raw(raw_msg) = &ui_tx.message else {
        return None;
    };

    for ix in &raw_msg.instructions {
        let index = ix.program_id_index as usize;
        let Some(program_id) = raw_msg.account_keys.get(index) else {
            continue;
        };
        if program_id != SPL_MEMO_PROGRAM_ID_BASE58 {
            continue;
        }

        // The memo program stores raw UTF-8 bytes. Solana RPC
        // returns the instruction data as base58; our base64
        // payload round-trips through base58 and UTF-8 without loss.
        let raw = bs58::decode(&ix.data).into_vec().ok()?;
        let as_string = String::from_utf8(raw).ok()?;
        return Some(as_string);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_deposit_log_happy_path() {
        let logs = vec![
            "Program 77CwxmFdDaFpKHXTjR5fHVpUJ36DmhnfBNBzn8dXKo42 invoke [1]".to_string(),
            "Program log: Instruction: Deposit".to_string(),
            format!(
                "Program log: tidex6-deposit:7:{}:{}",
                "a".repeat(64),
                "b".repeat(64)
            ),
            "Program 77CwxmFdDaFpKHXTjR5fHVpUJ36DmhnfBNBzn8dXKo42 consumed 42 CU".to_string(),
        ];
        let (leaf, commitment, root) = parse_deposit_log(&logs).expect("deposit log must parse");
        assert_eq!(leaf, 7);
        assert_eq!(commitment, [0xaa; 32]);
        assert_eq!(root, [0xbb; 32]);
    }

    #[test]
    fn parse_deposit_log_missing_returns_none() {
        let logs = vec!["Program log: Instruction: InitPool".to_string()];
        assert!(parse_deposit_log(&logs).is_none());
    }
}
