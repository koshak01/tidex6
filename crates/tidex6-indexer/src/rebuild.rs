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
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use solana_rpc_client::rpc_client::{GetConfirmedSignaturesForAddress2Config, RpcClient};
use solana_rpc_client_api::client_error::Error as RpcError;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_transaction_status::UiTransactionEncoding;
use solana_transaction_status::option_serializer::OptionSerializer;

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

        let Some(parsed) = parse_deposit_log(logs) else {
            return Ok(None);
        };

        Ok(Some(DepositRecord {
            leaf_index: parsed.leaf_index,
            commitment: Commitment::from_bytes(parsed.commitment),
            onchain_root: MerkleRoot::from_bytes(parsed.root),
            signature: signature.to_string(),
            memo_base64: parsed.memo_base64,
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

/// Parsed result of a single `tidex6-deposit:` log line.
///
/// The memo field is an `Option` because older deposits — everything
/// emitted before the Shielded Memo redeploy of 2026-04-15 — carried
/// only three colon-separated fields. Those records are still valid
/// and still contribute to the Merkle tree; they just do not have a
/// memo the accountant could decrypt.
struct ParsedDepositLog {
    leaf_index: u64,
    commitment: [u8; 32],
    root: [u8; 32],
    memo_base64: Option<String>,
}

/// Parse the `tidex6-deposit:<leaf>:<commitment_hex>:<root_hex>[:<memo_hex>]`
/// log line out of a transaction's program-log output. Returns
/// `None` if no matching line exists (e.g., this tx is not a
/// deposit). Accepts both the legacy 3-field and the current
/// 4-field variant so a single indexer pass can consume pool
/// histories that straddle the redeploy cut-over.
fn parse_deposit_log(logs: &[String]) -> Option<ParsedDepositLog> {
    const PREFIX: &str = "Program log: tidex6-deposit:";

    for line in logs {
        let Some(payload) = line.strip_prefix(PREFIX) else {
            continue;
        };
        let parts: Vec<&str> = payload.split(':').collect();
        if parts.len() < 3 {
            continue;
        }

        let leaf_index = parts[0].trim().parse::<u64>().ok()?;
        let commitment_bytes = hex::decode(parts[1].trim()).ok()?;
        let commitment: [u8; 32] = commitment_bytes.try_into().ok()?;
        let root_bytes = hex::decode(parts[2].trim()).ok()?;
        let root: [u8; 32] = root_bytes.try_into().ok()?;

        // Fourth field — lowercase hex of the Shielded Memo payload.
        // Present since the 2026-04-15 redeploy; absent from legacy
        // deposits. When present, we re-emit it as a base64 string
        // because the accountant module expects the same base64
        // wire format that `tidex6_core::memo::MemoPayload::to_base64`
        // produces on the depositor side.
        let memo_base64 = parts
            .get(3)
            .map(|memo_hex| hex::decode(memo_hex.trim()).ok())
            .and_then(|decoded| decoded)
            .map(|bytes| BASE64.encode(bytes));

        return Some(ParsedDepositLog {
            leaf_index,
            commitment,
            root,
            memo_base64,
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_deposit_log_legacy_three_fields() {
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
        let parsed = parse_deposit_log(&logs).expect("legacy deposit log must parse");
        assert_eq!(parsed.leaf_index, 7);
        assert_eq!(parsed.commitment, [0xaa; 32]);
        assert_eq!(parsed.root, [0xbb; 32]);
        assert!(parsed.memo_base64.is_none());
    }

    #[test]
    fn parse_deposit_log_with_memo() {
        // Memo payload: 60 bytes of 0xcd in the fixed prefix then
        // two bytes of ciphertext — shaped like a `MemoPayload` but
        // we are only testing the parser, not the crypto.
        let memo_bytes: Vec<u8> = std::iter::repeat_n(0xcd, 62).collect();
        let memo_hex = memo_bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let logs = vec![format!(
            "Program log: tidex6-deposit:3:{}:{}:{}",
            "a".repeat(64),
            "b".repeat(64),
            memo_hex,
        )];
        let parsed = parse_deposit_log(&logs).expect("v2 deposit log must parse");
        assert_eq!(parsed.leaf_index, 3);
        let decoded = BASE64
            .decode(parsed.memo_base64.expect("memo must be present"))
            .expect("base64 must decode");
        assert_eq!(decoded, memo_bytes);
    }

    #[test]
    fn parse_deposit_log_missing_returns_none() {
        let logs = vec!["Program log: Instruction: InitPool".to_string()];
        assert!(parse_deposit_log(&logs).is_none());
    }
}
