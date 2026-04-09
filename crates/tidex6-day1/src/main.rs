//! Day-1 Validation Checklist harness for tidex6.
//!
//! This binary runs the Day-1 kill gates against a live Solana cluster.
//! It sends a `hash_poseidon` transaction to the deployed
//! `tidex6-verifier` program, reads the hash from the transaction
//! program logs, and compares the onchain result byte-for-byte against
//! the offchain `tidex6_core::poseidon::hash_pair` output.
//!
//! The kill gate: if the two values diverge by even one byte, the
//! shielded pool commitment scheme breaks. See
//! `docs/release/security.md` sections 2.2 and 3.
//!
//! Usage:
//!
//! ```bash
//! cargo run -p tidex6-day1 --bin tidex6-day1
//! ```
//!
//! The binary reads the Solana keypair at `~/.config/solana/id.json`
//! and targets the cluster from `~/.config/solana/cli/config.yml`,
//! defaulting to devnet when no config is present.

use std::rc::Rc;

use anchor_client::{Client, Cluster, CommitmentConfig, Signer};
use anyhow::{Context, Result, anyhow};
use solana_keypair::{Keypair, read_keypair_file};
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_transaction_status::{UiTransactionEncoding, option_serializer::OptionSerializer};

use tidex6_core::poseidon;
use tidex6_verifier::accounts as verifier_accounts;
use tidex6_verifier::instruction as verifier_instruction;

const LOG_PREFIX: &str = "Program log: tidex6-day1-poseidon:";

fn main() -> Result<()> {
    println!("tidex6 Day-1 Validation Checklist");
    println!("=================================");
    println!();

    let payer = load_default_keypair().context("failed to load Solana keypair")?;
    let cluster = detect_cluster().context("failed to detect Solana cluster")?;
    let program_id = tidex6_verifier::ID;

    println!("cluster       : {}", cluster.url());
    println!("payer         : {}", payer.pubkey());
    println!("program id    : {program_id}");
    println!();

    let payer_handle = Rc::new(clone_keypair(&payer));
    let client = Client::new_with_options(cluster, payer_handle, CommitmentConfig::confirmed());
    let program = client
        .program(program_id)
        .context("failed to construct Anchor program handle")?;

    // Day-1 kill gate 1: Poseidon onchain ↔ offchain equivalence.
    //
    // Uses the canonical two-input vector ([1u8; 32], [2u8; 32]) from the
    // upstream `light-poseidon` and `solana-poseidon` docstrings. The
    // offchain wrapper already matches this vector in the tidex6-core
    // unit tests; this run confirms that the onchain syscall agrees
    // against a live cluster.
    let left = [1u8; 32];
    let right = [2u8; 32];

    let offchain = poseidon::hash_pair(&left, &right)
        .context("offchain Poseidon hash failed — Day-1 gate cannot proceed")?;
    println!("offchain hash : {}", hex::encode(offchain));

    let signature = program
        .request()
        .accounts(verifier_accounts::HashPoseidon {
            payer: payer.pubkey(),
        })
        .args(verifier_instruction::HashPoseidon {
            inputs: vec![left, right],
        })
        .signer(&payer)
        .send()
        .context("hash_poseidon transaction failed to confirm")?;
    println!("signature     : {signature}");

    let rpc = program.rpc();
    let transaction_config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };
    let transaction = rpc
        .get_transaction_with_config(&signature, transaction_config)
        .context("get_transaction_with_config RPC call failed")?;

    let log_messages = transaction
        .transaction
        .meta
        .as_ref()
        .ok_or_else(|| anyhow!("transaction meta is missing"))
        .and_then(|meta| match &meta.log_messages {
            OptionSerializer::Some(logs) => Ok(logs.clone()),
            _ => Err(anyhow!("transaction meta has no log messages")),
        })?;

    let hex_hash = log_messages
        .iter()
        .find_map(|line| line.strip_prefix(LOG_PREFIX))
        .ok_or_else(|| {
            anyhow!(
                "log line starting with `{LOG_PREFIX}` not found in transaction logs:\n{}",
                log_messages.join("\n")
            )
        })?;

    let decoded =
        hex::decode(hex_hash.trim()).context("failed to decode onchain hex hash into bytes")?;
    let onchain: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow!("onchain hash length is not 32 bytes"))?;

    println!("onchain hash  : {}", hex::encode(onchain));
    println!();

    if offchain == onchain {
        println!("Day-1 Validation Checklist — Test 1 (Poseidon equivalence): PASSED");
        println!("Offchain `light-poseidon` and onchain `sol_poseidon` produce byte-for-byte");
        println!("identical output on the canonical two-input vector. The shielded pool");
        println!("commitment scheme can be built on this primitive without divergence.");
        Ok(())
    } else {
        Err(anyhow!(
            "Day-1 kill gate FAILURE: offchain != onchain\n  \
             offchain: {}\n  \
             onchain : {}\n  \
             See docs/release/security.md section 2.2.",
            hex::encode(offchain),
            hex::encode(onchain),
        ))
    }
}

/// Loads the default Solana keypair from `~/.config/solana/id.json`.
fn load_default_keypair() -> Result<Keypair> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    let path = format!("{home}/.config/solana/id.json");
    read_keypair_file(&path).map_err(|err| anyhow!("failed to read keypair from {path}: {err}"))
}

/// Clones a `Keypair` by round-tripping through its byte representation,
/// because `Keypair` intentionally does not implement `Clone` to avoid
/// accidental key duplication in production code. The Day-1 harness is
/// a validation tool, not production.
fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::try_from(keypair.to_bytes().as_slice())
        .expect("round-tripping a Keypair through its byte form is infallible")
}

/// Reads the cluster URL from `~/.config/solana/cli/config.yml`.
///
/// Falls back to devnet when the config file is missing or unparseable,
/// since the tidex6 MVP deployment lives there.
fn detect_cluster() -> Result<Cluster> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    let path = format!("{home}/.config/solana/cli/config.yml");

    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Ok(Cluster::Devnet);
    };

    let url = contents
        .lines()
        .find_map(|line| line.trim().strip_prefix("json_rpc_url:"))
        .map(|value| value.trim().trim_matches('"').to_string());

    match url.as_deref() {
        Some(u) if u.contains("devnet") => Ok(Cluster::Devnet),
        Some(u) if u.contains("mainnet") => Ok(Cluster::Mainnet),
        Some(u) if u.contains("testnet") => Ok(Cluster::Testnet),
        Some(u) if u.starts_with("http") => Ok(Cluster::Custom(u.to_string(), u.to_string())),
        _ => Ok(Cluster::Devnet),
    }
}
