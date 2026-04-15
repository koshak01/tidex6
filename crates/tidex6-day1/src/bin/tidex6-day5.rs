//! Day-5 production deposit harness.
//!
//! This binary exercises the new `init_pool` + `deposit` flow in
//! `tidex6-verifier` end-to-end against a live Solana cluster.
//! Compared to the Day-1 harness, which only validates isolated
//! primitives, this binary drives the first real shielded-pool
//! operation: it initialises a pool for a specific denomination (or
//! skips the init if one already exists), deposits a freshly-generated
//! `DepositNote`, and then recomputes the expected Merkle root
//! offchain using `tidex6_core::merkle::MerkleTree` and compares it
//! to the root emitted by the onchain program.
//!
//! If any step fails or the roots diverge, the harness exits with a
//! loud error so the discrepancy is caught before moving to Day 6.

use std::rc::Rc;

use anchor_client::{Client, Cluster, CommitmentConfig, Signer};
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result, anyhow};
use solana_keypair::{Keypair, read_keypair_file};
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_transaction_status::{UiTransactionEncoding, option_serializer::OptionSerializer};

use tidex6_core::merkle::MerkleTree;
use tidex6_core::note::{Denomination, DepositNote};
use tidex6_core::types::MerkleRoot;
use tidex6_verifier::accounts as verifier_accounts;
use tidex6_verifier::instruction as verifier_instruction;

/// The test denomination we use. One-tenth SOL keeps devnet SOL
/// consumption low even across many re-runs while still exercising
/// every code path.
const TEST_DENOMINATION: Denomination = Denomination::OneTenthSol;

fn main() -> Result<()> {
    println!("tidex6 Day-5 deposit harness");
    println!("============================");
    println!();

    let payer = load_default_keypair().context("failed to load Solana keypair")?;
    let cluster = detect_cluster().context("failed to detect Solana cluster")?;
    let program_id = tidex6_verifier::ID;

    println!("cluster       : {}", cluster.url());
    println!("payer         : {}", payer.pubkey());
    println!("program id    : {program_id}");
    println!("denomination  : {}", TEST_DENOMINATION);
    println!();

    let payer_handle = Rc::new(clone_keypair(&payer));
    let client = Client::new_with_options(cluster, payer_handle, CommitmentConfig::confirmed());
    let program = client
        .program(program_id)
        .context("failed to construct Anchor program handle")?;

    let denomination_lamports = TEST_DENOMINATION.lamports();
    let (pool_pda, _pool_bump) = Pubkey::find_program_address(
        &[b"pool", &denomination_lamports.to_le_bytes()],
        &program_id,
    );
    let (vault_pda, _vault_bump) = Pubkey::find_program_address(
        &[b"vault", &denomination_lamports.to_le_bytes()],
        &program_id,
    );

    println!("pool PDA      : {pool_pda}");
    println!("vault PDA     : {vault_pda}");
    println!();

    ensure_pool_initialised(
        &program,
        &payer,
        denomination_lamports,
        &pool_pda,
        &vault_pda,
    )?;

    println!("--- Generating deposit note ---");
    let note = DepositNote::random(TEST_DENOMINATION)
        .context("failed to generate a random deposit note")?;
    println!("commitment    : {}", note.commitment().to_hex());
    println!();

    println!("--- Sending deposit transaction ---");
    let signature = program
        .request()
        .accounts(verifier_accounts::Deposit {
            pool: pool_pda,
            vault: vault_pda,
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(verifier_instruction::Deposit {
            commitment: note.commitment().to_bytes(),
            memo_payload: tidex6_core::memo::placeholder_payload_for_harness(),
        })
        .signer(&payer)
        .send()
        .context("deposit transaction failed to confirm")?;
    println!("signature     : {signature}");

    let logs = fetch_transaction_logs(&program, &signature)?;
    let (leaf_index, _log_commitment, onchain_root) = parse_deposit_log(&logs)?;
    println!("leaf index    : {leaf_index}");
    println!("onchain root  : {}", hex::encode(onchain_root));

    println!();
    println!("--- Recomputing root offchain ---");
    let offchain_root =
        compute_offchain_root_at_leaf_index(note.commitment().to_bytes(), leaf_index)?;
    println!("offchain root : {}", hex::encode(offchain_root));

    if onchain_root != offchain_root {
        return Err(anyhow!(
            "Day-5 FAIL: onchain root {} does not match offchain root {}",
            hex::encode(onchain_root),
            hex::encode(offchain_root)
        ));
    }

    println!();
    println!("============================");
    println!("Day-5 deposit harness: PASSED");
    println!("pool initialised, deposit executed, onchain root matches offchain computation.");
    println!("============================");

    Ok(())
}

/// Check whether the pool PDA already exists. If not, send an
/// `init_pool` transaction. If it already exists, skip.
fn ensure_pool_initialised<C>(
    program: &anchor_client::Program<C>,
    payer: &Keypair,
    denomination: u64,
    pool_pda: &Pubkey,
    vault_pda: &Pubkey,
) -> Result<()>
where
    C: std::ops::Deref<Target = Keypair> + Clone,
{
    let rpc = program.rpc();
    if let Ok(account) = rpc.get_account(pool_pda) {
        if !account.data.is_empty() {
            println!("--- pool already initialised, skipping init_pool ---");
            return Ok(());
        }
    }

    println!("--- Initialising pool ---");
    let signature = program
        .request()
        .accounts(verifier_accounts::InitPool {
            pool: *pool_pda,
            vault: *vault_pda,
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(verifier_instruction::InitPool { denomination })
        .signer(payer)
        .send()
        .context("init_pool transaction failed to confirm")?;
    println!("init signature: {signature}");
    Ok(())
}

/// Parse the `tidex6-deposit:<leaf_index>:<commitment>:<root>` log
/// line emitted by the deposit instruction. Returns the new leaf
/// index, the inserted commitment and the updated Merkle root.
fn parse_deposit_log(logs: &[String]) -> Result<(u64, [u8; 32], [u8; 32])> {
    const PREFIX: &str = "Program log: tidex6-deposit:";

    for line in logs {
        if let Some(payload) = line.strip_prefix(PREFIX) {
            let mut parts = payload.split(':');
            let leaf_index_str = parts
                .next()
                .ok_or_else(|| anyhow!("deposit log missing leaf index"))?;
            let hex_commitment = parts
                .next()
                .ok_or_else(|| anyhow!("deposit log missing commitment hex"))?;
            let hex_root = parts
                .next()
                .ok_or_else(|| anyhow!("deposit log missing root hex"))?;

            let leaf_index = leaf_index_str
                .parse::<u64>()
                .context("deposit log leaf index is not a number")?;
            let commitment_bytes =
                hex::decode(hex_commitment.trim()).context("deposit commitment hex decode")?;
            let commitment: [u8; 32] = commitment_bytes
                .try_into()
                .map_err(|_| anyhow!("deposit commitment is not 32 bytes"))?;
            let root_bytes = hex::decode(hex_root.trim()).context("deposit root hex decode")?;
            let root: [u8; 32] = root_bytes
                .try_into()
                .map_err(|_| anyhow!("deposit root is not 32 bytes"))?;

            return Ok((leaf_index, commitment, root));
        }
    }

    Err(anyhow!(
        "no deposit log line found in transaction output:\n{}",
        logs.join("\n")
    ))
}

/// Rebuild the shielded-pool Merkle tree offchain by inserting
/// zero leaves up to `leaf_index` and then the real commitment, and
/// return the resulting root. If `leaf_index` is 0 this simply
/// inserts the commitment into a fresh empty tree.
fn compute_offchain_root_at_leaf_index(
    commitment_bytes: [u8; 32],
    leaf_index: u64,
) -> Result<[u8; 32]> {
    use tidex6_core::merkle::DEFAULT_DEPTH;
    use tidex6_core::types::Commitment;

    let mut tree = MerkleTree::new(DEFAULT_DEPTH).context("new offchain tree")?;

    // Pad with zero leaves to match the leaf_index reported onchain,
    // then insert the real commitment.
    for _ in 0..leaf_index {
        tree.insert(Commitment::zero())
            .context("insert zero leaf")?;
    }
    let (_inserted_index, root) = tree
        .insert(Commitment::from_bytes(commitment_bytes))
        .context("insert real commitment")?;

    Ok(MerkleRoot::to_bytes(&root))
}

/// Fetch transaction logs from the cluster by signature.
fn fetch_transaction_logs<C>(
    program: &anchor_client::Program<C>,
    signature: &solana_signature::Signature,
) -> Result<Vec<String>>
where
    C: std::ops::Deref<Target = Keypair> + Clone,
{
    let rpc = program.rpc();
    let transaction_config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };

    let transaction = rpc
        .get_transaction_with_config(signature, transaction_config)
        .context("get_transaction_with_config RPC call failed")?;

    transaction
        .transaction
        .meta
        .as_ref()
        .ok_or_else(|| anyhow!("transaction meta is missing"))
        .and_then(|meta| match &meta.log_messages {
            OptionSerializer::Some(logs) => Ok(logs.clone()),
            _ => Err(anyhow!("transaction meta has no log messages")),
        })
}

fn load_default_keypair() -> Result<Keypair> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    let path = format!("{home}/.config/solana/id.json");
    read_keypair_file(&path).map_err(|err| anyhow!("failed to read keypair from {path}: {err}"))
}

fn clone_keypair(keypair: &Keypair) -> Keypair {
    Keypair::try_from(keypair.to_bytes().as_slice())
        .expect("round-tripping a Keypair through its byte form is infallible")
}

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
