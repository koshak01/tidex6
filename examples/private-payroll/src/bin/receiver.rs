//! Parents — the recipient (v2, stealth).
//!
//! In v2 Lena does NOT send them a note. The parents scan the chain
//! with their own ML-KEM secret, find every payment addressed to them,
//! reconstruct the note from the decrypted recipient slot, and withdraw
//! it to their wallet. The chain itself delivers the money — nothing was
//! handed over.
//!
//! ```text
//! cargo run --release --bin receiver -- receive \
//!     --identity ~/.tidex6/parents.json --to <wallet>
//! ```

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use anchor_client::Cluster;
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use serde::Deserialize;
use solana_keypair::{Keypair, read_keypair_file};

use tidex6_client::{Denomination, PrivatePool, RecipientScanner};
use tidex6_core::note::DepositNote;
use tidex6_core::pqc::PqcSecretKey;
use tidex6_core::types::{Nullifier, Secret};

#[derive(Parser, Debug)]
#[command(name = "receiver", about = "Parents — stealth receive (v2).")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan the chain for payments addressed to me and withdraw them.
    Receive(ReceiveArgs),
}

#[derive(clap::Args, Debug)]
struct ReceiveArgs {
    /// Parents' identity JSON file (contains the ML-KEM secret).
    #[arg(long)]
    identity: PathBuf,

    /// Wallet that receives the withdrawn SOL.
    #[arg(long)]
    to: String,
}

#[derive(Deserialize)]
struct Identity {
    mlkem_secret: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Receive(args) => run_receive(args),
    }
}

fn run_receive(args: ReceiveArgs) -> Result<()> {
    println!("┌──────────────────────────────────────────┐");
    println!("│  PARENTS (home) — stealth receive        │");
    println!("└──────────────────────────────────────────┘");
    println!();

    let mlkem_secret = load_mlkem_secret(&args.identity)?;
    let payer = load_default_keypair()?;
    let recipient =
        Pubkey::from_str(&args.to).with_context(|| format!("parse recipient {}", args.to))?;
    let cluster = detect_cluster()?;
    let program_id = PrivatePool::connect(cluster.clone(), Denomination::OneSol)?.program_id();

    println!("  cluster   : {}", cluster.url());
    println!("  to        : {recipient}");
    println!("Scanning the chain with the parents' ML-KEM key — no note was received...");

    let scanner = RecipientScanner::new(cluster.url(), program_id, &mlkem_secret);
    let entries = scanner.scan().context("recipient scan failed")?;

    if entries.is_empty() {
        println!("No payments addressed to the parents were found yet.");
        return Ok(());
    }
    println!("Found {} payment(s). Withdrawing each...", entries.len());

    for entry in entries {
        let denomination = denom_from_lamports(entry.denomination)?;
        let note = DepositNote::new(
            denomination,
            Secret::from_bytes(entry.secret),
            Nullifier::from_bytes(entry.nullifier),
        )
        .context("reconstruct note from recipient slot")?;
        let memo = String::from_utf8_lossy(&entry.plaintext);

        println!();
        println!("  payment    : {denomination}");
        if !memo.trim().is_empty() {
            println!("  message    : \"{memo}\"");
        }
        let pool = PrivatePool::connect(cluster.clone(), denomination)?;
        let outcome = pool.withdraw(&payer).note(note).to(recipient).send()?;
        println!("  withdrawn  → {recipient}");
        println!("  signature  : {}", outcome.signature);
    }

    println!();
    println!("Done. The chain delivered the payment — Lena handed over nothing.");
    Ok(())
}

fn load_mlkem_secret(path: &PathBuf) -> Result<PqcSecretKey> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("read identity {}", path.display()))?;
    let identity: Identity =
        serde_json::from_str(&raw).context("parse identity JSON (need mlkem_secret)")?;
    let bytes = hex::decode(identity.mlkem_secret.trim()).context("decode mlkem_secret hex")?;
    PqcSecretKey::from_bytes(&bytes).map_err(|err| anyhow!("invalid ML-KEM secret: {err}"))
}

fn denom_from_lamports(lamports: u64) -> Result<Denomination> {
    match lamports {
        100_000_000 => Ok(Denomination::OneTenthSol),
        500_000_000 => Ok(Denomination::HalfSol),
        1_000_000_000 => Ok(Denomination::OneSol),
        10_000_000_000 => Ok(Denomination::TenSol),
        other => Err(anyhow!("unknown denomination: {other} lamports")),
    }
}

fn load_default_keypair() -> Result<Keypair> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = format!("{home}/.config/solana/id.json");
    read_keypair_file(&path).map_err(|err| anyhow!("read {path}: {err}"))
}

fn detect_cluster() -> Result<Cluster> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = format!("{home}/.config/solana/cli/config.yml");
    let Ok(contents) = fs::read_to_string(&path) else {
        return Ok(Cluster::Devnet);
    };
    let url = contents
        .lines()
        .find_map(|line| line.trim().strip_prefix("json_rpc_url:"))
        .map(|v| v.trim().trim_matches('"').to_string());
    match url.as_deref() {
        Some(u) if u.contains("devnet") => Ok(Cluster::Devnet),
        Some(u) if u.contains("mainnet") => Ok(Cluster::Mainnet),
        Some(u) if u.contains("testnet") => Ok(Cluster::Testnet),
        Some(u) if u.starts_with("http") => Ok(Cluster::Custom(u.to_string(), u.to_string())),
        _ => Ok(Cluster::Devnet),
    }
}
