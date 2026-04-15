//! Parents — the recipient.
//!
//! Lena's parents live somewhere that makes European bank
//! transfers inconvenient. They receive a small encrypted text
//! file (the `DepositNote`) from Lena once a month. This binary
//! turns that file into SOL in their wallet.
//!
//! Under the hood, withdrawing is a zero-knowledge proof the
//! parents never have to think about:
//!
//!   1. tidex6-client's `PoolIndexer` rebuilds the offchain
//!      Merkle tree from the pool's on-chain history.
//!   2. It finds the leaf index corresponding to the note's
//!      commitment.
//!   3. It generates a Groth16 proof that the parents know the
//!      preimage (secret + nullifier) of a commitment at that
//!      leaf position, bound to their recipient pubkey.
//!   4. The proof goes on-chain via the `tidex6-verifier` program,
//!      which pays out the denomination to the parents' wallet.
//!
//! Usage:
//!
//! ```text
//! cargo run --release --bin receiver -- \
//!     withdraw --note /tmp/parents.note --to <my_pubkey>
//! ```

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use anchor_client::Cluster;
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use solana_keypair::{Keypair, read_keypair_file};

use tidex6_client::PrivatePool;
use tidex6_core::note::DepositNote;

#[derive(Parser, Debug)]
#[command(name = "receiver", about = "Parents — private payroll recipient.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Redeem one note into a recipient wallet.
    Withdraw(WithdrawArgs),
}

#[derive(clap::Args, Debug)]
struct WithdrawArgs {
    /// Path to the note file received from Lena.
    #[arg(long, default_value = "/tmp/parents.note")]
    note: PathBuf,

    /// Recipient wallet — where the withdrawn SOL lands.
    #[arg(long)]
    to: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Withdraw(args) => run_withdraw(args),
    }
}

fn run_withdraw(args: WithdrawArgs) -> Result<()> {
    println!("┌──────────────────────────────────────────┐");
    println!("│  PARENTS (home) — private payroll redeem │");
    println!("└──────────────────────────────────────────┘");
    println!();

    let note_text = fs::read_to_string(&args.note)
        .with_context(|| format!("read note from {}", args.note.display()))?;
    let note = DepositNote::from_text(&note_text).context("parse note text")?;

    let payer = load_default_keypair()?;
    let payer_pubkey = {
        use anchor_client::Signer;
        <Keypair as Signer>::pubkey(&payer)
    };
    let recipient =
        Pubkey::from_str(&args.to).with_context(|| format!("parse recipient {}", args.to))?;

    let cluster = detect_cluster()?;
    let pool = PrivatePool::connect(cluster.clone(), note.denomination())?;

    println!("  cluster        : {}", cluster.url());
    println!("  payer          : {payer_pubkey}");
    println!("  denomination   : {}", note.denomination());
    println!("  commitment     : {}", note.commitment().to_hex());
    println!("  recipient      : {recipient}");
    if let Some(memo) = note.memo() {
        println!();
        println!("  Message from Lena:");
        println!("    \"{memo}\"");
    }
    println!();
    println!("Redeeming note...");
    println!("  → rebuilding Merkle tree from on-chain history");
    println!("  → generating zero-knowledge withdraw proof");
    println!("  → submitting to verifier program");
    println!();

    let signature = pool.withdraw(&payer).note(note).to(recipient).send()?;

    println!("Signature: {signature}");
    println!("Explorer : https://explorer.solana.com/tx/{signature}?cluster=devnet");
    println!();
    println!("Recipient {recipient} received the funds. Done.");

    Ok(())
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
