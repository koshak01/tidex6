//! Lena — the depositor.
//!
//! Lena lives in Amsterdam and sends monthly money home to her
//! parents. With tidex6 she does what her grandmother did with
//! envelopes of cash: sends privately, by choice, not by hiding.
//! At tax time her accountant still gets a full, auditable view
//! of every transfer — but only because Lena chose to share it
//! with him.
//!
//! This binary runs a single deposit:
//!
//!   1. Lena picks a denomination (0.5 SOL in the demo).
//!   2. tidex6-client generates a fresh `DepositNote` and sends
//!      the deposit transaction to the shielded pool.
//!   3. The note is saved to a file Lena will pass to the
//!      recipient (`parents.note`).
//!   4. Lena also appends a metadata entry to her local
//!      "scan file" (`~/.tidex6/payroll_scan.jsonl`). This JSON
//!      Lines file is her offline view of her own activity —
//!      she can hand it, plus a viewing key, to her accountant
//!      for selective disclosure. For the MVP demo the scan file
//!      is the selective-disclosure primitive; the full ElGamal
//!      + onchain encrypted memo version is planned for v0.2.
//!
//! Usage:
//!
//! ```text
//! cargo run --release --bin sender -- \
//!     deposit --amount 0.5 \
//!     --memo "october medicine" \
//!     --recipient-label parents \
//!     --note-out /tmp/parents.note
//! ```

use std::fs;
use std::path::PathBuf;

use anchor_client::Cluster;
use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use solana_keypair::{Keypair, read_keypair_file};

use tidex6_client::PrivatePool;
use tidex6_core::note::Denomination;

/// Top-level CLI definition for Lena's side of the demo.
#[derive(Parser, Debug)]
#[command(name = "sender", about = "Lena — private payroll sender.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Send one monthly payment to the shielded pool.
    Deposit(DepositArgs),
}

#[derive(clap::Args, Debug)]
struct DepositArgs {
    /// Denomination: 0.1, 0.5, 1, or 10 SOL.
    #[arg(long, default_value = "0.5")]
    amount: String,

    /// Short human-readable memo describing this payment
    /// (e.g. "october medicine"). Written only to the local
    /// scan file — never goes onchain.
    #[arg(long)]
    memo: String,

    /// Label for the recipient (e.g. "parents", "sister").
    /// Grouped by accountant.rs for reporting.
    #[arg(long, default_value = "parents")]
    recipient_label: String,

    /// Where to write the note file for the recipient.
    #[arg(long, default_value = "/tmp/parents.note")]
    note_out: PathBuf,

    /// Path to the scan file Lena keeps locally. Defaults to
    /// `~/.tidex6/payroll_scan.jsonl`.
    #[arg(long)]
    scan_file: Option<PathBuf>,
}

/// One entry in Lena's scan file. JSON Lines format — append
/// one object per line on each deposit. accountant.rs reads this
/// file line-by-line.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanEntry {
    /// ISO-8601 timestamp of the deposit.
    timestamp: String,
    /// Lowercase hex of the commitment. Lets the accountant
    /// correlate an entry with a confirmed on-chain deposit via
    /// the `tidex6-indexer` log lines.
    commitment: String,
    /// Denomination in lamports.
    amount_lamports: u64,
    /// Denomination as a human-readable string ("0.5 SOL").
    amount: String,
    /// User-supplied memo — "october medicine", "november rent"…
    memo: String,
    /// Recipient label for grouping.
    recipient_label: String,
    /// tx signature of the deposit for full traceability.
    signature: String,
    /// Leaf index assigned by the pool.
    leaf_index: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Deposit(args) => run_deposit(args),
    }
}

fn run_deposit(args: DepositArgs) -> Result<()> {
    println!("┌──────────────────────────────────────────┐");
    println!("│  LENA (Amsterdam) — private payroll send │");
    println!("└──────────────────────────────────────────┘");
    println!();

    let denomination = parse_denomination(&args.amount)?;
    let payer = load_default_keypair()?;
    let payer_pubkey = {
        use anchor_client::Signer;
        <Keypair as Signer>::pubkey(&payer)
    };

    let cluster = detect_cluster()?;
    let pool = PrivatePool::connect(cluster.clone(), denomination)?;

    println!("  cluster         : {}", cluster.url());
    println!("  payer (Lena)    : {payer_pubkey}");
    println!("  denomination    : {denomination}");
    println!("  memo            : {}", args.memo);
    println!("  recipient label : {}", args.recipient_label);
    println!();

    println!("Sending deposit to the shielded pool...");
    let (signature, note, leaf_index) = pool.deposit(&payer).send()?;

    println!("  commitment  : {}", note.commitment().to_hex());
    println!("  signature   : {signature}");
    println!("  leaf index  : {leaf_index}");
    println!("  explorer    : https://explorer.solana.com/tx/{signature}?cluster=devnet");
    println!();

    // Save the note for the recipient.
    fs::write(&args.note_out, note.to_text())
        .with_context(|| format!("write note to {}", args.note_out.display()))?;
    println!("Note written to: {}", args.note_out.display());
    println!("  → hand this file (or a QR of it) to parents.");

    // Append to the scan file for the accountant. This is Lena's
    // "view-key-lite" record of her own activity — she keeps it
    // locally and shares it with her accountant once a year.
    let scan_path = resolve_scan_path(args.scan_file)?;
    if let Some(parent) = scan_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create scan dir {}", parent.display()))?;
    }

    let entry = ScanEntry {
        timestamp: Utc::now().to_rfc3339(),
        commitment: note.commitment().to_hex(),
        amount_lamports: denomination.lamports(),
        amount: format!("{denomination}"),
        memo: args.memo,
        recipient_label: args.recipient_label,
        signature: signature.to_string(),
        leaf_index,
    };
    let line = serde_json::to_string(&entry).context("serialise scan entry")?;

    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&scan_path)
        .with_context(|| format!("open scan file {}", scan_path.display()))?;
    writeln!(file, "{line}").context("append scan entry")?;

    println!();
    println!("Scan entry appended to: {}", scan_path.display());
    println!("  → share this file + your viewing key with Kai at tax time.");

    Ok(())
}

fn parse_denomination(input: &str) -> Result<Denomination> {
    let cleaned = input
        .trim()
        .trim_end_matches(" SOL")
        .trim_end_matches("SOL");
    match cleaned {
        "0.1" => Ok(Denomination::OneTenthSol),
        "0.5" => Ok(Denomination::HalfSol),
        "1" => Ok(Denomination::OneSol),
        "10" => Ok(Denomination::TenSol),
        _ => Err(anyhow!(
            "unsupported denomination: {input}. Must be one of: 0.1, 0.5, 1, 10"
        )),
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

fn resolve_scan_path(override_path: Option<PathBuf>) -> Result<PathBuf> {
    match override_path {
        Some(path) => Ok(path),
        None => {
            let home = std::env::var("HOME").context("HOME not set")?;
            Ok(PathBuf::from(format!("{home}/.tidex6/payroll_scan.jsonl")))
        }
    }
}
