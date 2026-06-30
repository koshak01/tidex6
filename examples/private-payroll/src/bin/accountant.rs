//! Kai — Lena's accountant (v2, on-chain).
//!
//! In v2 Lena does not hand Kai a scan file. On every deposit she sealed
//! an auditor slot to Kai's ML-KEM public key, so Kai scans the chain on
//! his own with his ML-KEM secret and sees the amount + memo of every
//! transfer Lena addressed to him — without being able to spend, and
//! without Lena sending him anything. He builds a Markdown tax report.
//!
//! Everything Kai sees is something Lena explicitly chose to disclose by
//! including his auditor key. He has no spending capability.
//!
//! ```text
//! cargo run --release --bin accountant -- scan \
//!     --identity ~/.tidex6/kai.json --output /tmp/lena_tax_report.md
//! ```

use std::fs;
use std::path::PathBuf;

use anchor_client::Cluster;
use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use clap::{Parser, Subcommand};
use serde::Deserialize;

use tidex6_client::{AccountantScanner, Denomination, PrivatePool};
use tidex6_core::pqc::PqcSecretKey;

#[derive(Parser, Debug)]
#[command(name = "accountant", about = "Kai — private payroll accountant (v2 on-chain).")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan the chain with Kai's ML-KEM secret and produce a report.
    Scan(ScanArgs),
}

#[derive(clap::Args, Debug)]
struct ScanArgs {
    /// Kai's identity JSON file (contains the ML-KEM secret).
    #[arg(long)]
    identity: PathBuf,

    /// Where to write the Markdown report.
    #[arg(long, default_value = "/tmp/lena_tax_report.md")]
    output: PathBuf,
}

#[derive(Deserialize)]
struct Identity {
    mlkem_secret: String,
}

/// One decoded transfer Kai can see.
struct Transfer {
    amount_lamports: u64,
    memo: String,
    commitment: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => run_scan(args),
    }
}

fn run_scan(args: ScanArgs) -> Result<()> {
    println!("┌──────────────────────────────────────────┐");
    println!("│  KAI — accountant on-chain disclosure     │");
    println!("└──────────────────────────────────────────┘");
    println!();

    let mlkem_secret = load_mlkem_secret(&args.identity)?;
    let cluster = detect_cluster()?;
    let program_id = PrivatePool::connect(cluster.clone(), Denomination::OneSol)?.program_id();

    println!("  rpc       : {}", cluster.url());
    println!("Scanning the chain with Kai's ML-KEM key for transfers Lena disclosed to him...");

    let scanner = AccountantScanner::new(cluster.url(), program_id, &mlkem_secret);
    let entries = scanner.scan().context("memo-account scan failed")?;

    if entries.is_empty() {
        return Err(anyhow!(
            "no transfers addressed to this auditor key were found — did Lena include Kai's ML-KEM key as --auditor?"
        ));
    }

    let transfers: Vec<Transfer> = entries
        .into_iter()
        .map(|e| Transfer {
            amount_lamports: e.denomination,
            memo: e.plaintext_lossy(),
            commitment: e.commitment_hex,
        })
        .collect();

    let report = build_report(&transfers);
    fs::write(&args.output, &report)
        .with_context(|| format!("write report to {}", args.output.display()))?;

    println!("  entries   : {}", transfers.len());
    println!("  report    : {}", args.output.display());
    println!();
    print_summary(&transfers);

    Ok(())
}

fn build_report(transfers: &[Transfer]) -> String {
    let mut out = String::new();
    out.push_str("# tidex6 — private payroll report (on-chain disclosure)\n\n");
    out.push_str(&format!(
        "Total transfers: **{}**  \nGenerated: {}\n\n",
        transfers.len(),
        Utc::now().to_rfc3339()
    ));

    out.push_str("## All transfers\n\n");
    out.push_str("| Amount (SOL) | Memo | Commitment |\n");
    out.push_str("|--------------|------|------------|\n");
    for t in transfers {
        out.push_str(&format!(
            "| {:.3} | {} | `{}…` |\n",
            lamports_to_sol(t.amount_lamports),
            t.memo,
            &t.commitment[..t.commitment.len().min(16)]
        ));
    }
    out.push('\n');

    let total_lamports: u64 = transfers.iter().map(|t| t.amount_lamports).sum();
    out.push_str(&format!(
        "## Grand total\n\n**{:.3} SOL** across {} transfers.\n",
        lamports_to_sol(total_lamports),
        transfers.len()
    ));
    out
}

fn print_summary(transfers: &[Transfer]) {
    println!("  Transfers Lena disclosed to Kai:");
    for t in transfers {
        println!(
            "    {:.3} SOL | {} | {}…",
            lamports_to_sol(t.amount_lamports),
            t.memo,
            &t.commitment[..t.commitment.len().min(12)]
        );
    }
    let total_lamports: u64 = transfers.iter().map(|t| t.amount_lamports).sum();
    println!();
    println!("  Grand total: {:.3} SOL", lamports_to_sol(total_lamports));
    println!();
    println!("Tax report ready. Kai saw everything Lena disclosed — and could spend nothing.");
}

fn load_mlkem_secret(path: &PathBuf) -> Result<PqcSecretKey> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read identity {}", path.display()))?;
    let identity: Identity =
        serde_json::from_str(&raw).context("parse identity JSON (need mlkem_secret)")?;
    let bytes = hex::decode(identity.mlkem_secret.trim()).context("decode mlkem_secret hex")?;
    PqcSecretKey::from_bytes(&bytes).map_err(|err| anyhow!("invalid ML-KEM secret: {err}"))
}

fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
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
