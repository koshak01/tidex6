//! Kai — Lena's accountant.
//!
//! Once a year Lena hands Kai her scan file
//! (`~/.tidex6/payroll_scan.jsonl`) and tells him "this is every
//! transfer I made in 2026". Kai runs this binary, which reads
//! the scan file, groups transfers by month and by recipient
//! label, and emits a Markdown report suitable for attaching to
//! Lena's tax return.
//!
//! Kai never gets Lena's spending key — only the scan file and,
//! in the full v0.2 protocol, a one-off viewing key. The MVP
//! demo skips the viewing-key handshake and trusts the scan
//! file as the selective-disclosure primitive. Everything the
//! accountant sees is something Lena explicitly chose to share.
//!
//! Usage:
//!
//! ```text
//! cargo run --release --bin accountant -- \
//!     scan --scan-file ~/.tidex6/payroll_scan.jsonl \
//!          --output /tmp/lena_tax_report.md
//! ```

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Datelike, Utc};
use clap::{Parser, Subcommand};
use serde::Deserialize;

#[derive(Parser, Debug)]
#[command(name = "accountant", about = "Kai — private payroll accountant.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Scan Lena's offline scan file and produce a Markdown tax
    /// report.
    Scan(ScanArgs),
}

#[derive(clap::Args, Debug)]
struct ScanArgs {
    /// Path to the scan file Lena shared.
    #[arg(long)]
    scan_file: Option<PathBuf>,

    /// Where to write the generated Markdown report. Defaults to
    /// `/tmp/lena_tax_report.md`.
    #[arg(long, default_value = "/tmp/lena_tax_report.md")]
    output: PathBuf,
}

/// The scan entry layout must match `sender.rs`. Kept as a
/// separate struct here so the accountant binary is standalone.
///
/// `commitment` and `leaf_index` are parsed but not currently
/// rendered in the report — they are preserved here so a future
/// version of accountant.rs can cross-check the scan file against
/// on-chain `DepositEvent` logs via the indexer. Allowing
/// dead_code on those fields keeps the file format honest.
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct ScanEntry {
    timestamp: String,
    commitment: String,
    amount_lamports: u64,
    amount: String,
    memo: String,
    recipient_label: String,
    signature: String,
    leaf_index: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan(args) => run_scan(args),
    }
}

fn run_scan(args: ScanArgs) -> Result<()> {
    println!("┌──────────────────────────────────────────┐");
    println!("│  KAI — accountant selective-disclosure   │");
    println!("└──────────────────────────────────────────┘");
    println!();

    let scan_path = resolve_scan_path(args.scan_file)?;
    println!("  scan file : {}", scan_path.display());

    let contents = fs::read_to_string(&scan_path)
        .with_context(|| format!("read scan file {}", scan_path.display()))?;

    let mut entries: Vec<ScanEntry> = Vec::new();
    for (line_number, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let entry: ScanEntry = serde_json::from_str(trimmed)
            .with_context(|| format!("parse line {} of scan file", line_number + 1))?;
        entries.push(entry);
    }

    if entries.is_empty() {
        return Err(anyhow!(
            "scan file {} contains no entries — has Lena made any deposits?",
            scan_path.display()
        ));
    }

    // Sort chronologically (the scan file is append-only in
    // practice, but be defensive).
    entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let report = build_report(&entries)?;
    fs::write(&args.output, &report)
        .with_context(|| format!("write report to {}", args.output.display()))?;

    println!("  entries   : {}", entries.len());
    println!("  report    : {}", args.output.display());
    println!();

    // Also print a short summary directly to stdout — it's what
    // will show up in the demo video.
    print_summary(&entries);

    Ok(())
}

fn build_report(entries: &[ScanEntry]) -> Result<String> {
    let mut out = String::new();
    out.push_str("# tidex6 — private payroll report\n\n");
    out.push_str(&format!(
        "Total entries: **{}**  \nGenerated: {}\n\n",
        entries.len(),
        Utc::now().to_rfc3339()
    ));

    // All transfers table.
    out.push_str("## All transfers\n\n");
    out.push_str("| Date | Recipient | Amount | Memo | Tx |\n");
    out.push_str("|------|-----------|--------|------|----|\n");
    for entry in entries {
        let date = parse_timestamp(&entry.timestamp).unwrap_or_else(|| entry.timestamp.clone());
        let sig_short = short_signature(&entry.signature);
        out.push_str(&format!(
            "| {} | {} | {} | {} | `{}` |\n",
            date, entry.recipient_label, entry.amount, entry.memo, sig_short
        ));
    }
    out.push('\n');

    // Monthly totals.
    out.push_str("## Monthly totals\n\n");
    out.push_str("| Month | Transfers | Total (SOL) |\n");
    out.push_str("|-------|-----------|-------------|\n");
    let mut monthly: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for entry in entries {
        let month = month_key(&entry.timestamp);
        let slot = monthly.entry(month).or_insert((0, 0));
        slot.0 += 1;
        slot.1 += entry.amount_lamports;
    }
    for (month, (count, total_lamports)) in &monthly {
        out.push_str(&format!(
            "| {} | {} | {:.3} |\n",
            month,
            count,
            lamports_to_sol(*total_lamports)
        ));
    }
    out.push('\n');

    // Recipient totals.
    out.push_str("## By recipient\n\n");
    out.push_str("| Recipient | Transfers | Total (SOL) |\n");
    out.push_str("|-----------|-----------|-------------|\n");
    let mut by_recipient: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    for entry in entries {
        let slot = by_recipient
            .entry(entry.recipient_label.clone())
            .or_insert((0, 0));
        slot.0 += 1;
        slot.1 += entry.amount_lamports;
    }
    for (label, (count, total_lamports)) in &by_recipient {
        out.push_str(&format!(
            "| {} | {} | {:.3} |\n",
            label,
            count,
            lamports_to_sol(*total_lamports)
        ));
    }
    out.push('\n');

    // Grand total.
    let total_lamports: u64 = entries.iter().map(|e| e.amount_lamports).sum();
    out.push_str(&format!(
        "## Grand total\n\n**{:.3} SOL** across {} transfers.\n",
        lamports_to_sol(total_lamports),
        entries.len()
    ));

    Ok(out)
}

fn print_summary(entries: &[ScanEntry]) {
    println!("  Lena's transfers summary:");
    for entry in entries {
        let date = parse_timestamp(&entry.timestamp).unwrap_or_else(|| entry.timestamp.clone());
        println!(
            "    {} | {} | {} | {} | {}",
            date,
            entry.recipient_label,
            entry.amount,
            entry.memo,
            short_signature(&entry.signature)
        );
    }
    let total_lamports: u64 = entries.iter().map(|e| e.amount_lamports).sum();
    println!();
    println!("  Grand total: {:.3} SOL", lamports_to_sol(total_lamports));
    println!();
    println!("Tax report ready. Kai can attach it to Lena's return.");
}

fn parse_timestamp(input: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(input)
        .ok()
        .map(|dt| dt.with_timezone(&Utc).format("%Y-%m-%d").to_string())
}

fn month_key(timestamp: &str) -> String {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|dt| {
            let d = dt.with_timezone(&Utc);
            format!("{:04}-{:02}", d.year(), d.month())
        })
        .unwrap_or_else(|_| "unknown".to_string())
}

fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
}

fn short_signature(sig: &str) -> String {
    if sig.len() > 12 {
        format!("{}…", &sig[..12])
    } else {
        sig.to_string()
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
