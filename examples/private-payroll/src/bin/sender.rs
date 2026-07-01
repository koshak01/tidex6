//! Lena — the depositor (v2, stealth + ML-KEM).
//!
//! Lena lives in Amsterdam and sends monthly money home to her
//! parents. With tidex6 she does what her grandmother did with
//! envelopes of cash: sends privately, by choice, not by hiding.
//!
//! In v2 she does NOT hand a note to her parents. She seals the payment
//! to their ML-KEM public key; they scan the chain and withdraw it
//! themselves (`receiver`). She also seals an auditor slot to Kai's
//! ML-KEM key so he can reconstruct the ledger (`accountant`). She keeps
//! the note locally only in case she needs to `refund` (revoke).
//!
//! ```text
//! cargo run --release --bin sender -- deposit --amount 0.5 \
//!     --memo "october medicine" \
//!     --recipient <parents_mlkem_pk_hex> \
//!     --auditor <kai_mlkem_pk_hex> \
//!     --revoke-after-days 30
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
use tidex6_core::pqc::PqcPublicKey;

#[derive(Parser, Debug)]
#[command(name = "sender", about = "Lena — private payroll sender (v2 stealth).")]
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

    /// Short human-readable memo (e.g. "october medicine"). Sealed for
    /// the recipient and the auditor.
    #[arg(long)]
    memo: String,

    /// Recipient ML-KEM-768 public key (hex) — the parents. The note is
    /// sealed for this key; they scan the chain and withdraw themselves.
    #[arg(long)]
    recipient: String,

    /// Auditor ML-KEM-768 public key (hex) — Kai. Gets an amount+memo
    /// slot (cannot spend). Optional.
    #[arg(long)]
    auditor: Option<String>,

    /// Revoke window in days. After this, if parents never withdrew,
    /// Lena can `tidex6 refund`. 0 = irrevocable.
    #[arg(long, default_value_t = 30)]
    revoke_after_days: u32,

    /// Recipient label for Lena's own bookkeeping.
    #[arg(long, default_value = "parents")]
    recipient_label: String,

    /// Where to write the local note file (kept by Lena for a refund).
    #[arg(long, default_value = "/tmp/parents.note")]
    note_out: PathBuf,

    /// Lena's local scan file. Defaults to `~/.tidex6/payroll_scan.jsonl`.
    #[arg(long)]
    scan_file: Option<PathBuf>,
}

/// One entry in Lena's local scan file (JSON Lines).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanEntry {
    timestamp: String,
    commitment: String,
    amount_lamports: u64,
    amount: String,
    memo: String,
    recipient_label: String,
    signature: String,
    leaf_index: u64,
    memo_account: String,
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

    let recipient_pqc = parse_mlkem(&args.recipient).context("invalid --recipient ML-KEM key")?;
    let auditor_pqc = match args.auditor.as_deref() {
        Some(hex) => Some(parse_mlkem(hex).context("invalid --auditor ML-KEM key")?),
        None => None,
    };
    let revoke_window_secs = (args.revoke_after_days as i64) * 86_400;

    println!("  cluster         : {}", cluster.url());
    println!("  payer (Lena)    : {payer_pubkey}");
    println!("  denomination    : {denomination}");
    println!("  memo            : {}", args.memo);
    println!("  recipient label : {}", args.recipient_label);
    println!(
        "  auditor (Kai)   : {}",
        if auditor_pqc.is_some() { "yes" } else { "none" }
    );
    println!(
        "  revoke          : {}",
        if revoke_window_secs == 0 {
            "irrevocable".to_string()
        } else {
            format!("after {} days", args.revoke_after_days)
        }
    );
    println!();

    println!("Sealing the payment for the parents' ML-KEM key and sending...");
    let mut builder = pool
        .deposit(&payer)
        .to_recipient(recipient_pqc)
        .with_memo(args.memo.clone())
        .revoke_after(revoke_window_secs);
    if let Some(auditor) = auditor_pqc {
        builder = builder.with_auditor(auditor);
    }
    let outcome = builder.send()?;
    let signature = outcome.signature;
    let note = outcome.note;
    let leaf_index = outcome.leaf_index;

    println!("  commitment   : {}", note.commitment().to_hex());
    println!("  signature    : {signature}");
    println!("  leaf index   : {leaf_index}");
    println!("  memo account : {}", outcome.memo_account);
    println!("  explorer     : https://explorer.solana.com/tx/{signature}");
    println!();

    // Save the note locally — Lena keeps it ONLY for a possible refund.
    fs::write(&args.note_out, note.to_text())
        .with_context(|| format!("write note to {}", args.note_out.display()))?;
    println!(
        "Note saved locally (for a refund only): {}",
        args.note_out.display()
    );
    println!("  → the parents do NOT need it; they scan the chain themselves.");

    // Append to Lena's local scan file.
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
        memo_account: outcome.memo_account.to_string(),
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

    Ok(())
}

/// Parse an ML-KEM-768 public key from hex.
fn parse_mlkem(input: &str) -> Result<PqcPublicKey> {
    let bytes = hex::decode(input.trim()).context("decode ML-KEM public key hex")?;
    PqcPublicKey::from_bytes(&bytes).map_err(|err| anyhow!("invalid ML-KEM public key: {err}"))
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
