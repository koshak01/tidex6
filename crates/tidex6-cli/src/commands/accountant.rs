//! `tidex6 accountant scan` — read every v2 memo account whose auditor
//! slot is addressed to the ML-KEM secret in the identity file and
//! render the result as a ledger (ADR-014).
//!
//! Read-only: never sends a transaction, never writes the secret
//! anywhere but local session memory. One `getProgramAccounts` pass
//! over the v2 program covers every pool — the amount comes from inside
//! each decrypted envelope, so there is no per-denomination loop.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};

use tidex6_client::{AccountantEntry, AccountantScanner, Denomination, PrivatePool};

use crate::commands::keygen::IdentityFile;
use crate::common::detect_cluster;

/// Arguments for `tidex6 accountant`.
#[derive(Args, Debug)]
pub struct AccountantArgs {
    #[command(subcommand)]
    pub command: AccountantCommand,
}

/// Top-level verbs under `tidex6 accountant`.
#[derive(Subcommand, Debug)]
pub enum AccountantCommand {
    /// Scan the v2 program and print every memo whose auditor slot
    /// decrypts under this identity's ML-KEM secret.
    Scan(ScanArgs),
}

/// Output format for the decoded ledger.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Table,
    Json,
    Csv,
}

/// Arguments for `tidex6 accountant scan`.
#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Identity file whose ML-KEM secret decrypts the auditor slots.
    /// Defaults to `~/.tidex6/identity.json`.
    #[arg(long)]
    pub identity: Option<PathBuf>,

    /// Output format. Defaults to the human-friendly table.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,

    /// Optional file to write the output to instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

/// Run `tidex6 accountant`.
pub fn run(args: AccountantArgs) -> Result<()> {
    match args.command {
        AccountantCommand::Scan(scan_args) => run_scan(scan_args),
    }
}

fn run_scan(args: ScanArgs) -> Result<()> {
    let identity_path = resolve_identity_path(args.identity)?;
    let identity = IdentityFile::load(&identity_path)
        .with_context(|| format!("failed to load identity from {}", identity_path.display()))?;
    let mlkem_secret = identity
        .load_mlkem_secret()
        .context("identity file is missing ML-KEM keys")?;

    let cluster = detect_cluster().context("failed to detect Solana cluster")?;
    // The v2 program id is the same for every denomination; connect to
    // any pool just to read it.
    let program_id = PrivatePool::connect(cluster.clone(), Denomination::OneSol)?.program_id();

    eprintln!("tidex6 accountant scan (ML-KEM)");
    eprintln!("  rpc      : {}", cluster.url());
    eprintln!("  identity : {}", identity_path.display());
    eprintln!("  program  : {program_id}");
    eprintln!();

    let scanner = AccountantScanner::new(cluster.url(), program_id, &mlkem_secret);
    let start = std::time::Instant::now();
    let entries = scanner.scan().context("memo-account scan failed")?;
    eprintln!(
        "  {} memo(s) addressed to this auditor ({:.1}s)",
        entries.len(),
        start.elapsed().as_secs_f64()
    );
    eprintln!();

    let rows: Vec<LedgerRow> = entries.into_iter().map(LedgerRow::from_entry).collect();

    let rendered = match args.format {
        OutputFormat::Table => render_table(&rows),
        OutputFormat::Json => render_json(&rows)?,
        OutputFormat::Csv => render_csv(&rows),
    };

    match args.output {
        Some(path) => {
            fs::write(&path, &rendered)
                .with_context(|| format!("write output to {}", path.display()))?;
            eprintln!("Wrote {} entries to {}", rows.len(), path.display());
        }
        None => {
            print!("{rendered}");
            if args.format != OutputFormat::Table {
                eprintln!("{} entries", rows.len());
            }
        }
    }

    Ok(())
}

/// One ledger row as the accountant command renders it.
#[derive(Clone, Debug)]
struct LedgerRow {
    commitment_hex: String,
    memo_account: String,
    denomination_lamports: u64,
    memo: String,
}

impl LedgerRow {
    fn from_entry(entry: AccountantEntry) -> Self {
        Self {
            commitment_hex: entry.commitment_hex.clone(),
            memo_account: entry.memo_account.to_string(),
            denomination_lamports: entry.denomination,
            memo: entry.plaintext_lossy(),
        }
    }

    fn amount_sol(&self) -> String {
        format!("{:.4}", self.denomination_lamports as f64 / 1_000_000_000.0)
    }
}

fn render_table(rows: &[LedgerRow]) -> String {
    if rows.is_empty() {
        return "No memos addressed to this auditor key were found.\n".to_string();
    }
    let mut out = String::new();
    out.push_str(&format!(
        "{:>4} │ {:<10} │ {:<40} │ {:<16}\n",
        "#", "Amount", "Memo", "Commitment"
    ));
    out.push_str(&"─".repeat(80));
    out.push('\n');
    for (i, row) in rows.iter().enumerate() {
        out.push_str(&format!(
            "{:>4} │ {:<10} │ {:<40} │ {}…\n",
            i + 1,
            row.amount_sol(),
            truncate_memo(&row.memo, 40),
            &row.commitment_hex[..row.commitment_hex.len().min(16)],
        ));
    }
    out.push_str(&format!("\n{} entries decoded for this auditor.\n", rows.len()));
    out
}

fn render_json(rows: &[LedgerRow]) -> Result<String> {
    let mut out = String::new();
    for row in rows {
        let obj = serde_json::json!({
            "commitment_hex": row.commitment_hex,
            "memo_account": row.memo_account,
            "amount_lamports": row.denomination_lamports,
            "amount_sol": row.amount_sol(),
            "memo": row.memo,
        });
        out.push_str(&serde_json::to_string(&obj).context("serialize ledger row")?);
        out.push('\n');
    }
    Ok(out)
}

fn render_csv(rows: &[LedgerRow]) -> String {
    let mut out = String::from("commitment_hex,memo_account,amount_lamports,amount_sol,memo\n");
    for row in rows {
        out.push_str(&format!(
            "{},{},{},{},{}\n",
            row.commitment_hex,
            row.memo_account,
            row.denomination_lamports,
            row.amount_sol(),
            csv_escape(&row.memo),
        ));
    }
    out
}

fn csv_escape(input: &str) -> String {
    if input.contains('"') || input.contains(',') || input.contains('\n') {
        let escaped = input.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        input.to_string()
    }
}

fn truncate_memo(memo: &str, max_chars: usize) -> String {
    if memo.chars().count() <= max_chars {
        let mut out = memo.to_string();
        while out.chars().count() < max_chars {
            out.push(' ');
        }
        out
    } else {
        let truncated: String = memo.chars().take(max_chars - 1).collect();
        format!("{truncated}…")
    }
}

fn resolve_identity_path(identity: Option<PathBuf>) -> Result<PathBuf> {
    match identity {
        Some(path) => Ok(path),
        None => {
            let home = std::env::var("HOME").context("HOME environment variable is not set")?;
            Ok(PathBuf::from(format!("{home}/.tidex6/identity.json")))
        }
    }
}
