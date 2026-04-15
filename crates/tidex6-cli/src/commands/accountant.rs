//! `tidex6 accountant scan` — read every Shielded Memo addressed
//! to the auditor secret held in the user's identity file and
//! render the result as a human-readable ledger.
//!
//! The scan is strictly read-only: it never sends a transaction,
//! never modifies the identity file, and never writes the auditor
//! secret anywhere but the local session memory.

use std::fs;
use std::path::PathBuf;

use anchor_client::Cluster;
use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand, ValueEnum};

use tidex6_client::{AccountantEntry, AccountantScanner, PrivatePool};
use tidex6_core::note::Denomination;

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
    /// Scan one or all shielded pools and print every memo that
    /// decrypts under this identity's auditor secret.
    Scan(ScanArgs),
}

/// Output format for the decoded ledger.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Pretty-printed ASCII table — the default, suitable for a
    /// terminal.
    Table,
    /// Newline-delimited JSON, one object per entry. Feed directly
    /// into `jq` or pipe into a spreadsheet import.
    Json,
    /// Comma-separated values with a header row.
    Csv,
}

/// Arguments for `tidex6 accountant scan`.
#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Path to the identity file whose auditor secret key will be
    /// used for decryption. Defaults to `~/.tidex6/identity.json`.
    #[arg(long)]
    pub identity: Option<PathBuf>,

    /// Denomination of the pool to scan. When omitted, every
    /// supported denomination is scanned sequentially and the
    /// results merged into one ledger.
    #[arg(long)]
    pub amount: Option<String>,

    /// Output format. Defaults to the human-friendly table.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    pub format: OutputFormat,

    /// Optional file to write the output to instead of stdout.
    /// Useful for exporting a CSV straight to the accountant.
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
    let auditor_sk = identity
        .load_auditor_secret_key()
        .context("identity file is missing auditor keys")?;

    let cluster = detect_cluster().context("failed to detect Solana cluster")?;

    // Figure out which pools to scan. The user can filter to one
    // denomination; otherwise we walk all supported denominations
    // so a single `tidex6 accountant scan` sees the whole ledger.
    let denominations: Vec<Denomination> = match args.amount.as_deref() {
        Some(amount_str) => vec![parse_denomination(amount_str)?],
        None => vec![
            Denomination::OneTenthSol,
            Denomination::HalfSol,
            Denomination::OneSol,
            Denomination::TenSol,
        ],
    };

    // Progress output so the user sees what is happening while we
    // hit the RPC for every pool and every transaction. The scan
    // walks `getSignaturesForAddress` + `getTransaction` per tx — on
    // a pool with a long history this is the rate-limiting step.
    eprintln!("tidex6 accountant scan");
    eprintln!("  rpc      : {}", cluster.url());
    eprintln!("  identity : {}", identity_path.display());
    eprintln!("  auditor  : {}", identity.auditor_public_key);
    eprintln!();

    let mut all_entries: Vec<LedgerRow> = Vec::new();
    for denomination in denominations {
        let pool = PrivatePool::connect(cluster.clone(), denomination)
            .with_context(|| format!("connect to {denomination} pool"))?;
        eprintln!(
            "  scanning {:<8}  pool {}...",
            denomination.to_string(),
            pool.pool_pda()
        );
        let scanner = AccountantScanner::new(cluster.url(), pool.pool_pda(), &auditor_sk);
        let start = std::time::Instant::now();
        match scanner.scan() {
            Ok(entries) => {
                let elapsed = start.elapsed();
                eprintln!(
                    "    ↳ {} memo(s) addressed to this auditor ({:.1}s)",
                    entries.len(),
                    elapsed.as_secs_f64()
                );
                for entry in entries {
                    all_entries.push(LedgerRow::from_entry(entry, denomination));
                }
            }
            // A pool the user has never used yet returns an empty
            // history, which is fine. A genuine RPC failure should
            // still stop the whole scan so the user does not get a
            // half-complete ledger.
            Err(err) => {
                return Err(anyhow!("scan of {denomination} pool failed: {err}"));
            }
        }
    }
    eprintln!();

    // Sort by ascending block time so the ledger reads
    // chronologically regardless of which pool the entry came from.
    all_entries.sort_by_key(|row| row.block_time.unwrap_or(i64::MAX));

    let rendered = match args.format {
        OutputFormat::Table => render_table(&all_entries),
        OutputFormat::Json => render_json(&all_entries)?,
        OutputFormat::Csv => render_csv(&all_entries),
    };

    match args.output {
        Some(path) => {
            fs::write(&path, &rendered)
                .with_context(|| format!("write output to {}", path.display()))?;
            eprintln!("Wrote {} entries to {}", all_entries.len(), path.display());
        }
        None => {
            print!("{rendered}");
            if args.format != OutputFormat::Table {
                // Table already prints its own footer; JSON/CSV do
                // not, so add a stderr note for the user.
                eprintln!("{} entries", all_entries.len());
            }
        }
    }

    Ok(())
}

/// One row of the reconstructed ledger as the accountant command
/// renders it — enriches `AccountantEntry` with the denomination
/// of the pool the entry came from so a merged multi-pool report
/// is still unambiguous.
#[derive(Clone, Debug)]
struct LedgerRow {
    leaf_index: u64,
    commitment_hex: String,
    signature: String,
    block_time: Option<i64>,
    memo: String,
    denomination: Denomination,
}

impl LedgerRow {
    fn from_entry(entry: AccountantEntry, denomination: Denomination) -> Self {
        let memo = entry.plaintext_lossy();
        Self {
            leaf_index: entry.leaf_index,
            commitment_hex: entry.commitment_hex,
            signature: entry.signature,
            block_time: entry.block_time,
            memo,
            denomination,
        }
    }

    fn date_string(&self) -> String {
        match self.block_time {
            Some(ts) => format_unix_ts(ts),
            None => "—".to_string(),
        }
    }
}

fn render_table(rows: &[LedgerRow]) -> String {
    if rows.is_empty() {
        return "No memos addressed to this auditor key were found in the scanned pools.\n"
            .to_string();
    }

    // Simple pipe-and-dash table. We deliberately don't pull in
    // comfy-table here because a hand-rolled renderer keeps the
    // CLI binary small, has no lint pitfalls, and is easy to read
    // when debugging an RPC-sourced dataset.
    let mut header = String::new();
    header.push_str(&format!(
        "{:>4} │ {:<10} │ {:<8} │ {:<6} │ {:<40} │ {}\n",
        "#", "Date", "Amount", "Leaf", "Memo", "Signature"
    ));
    header.push_str(&"─".repeat(110));
    header.push('\n');

    let mut body = String::new();
    for (i, row) in rows.iter().enumerate() {
        let memo_display = truncate_memo(&row.memo, 40);
        body.push_str(&format!(
            "{:>4} │ {:<10} │ {:<8} │ {:<6} │ {:<40} │ {}…\n",
            i + 1,
            row.date_string(),
            row.denomination,
            row.leaf_index,
            memo_display,
            &row.signature[..row.signature.len().min(16)],
        ));
    }

    let footer = format!("\n{} entries decoded for this auditor.\n", rows.len());
    format!("{header}{body}{footer}")
}

fn render_json(rows: &[LedgerRow]) -> Result<String> {
    let mut out = String::new();
    for row in rows {
        let obj = serde_json::json!({
            "leaf_index": row.leaf_index,
            "commitment_hex": row.commitment_hex,
            "signature": row.signature,
            "block_time": row.block_time,
            "date": row.date_string(),
            "amount": row.denomination.to_string(),
            "amount_lamports": row.denomination.lamports(),
            "memo": row.memo,
        });
        out.push_str(&serde_json::to_string(&obj).context("serialize ledger row")?);
        out.push('\n');
    }
    Ok(out)
}

fn render_csv(rows: &[LedgerRow]) -> String {
    let mut out = String::from(
        "leaf_index,commitment_hex,signature,block_time,date,amount,amount_lamports,memo\n",
    );
    for row in rows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            row.leaf_index,
            row.commitment_hex,
            row.signature,
            row.block_time
                .map(|t| t.to_string())
                .unwrap_or_else(|| "".to_string()),
            row.date_string(),
            row.denomination,
            row.denomination.lamports(),
            csv_escape(&row.memo),
        ));
    }
    out
}

/// Minimal RFC4180-style CSV escaping for the memo field.
fn csv_escape(input: &str) -> String {
    if input.contains('"') || input.contains(',') || input.contains('\n') {
        let escaped = input.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        input.to_string()
    }
}

/// Truncate a memo string for table display, adding an ellipsis
/// when shortened. Operates on bytes since short memos are
/// dominated by ASCII; if a memo is non-ASCII the byte boundary may
/// cut a codepoint but `from_utf8_lossy` already ran upstream so
/// the result is guaranteed valid UTF-8.
fn truncate_memo(memo: &str, max_chars: usize) -> String {
    if memo.chars().count() <= max_chars {
        let mut out = memo.to_string();
        // pad to align the table column
        while out.chars().count() < max_chars {
            out.push(' ');
        }
        out
    } else {
        let truncated: String = memo.chars().take(max_chars - 1).collect();
        format!("{truncated}…")
    }
}

/// Format a Unix timestamp as `YYYY-MM-DD`. The CLI does not pull
/// in chrono for this — a local-date formatter adds another ~300KB
/// to the binary and the exact timezone is not load-bearing for an
/// accountant-style ledger. The formatting matches UTC.
fn format_unix_ts(ts: i64) -> String {
    // Days since 1970-01-01. This is a minimal civil-from-days
    // algorithm by Howard Hinnant (public domain), sufficient for
    // display purposes.
    let mut z = ts.div_euclid(86_400) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    let _ = &mut z;
    format!("{year:04}-{m:02}-{d:02}")
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

fn parse_denomination(input: &str) -> Result<Denomination> {
    let cleaned = input
        .trim()
        .trim_end_matches(|c: char| c.is_ascii_alphabetic() || c == ' ')
        .trim();
    match cleaned {
        "0.1" => Ok(Denomination::OneTenthSol),
        "0.5" => Ok(Denomination::HalfSol),
        "1" | "1.0" => Ok(Denomination::OneSol),
        "10" | "10.0" => Ok(Denomination::TenSol),
        _ => Err(anyhow!(
            "unsupported denomination {input}: expected 0.1, 0.5, 1, or 10"
        )),
    }
}

// Suppress unused-import warning when only the `Cluster` type is
// referenced via detect_cluster().
#[allow(dead_code)]
type _ClusterAlias = Cluster;
