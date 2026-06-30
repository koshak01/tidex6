//! `tidex6 deposit` — put a fresh `DepositNote` into the shielded pool
//! and seal it for a stealth recipient (ADR-014).
//!
//! Thin wrapper around `tidex6_client::PrivatePool::deposit`. The note
//! is encrypted to the recipient's ML-KEM public key and stored in the
//! on-chain memo account; the recipient scans the chain and withdraws
//! it themselves — it is never handed over. The note IS saved locally
//! for the depositor, because the depositor needs its `secret` /
//! `nullifier` to `refund` if the deposit is never claimed.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::Args;

use tidex6_client::PrivatePool;
use tidex6_core::note::Denomination;
use tidex6_core::pqc::PqcPublicKey;

use crate::commands::keygen::{IdentityFile, parse_mlkem_pk, resolve_output_path};
use crate::common::{detect_cluster, explorer_url, load_default_keypair};

/// Arguments for `tidex6 deposit`.
#[derive(Args, Debug)]
pub struct DepositArgs {
    /// Deposit denomination: `0.1`, `0.5`, `1`, or `10` (SOL).
    #[arg(long)]
    pub amount: String,

    /// Recipient ML-KEM-768 public key (hex). The note is sealed for
    /// this key; the recipient scans the chain and withdraws on their
    /// own — the note is never handed over. **Required.**
    #[arg(long)]
    pub recipient: String,

    /// Optional auditor ML-KEM public key (hex). The auditor gets a
    /// slot carrying amount + memo (cannot spend). Defaults to your own
    /// ML-KEM key from the identity file so you can audit your own
    /// deposits later. Pass `--no-auditor` to omit entirely.
    #[arg(long)]
    pub auditor: Option<String>,

    /// Omit the auditor slot entirely (no selective disclosure).
    #[arg(long, default_value_t = false)]
    pub no_auditor: bool,

    /// Memo plaintext — short description, e.g. `"Rent March 2026"`.
    /// Sealed for the recipient and (if present) the auditor.
    #[arg(long)]
    pub memo: String,

    /// Revoke window in days. After this many days, if the note was
    /// never withdrawn, you can `tidex6 refund` it. `0` (default) makes
    /// the deposit irrevocable.
    #[arg(long, default_value_t = 0)]
    pub revoke_after_days: u32,

    /// Optional custom Solana fee-payer keypair path.
    #[arg(long)]
    pub keypair: Option<PathBuf>,

    /// Where to write the local note file (kept by the depositor for a
    /// possible refund). Defaults to `~/.tidex6/notes/<prefix>.note`.
    #[arg(long)]
    pub note_out: Option<PathBuf>,

    /// Identity file for the default auditor key. Defaults to
    /// `~/.tidex6/identity.json`.
    #[arg(long)]
    pub identity: Option<PathBuf>,
}

/// Run `tidex6 deposit`.
pub fn run(args: DepositArgs) -> Result<()> {
    let denomination = parse_denomination(&args.amount)?;

    let payer = match args.keypair {
        Some(path) => solana_keypair::read_keypair_file(&path)
            .map_err(|err| anyhow!("failed to read keypair from {}: {err}", path.display()))?,
        None => load_default_keypair().context("failed to load default Solana keypair")?,
    };

    let cluster = detect_cluster().context("failed to detect Solana cluster")?;
    let pool = PrivatePool::connect(cluster.clone(), denomination)?;
    let payer_pubkey = {
        use anchor_client::Signer;
        <solana_keypair::Keypair as Signer>::pubkey(&payer)
    };

    let recipient_pqc = parse_mlkem_pk(&args.recipient)
        .context("invalid --recipient ML-KEM public key")?;
    let auditor_pqc = resolve_auditor_pk(args.auditor.as_deref(), args.no_auditor, args.identity.clone())?;
    let revoke_window_secs = (args.revoke_after_days as i64) * 86_400;

    println!("tidex6 deposit (stealth, ML-KEM)");
    println!("  cluster      : {}", cluster.url());
    println!("  payer        : {payer_pubkey}");
    println!(
        "  denomination : {} ({} lamports)",
        denomination,
        denomination.lamports()
    );
    println!("  pool pda     : {}", pool.pool_pda());
    match pool.next_leaf_index(&payer)? {
        Some(next) => println!("  pool status  : initialised, next_leaf_index = {next}"),
        None => println!("  pool status  : not initialised, init_pool will run first"),
    }
    println!("  recipient pk : {}…", &args.recipient[..16.min(args.recipient.len())]);
    println!(
        "  auditor      : {}",
        if auditor_pqc.is_some() { "yes (amount+memo slot)" } else { "none" }
    );
    println!(
        "  revoke       : {}",
        if revoke_window_secs == 0 {
            "irrevocable".to_string()
        } else {
            format!("after {} days", args.revoke_after_days)
        }
    );
    println!("  memo         : \"{}\" ({} bytes)", args.memo, args.memo.len());
    println!("Sending deposit via PrivatePool::deposit...");

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
    println!("  explorer     : {}", explorer_url(&signature, &cluster));
    println!("  leaf index   : {leaf_index}");
    println!("  memo account : {}", outcome.memo_account);

    // Save the note locally — the depositor needs it to `refund`.
    let note_text = note.to_text();
    let note_path = match args.note_out {
        Some(path) => path,
        None => default_note_path(&note.commitment().to_hex())?,
    };
    if let Some(parent) = note_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create notes directory {}", parent.display()))?;
    }
    fs::write(&note_path, &note_text)
        .with_context(|| format!("write note file to {}", note_path.display()))?;
    println!();
    println!("Note saved locally (for a possible refund): {}", note_path.display());
    println!("The recipient does NOT need it — they find this payment by scanning the");
    println!("chain with their ML-KEM key. Nothing was handed over.");

    Ok(())
}

/// `~/.tidex6/notes/<commitment_prefix>.note`.
fn default_note_path(commitment_hex: &str) -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    let prefix = &commitment_hex[..commitment_hex.len().min(12)];
    Ok(PathBuf::from(format!("{home}/.tidex6/notes/{prefix}.note")))
}

/// Resolve the auditor ML-KEM public key for this deposit.
///
/// - `--no-auditor` → `None` (no auditor slot).
/// - `--auditor <hex>` → parse and use it.
/// - otherwise → the user's own `mlkem_public` from the identity file
///   (audit your own deposits). Missing identity is a hard error unless
///   `--no-auditor` was given.
fn resolve_auditor_pk(
    explicit_hex: Option<&str>,
    no_auditor: bool,
    identity_path: Option<PathBuf>,
) -> Result<Option<PqcPublicKey>> {
    if no_auditor {
        return Ok(None);
    }
    if let Some(hex) = explicit_hex {
        return parse_mlkem_pk(hex)
            .map(Some)
            .with_context(|| format!("invalid --auditor value: {hex}"));
    }

    let path =
        resolve_output_path(identity_path).context("could not locate default identity path")?;
    let identity = IdentityFile::load(&path).with_context(|| {
        format!(
            "no --auditor given and no identity file at {}. \
             Run `tidex6 keygen`, pass --auditor <hex>, or --no-auditor.",
            path.display()
        )
    })?;
    parse_mlkem_pk(&identity.mlkem_public)
        .map(Some)
        .context("identity file contains a malformed mlkem_public")
}

/// Parse the user-supplied amount string into a fixed `Denomination`.
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
