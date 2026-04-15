//! `tidex6 deposit` — put a fresh `DepositNote` into the shielded
//! pool for a given denomination.
//!
//! After Day 15 this is a thin wrapper around
//! `tidex6_client::PrivatePool::deposit`. The heavy lifting
//! (pool init, tx construction, log parsing) lives in the SDK.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::Args;

use tidex6_client::PrivatePool;
use tidex6_core::elgamal::AuditorPublicKey;
use tidex6_core::note::Denomination;

use crate::commands::keygen::{IdentityFile, resolve_output_path};
use crate::common::{detect_cluster, devnet_explorer_url, load_default_keypair};

/// Arguments for `tidex6 deposit`.
#[derive(Args, Debug)]
pub struct DepositArgs {
    /// Deposit denomination. Must be one of the supported fixed
    /// amounts: `0.1`, `0.5`, `1`, or `10` (SOL).
    #[arg(long)]
    pub amount: String,

    /// Where to write the note file. The note is the offline
    /// capability the recipient needs to withdraw. Defaults to
    /// `./<commitment_prefix>.note` in the current directory.
    #[arg(long)]
    pub note_out: Option<PathBuf>,

    /// Optional custom path to the Solana fee payer keypair.
    /// Defaults to `~/.config/solana/id.json`.
    #[arg(long)]
    pub keypair: Option<PathBuf>,

    /// Auditor public key (Baby Jubjub, 64-character hex). The memo
    /// is encrypted under this key and attached to the deposit
    /// transaction. Omit to default to your own auditor public key
    /// from `~/.tidex6/identity.json` — that way the memo is still
    /// recoverable later via `tidex6 accountant scan --identity
    /// <same file>` even if no external bookkeeper was involved.
    #[arg(long)]
    pub auditor: Option<String>,

    /// Memo plaintext — short description of this deposit, for
    /// example `"Rent March 2026"`. **Required.** The memo is both
    /// encrypted for the auditor (SPL Memo on chain) *and* stored
    /// in the note file for the recipient. Both sides read the
    /// same sentence through different channels.
    #[arg(long)]
    pub memo: String,

    /// Path to the identity file used to fill in the default auditor
    /// public key when `--auditor` is not given. Defaults to
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

    println!("tidex6 deposit");
    println!("  cluster      : {}", cluster.url());
    println!("  payer        : {payer_pubkey}");
    println!(
        "  denomination : {} ({} lamports)",
        denomination,
        denomination.lamports()
    );
    println!("  pool pda     : {}", pool.pool_pda());
    println!("  vault pda    : {}", pool.vault_pda());

    // Show pool status up front so the user knows whether
    // `init_pool` will run as part of this deposit.
    match pool.next_leaf_index(&payer)? {
        Some(next) => println!("  pool status  : initialised, next_leaf_index = {next}"),
        None => println!("  pool status  : not initialised, init_pool will run first"),
    }

    // Resolve the auditor pubkey. Priority: explicit --auditor,
    // then the user's own auditor_public_key from the identity
    // file. Failing both is a hard error — tidex6 always encrypts
    // the memo, never ships plaintext onchain.
    let auditor_pk = resolve_auditor_pk(args.auditor.as_deref(), args.identity.clone())
        .context("could not determine an auditor public key for this deposit")?;

    println!();
    println!(
        "  memo         : \"{}\" ({} bytes, encrypted for auditor)",
        args.memo,
        args.memo.len()
    );
    println!("  auditor pk   : {}", auditor_pk.to_hex());
    println!("Sending deposit via PrivatePool::deposit...");

    let outcome = pool
        .deposit(&payer)
        .with_auditor(auditor_pk)
        .with_memo(args.memo.clone())
        .send()?;
    let signature = outcome.signature;
    let note = outcome.note;
    let leaf_index = outcome.leaf_index;

    println!("  commitment   : {}", note.commitment().to_hex());
    println!("  signature    : {signature}");
    println!("  explorer     : {}", devnet_explorer_url(&signature));
    println!("  leaf index   : {leaf_index}");
    if let Some(memo_b64) = outcome.memo_base64.as_ref() {
        println!(
            "  memo payload : {} base64 chars in SPL Memo instruction",
            memo_b64.len()
        );
    }

    // Persist the note so the recipient can redeem it later.
    let note_text = note.to_text();
    let note_path = args
        .note_out
        .unwrap_or_else(|| PathBuf::from(format!("./{}.note", &note.commitment().to_hex()[..12])));
    fs::write(&note_path, &note_text)
        .with_context(|| format!("write note file to {}", note_path.display()))?;
    println!();
    println!("Note written to: {}", note_path.display());
    println!("Share this file with the recipient to let them withdraw.");

    Ok(())
}

/// Resolve the auditor public key for this deposit.
///
/// - If `--auditor` was explicitly passed, parse and return it.
/// - Otherwise, load the identity file (default
///   `~/.tidex6/identity.json`) and use its `auditor_public_key`.
/// - Fail loudly if neither is available: tidex6 never ships an
///   unencrypted memo.
fn resolve_auditor_pk(
    explicit_hex: Option<&str>,
    identity_path: Option<PathBuf>,
) -> Result<AuditorPublicKey> {
    if let Some(hex) = explicit_hex {
        return AuditorPublicKey::from_hex(hex)
            .with_context(|| format!("invalid --auditor value: {hex}"));
    }

    let path = resolve_output_path(identity_path)
        .context("could not locate default identity path")?;
    let identity = IdentityFile::load(&path).with_context(|| {
        format!(
            "no --auditor given and no identity file at {}. \
             Run `tidex6 keygen` first or pass --auditor <hex>.",
            path.display()
        )
    })?;
    if identity.auditor_public_key.is_empty() {
        return Err(anyhow!(
            "identity at {} has no auditor public key (v1 format); regenerate with `tidex6 keygen --force`",
            path.display()
        ));
    }
    AuditorPublicKey::from_hex(&identity.auditor_public_key)
        .context("identity file contains a malformed auditor_public_key")
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
