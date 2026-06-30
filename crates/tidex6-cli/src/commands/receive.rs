//! `tidex6 receive` — stealth receipt (ADR-014, A9).
//!
//! The recipient scans the chain with their ML-KEM secret, finds every
//! payment addressed to them, reconstructs the note from the decrypted
//! recipient slot, and withdraws each to a chosen Solana account. **No
//! note was ever handed over** — the chain itself delivers the payment.

use std::path::PathBuf;
use std::str::FromStr;

use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result, anyhow};
use clap::Args;

use tidex6_client::{Denomination, PrivatePool, RecipientScanner};
use tidex6_core::note::DepositNote;
use tidex6_core::types::{Nullifier, Secret};

use crate::commands::keygen::IdentityFile;
use crate::common::{detect_cluster, explorer_url, load_default_keypair};

/// Arguments for `tidex6 receive`.
#[derive(Args, Debug)]
pub struct ReceiveArgs {
    /// Identity file holding the ML-KEM secret used to find payments.
    /// Defaults to `~/.tidex6/identity.json`.
    #[arg(long)]
    pub identity: Option<PathBuf>,

    /// Solana account that receives the withdrawn SOL.
    #[arg(long)]
    pub to: String,

    /// Optional custom fee-payer keypair.
    #[arg(long)]
    pub keypair: Option<PathBuf>,
}

/// Run `tidex6 receive`.
pub fn run(args: ReceiveArgs) -> Result<()> {
    let identity_path = match args.identity {
        Some(path) => path,
        None => {
            let home = std::env::var("HOME").context("HOME environment variable is not set")?;
            PathBuf::from(format!("{home}/.tidex6/identity.json"))
        }
    };
    let identity = IdentityFile::load(&identity_path)
        .with_context(|| format!("load identity from {}", identity_path.display()))?;
    let mlkem_secret = identity
        .load_mlkem_secret()
        .context("identity file is missing ML-KEM keys")?;

    let payer = match args.keypair {
        Some(path) => solana_keypair::read_keypair_file(&path)
            .map_err(|err| anyhow!("failed to read keypair from {}: {err}", path.display()))?,
        None => load_default_keypair().context("failed to load default Solana keypair")?,
    };
    let recipient = Pubkey::from_str(&args.to)
        .with_context(|| format!("parse recipient pubkey {}", args.to))?;

    let cluster = detect_cluster().context("failed to detect Solana cluster")?;
    let program_id = PrivatePool::connect(cluster.clone(), Denomination::OneSol)?.program_id();

    println!("tidex6 receive (stealth)");
    println!("  rpc        : {}", cluster.url());
    println!("  identity   : {}", identity_path.display());
    println!("  to         : {recipient}");
    println!("Scanning the chain with your ML-KEM key for payments addressed to you...");

    let scanner = RecipientScanner::new(cluster.url(), program_id, &mlkem_secret);
    let entries = scanner.scan().context("recipient scan failed")?;

    if entries.is_empty() {
        println!("No payments addressed to you were found.");
        return Ok(());
    }
    println!("Found {} payment(s) for you. Withdrawing each...", entries.len());

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
        println!("  payment    : {} ({})", denomination, entry.commitment_hex);
        if !memo.trim().is_empty() {
            println!("  memo       : \"{memo}\"");
        }
        println!("  withdrawing to {recipient}...");

        let pool = PrivatePool::connect(cluster.clone(), denomination)?;
        let outcome = pool.withdraw(&payer).note(note).to(recipient).send()?;
        println!("  signature  : {}", outcome.signature);
        println!("  explorer   : {}", explorer_url(&outcome.signature, &cluster));
    }

    println!();
    println!("Done. Payments were found by scanning — no note was ever handed to you.");

    Ok(())
}

/// Map a lamports amount back to a fixed `Denomination`.
fn denom_from_lamports(lamports: u64) -> Result<Denomination> {
    match lamports {
        100_000_000 => Ok(Denomination::OneTenthSol),
        500_000_000 => Ok(Denomination::HalfSol),
        1_000_000_000 => Ok(Denomination::OneSol),
        10_000_000_000 => Ok(Denomination::TenSol),
        other => Err(anyhow!("unknown denomination: {other} lamports")),
    }
}
