//! `tidex6 refund` — 30-day revoke. Reclaim a never-withdrawn deposit
//! using the note the depositor kept locally (ADR-014).

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::Args;

use tidex6_client::PrivatePool;
use tidex6_core::note::DepositNote;

use crate::common::{detect_cluster, explorer_url, load_default_keypair};

/// Arguments for `tidex6 refund`.
#[derive(Args, Debug)]
pub struct RefundArgs {
    /// Note file kept locally when the deposit was made.
    #[arg(long)]
    pub note: PathBuf,

    /// Optional custom fee-payer keypair. Must be the original
    /// depositor — the refund returns to this account.
    #[arg(long)]
    pub keypair: Option<PathBuf>,
}

/// Run `tidex6 refund`.
pub fn run(args: RefundArgs) -> Result<()> {
    let note_text = fs::read_to_string(&args.note)
        .with_context(|| format!("read note {}", args.note.display()))?;
    let note = DepositNote::from_text(&note_text).context("parse note file")?;

    let payer = match args.keypair {
        Some(path) => solana_keypair::read_keypair_file(&path)
            .map_err(|err| anyhow!("failed to read keypair from {}: {err}", path.display()))?,
        None => load_default_keypair().context("failed to load default Solana keypair")?,
    };

    let cluster = detect_cluster().context("failed to detect Solana cluster")?;
    let pool = PrivatePool::connect(cluster.clone(), note.denomination())?;

    println!("tidex6 refund (30-day revoke)");
    println!("  cluster      : {}", cluster.url());
    println!(
        "  denomination : {} ({} lamports)",
        note.denomination(),
        note.denomination().lamports()
    );
    println!("  commitment   : {}", note.commitment().to_hex());
    println!("Sending refund (proves ownership on-chain, returns the deposit)...");

    let signature = pool.refund(&payer).note(note).send()?;

    println!("  signature    : {signature}");
    println!("  explorer     : {}", explorer_url(&signature, &cluster));
    println!();
    println!("Deposit returned. The note is now permanently spent — it can never be withdrawn.");

    Ok(())
}
