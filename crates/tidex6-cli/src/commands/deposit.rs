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
use tidex6_core::note::Denomination;

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

    println!();
    println!("Sending deposit via PrivatePool::deposit...");
    let (signature, note, leaf_index) = pool.deposit(&payer).send()?;

    println!("  commitment   : {}", note.commitment().to_hex());
    println!("  signature    : {signature}");
    println!("  explorer     : {}", devnet_explorer_url(&signature));
    println!("  leaf index   : {leaf_index}");

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
