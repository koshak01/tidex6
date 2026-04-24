//! `tidex6 withdraw` — redeem a `DepositNote` by generating a
//! zero-knowledge withdrawal proof.
//!
//! After Day 15 this is a thin wrapper around
//! `tidex6_client::PrivatePool::withdraw`. The SDK handles tree
//! rebuild, proof generation, byte conversion and transaction
//! submission internally.

use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result, anyhow};
use clap::Args;

use tidex6_client::PrivatePool;
use tidex6_core::note::DepositNote;

use crate::common::{detect_cluster, explorer_url, load_default_keypair};

/// Arguments for `tidex6 withdraw`.
#[derive(Args, Debug)]
pub struct WithdrawArgs {
    /// Path to the note file produced by a previous
    /// `tidex6 deposit` run.
    #[arg(long)]
    pub note: PathBuf,

    /// Recipient Solana account — will receive the `denomination`
    /// lamports on success.
    #[arg(long)]
    pub to: String,

    /// Optional custom path to the fee payer keypair. Defaults to
    /// `~/.config/solana/id.json`.
    #[arg(long)]
    pub keypair: Option<PathBuf>,

    /// Submit via a relayer service instead of signing locally
    /// (ADR-011). Accepts the relayer's HTTPS URL. Pair with
    /// `--relayer-pubkey` so the Groth16 proof binds to the
    /// specific relayer. Default behavior (flag absent) is the
    /// legacy direct path where the user signs the withdraw.
    #[arg(long)]
    pub relayer: Option<String>,

    /// Relayer pubkey to commit to when `--relayer` is set. Must
    /// match the pubkey the relayer service itself uses; otherwise
    /// the on-chain verifier rejects the proof.
    #[arg(long)]
    pub relayer_pubkey: Option<String>,

    /// Explicitly force the legacy direct path. Equivalent to
    /// omitting `--relayer`, but makes the choice visible in
    /// scripts and logs.
    #[arg(long, conflicts_with = "relayer")]
    pub direct: bool,
}

/// Run `tidex6 withdraw`.
pub fn run(args: WithdrawArgs) -> Result<()> {
    let note_text = fs::read_to_string(&args.note)
        .with_context(|| format!("read note {}", args.note.display()))?;
    let note = DepositNote::from_text(&note_text).context("parse note file")?;

    let payer = match args.keypair {
        Some(path) => solana_keypair::read_keypair_file(&path)
            .map_err(|err| anyhow!("failed to read keypair from {}: {err}", path.display()))?,
        None => load_default_keypair().context("failed to load default Solana keypair")?,
    };

    let recipient = Pubkey::from_str(&args.to)
        .with_context(|| format!("parse recipient pubkey {}", args.to))?;

    let cluster = detect_cluster().context("failed to detect Solana cluster")?;
    let pool = PrivatePool::connect(cluster.clone(), note.denomination())?;
    let payer_pubkey = {
        use anchor_client::Signer;
        <solana_keypair::Keypair as Signer>::pubkey(&payer)
    };

    println!("tidex6 withdraw");
    println!("  cluster      : {}", cluster.url());
    println!("  payer        : {payer_pubkey}");
    println!(
        "  denomination : {} ({} lamports)",
        note.denomination(),
        note.denomination().lamports()
    );
    println!("  recipient    : {recipient}");
    println!("  commitment   : {}", note.commitment().to_hex());
    println!("  pool pda     : {}", pool.pool_pda());
    println!("  vault pda    : {}", pool.vault_pda());
    if let Some(memo) = note.memo() {
        println!();
        println!("  ┌──────────────────────────────────────────┐");
        println!("  │ Memo from the sender:                    │");
        println!("  │ {memo}");
        println!("  └──────────────────────────────────────────┘");
    }

    println!();
    match &args.relayer {
        Some(url) => println!("Sending withdraw via relayer at {url} ..."),
        None if args.direct => println!("Sending withdraw via direct path (user-signed) ..."),
        None => println!("Sending withdraw via direct path (default) ..."),
    }
    println!("(Indexer rebuild + proof generation may take 10-30 seconds.)");

    let mut builder = pool.withdraw(&payer).note(note).to(recipient);
    if let Some(url) = &args.relayer {
        let relayer_pubkey_str = args.relayer_pubkey.as_ref().ok_or_else(|| {
            anyhow!("--relayer requires --relayer-pubkey; pass the relayer's public key")
        })?;
        let relayer_pubkey = Pubkey::from_str(relayer_pubkey_str)
            .with_context(|| format!("parse relayer pubkey {relayer_pubkey_str}"))?;
        builder = builder.via_relayer(url.clone(), relayer_pubkey);
    } else if args.direct {
        builder = builder.direct();
    }

    let signature = builder.send()?;

    println!("  signature    : {signature}");
    println!("  explorer     : {}", explorer_url(&signature, &cluster));
    println!();
    println!(
        "Recipient {recipient} received {} lamports.",
        pool.denomination().lamports()
    );

    Ok(())
}
