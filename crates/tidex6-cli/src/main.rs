//! `tidex6` — command-line interface for the tidex6 privacy
//! framework.
//!
//! The subcommands wrap the offchain crypto primitives and the onchain
//! verifier into a note-free stealth experience: you deposit sealed for a
//! recipient's ML-KEM public key, and the recipient scans the chain with
//! their own secret and withdraws. Nothing is ever handed over.
//!
//! ```text
//! tidex6 keygen [--out <file>] [--force]
//! tidex6 keygen print-mlkem-pk [--identity <file>]
//! tidex6 deposit --amount <0.1|0.5|1|10> --recipient <mlkem-pk>
//!                [--auditor <pk>] [--memo <text>]
//! tidex6 receive --identity <file> --to <pubkey>
//! tidex6 accountant scan [--identity <file>] [--amount <d>]
//!                        [--format table|json|csv] [--output <file>]
//! ```
//!
//! The commands operate on whichever Solana cluster is configured
//! in `~/.config/solana/cli/config.yml` (defaulting to devnet).
//! The fee payer is `~/.config/solana/id.json` unless overridden
//! with `--keypair`.

mod commands;
mod common;

use anyhow::Result;
use clap::{Parser, Subcommand};

/// Top-level CLI definition.
#[derive(Parser, Debug)]
#[command(
    name = "tidex6",
    about = "tidex6 — privacy framework for Solana. I grant access, not permission.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// All top-level subcommands.
#[derive(Subcommand, Debug)]
enum Command {
    /// Generate a fresh spending key + derived viewing key and
    /// write them to a JSON identity file.
    Keygen(commands::keygen::KeygenArgs),

    /// Deposit SOL into the shielded pool, sealed for a stealth
    /// recipient's ML-KEM key. Nothing is handed over — the recipient
    /// scans and withdraws with `receive`.
    Deposit(commands::deposit::DepositArgs),

    /// Read every Shielded Memo addressed to this identity's
    /// auditor secret key and render the result as a ledger.
    Accountant(commands::accountant::AccountantArgs),

    /// Stealth receipt: scan the chain with your ML-KEM key, find
    /// payments addressed to you, and withdraw them — no note needed.
    Receive(commands::receive::ReceiveArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(args) => commands::keygen::run(args),
        Command::Deposit(args) => commands::deposit::run(args),
        Command::Accountant(args) => commands::accountant::run(args),
        Command::Receive(args) => commands::receive::run(args),
    }
}
