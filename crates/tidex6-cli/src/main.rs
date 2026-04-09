//! `tidex6` — command-line interface for the tidex6 privacy
//! framework.
//!
//! Three subcommands wrap the existing offchain crypto primitives
//! and the onchain verifier program into a user-facing experience:
//!
//! ```text
//! tidex6 keygen [--out <file>] [--force]
//! tidex6 deposit --amount <0.1|1|10> [--note-out <file>]
//! tidex6 withdraw --note <file> --to <pubkey> [--leaf-index <n>]
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

    /// Put a fresh `DepositNote` into the shielded pool for a
    /// given denomination and save the note to a file.
    Deposit(commands::deposit::DepositArgs),

    /// Redeem a previously-generated `DepositNote` by proving
    /// knowledge of its preimage in zero knowledge.
    Withdraw(commands::withdraw::WithdrawArgs),
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen(args) => commands::keygen::run(args),
        Command::Deposit(args) => commands::deposit::run(args),
        Command::Withdraw(args) => commands::withdraw::run(args),
    }
}
