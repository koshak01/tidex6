//! Minimal shared helpers used by the CLI subcommands after the
//! Day-15 refactor. The bulk of the deposit/withdraw logic now
//! lives in `tidex6-client`; this module only keeps the helpers
//! that are specific to the CLI interactive surface (keypair
//! loading, cluster detection from the user's Solana config,
//! explorer URL formatting).

use anchor_client::Cluster;
use anyhow::{Context, Result, anyhow};
use solana_keypair::{Keypair, read_keypair_file};

/// Load the user's default Solana keypair from
/// `~/.config/solana/id.json`. Used as the tx fee payer across
/// every CLI subcommand.
pub fn load_default_keypair() -> Result<Keypair> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    let path = format!("{home}/.config/solana/id.json");
    read_keypair_file(&path).map_err(|err| anyhow!("failed to read keypair from {path}: {err}"))
}

/// Detect which Solana cluster is currently configured in the
/// user's Solana CLI config file. Defaults to devnet if no config
/// is found or if the URL is not recognised.
pub fn detect_cluster() -> Result<Cluster> {
    let home = std::env::var("HOME").context("HOME environment variable is not set")?;
    let path = format!("{home}/.config/solana/cli/config.yml");

    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Ok(Cluster::Devnet);
    };

    let url = contents
        .lines()
        .find_map(|line| line.trim().strip_prefix("json_rpc_url:"))
        .map(|value| value.trim().trim_matches('"').to_string());

    // Priority: exact match of the public Solana Foundation endpoints
    // first, then treat anything else http(s) as a custom RPC. The
    // custom path is critical for Helius / QuickNode / Triton users —
    // an earlier version fell through `contains("mainnet")` and quietly
    // replaced the user's Helius URL with the public rate-limited one.
    match url.as_deref() {
        Some("https://api.devnet.solana.com") => Ok(Cluster::Devnet),
        Some("https://api.mainnet-beta.solana.com") => Ok(Cluster::Mainnet),
        Some("https://api.testnet.solana.com") => Ok(Cluster::Testnet),
        Some(u) if u.starts_with("http") => Ok(Cluster::Custom(u.to_string(), u.to_string())),
        _ => Ok(Cluster::Devnet),
    }
}

/// Format a Solana explorer URL for a transaction signature,
/// picking the correct `?cluster=` suffix based on where the CLI
/// is currently pointed. Mainnet uses no suffix (the explorer
/// defaults to mainnet-beta); devnet/testnet use the explicit
/// suffix. Custom-RPC users get a mainnet-beta-shaped URL because
/// that is by far the most common case for integrator-local RPCs.
pub fn explorer_url(signature: &solana_signature::Signature, cluster: &Cluster) -> String {
    match cluster {
        Cluster::Devnet => format!("https://explorer.solana.com/tx/{signature}?cluster=devnet"),
        Cluster::Testnet => format!("https://explorer.solana.com/tx/{signature}?cluster=testnet"),
        _ => format!("https://explorer.solana.com/tx/{signature}"),
    }
}
