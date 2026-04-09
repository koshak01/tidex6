//! `tidex6 keygen` — generate a fresh spending key + viewing key
//! and write them to a JSON file.
//!
//! The output file is a minimal wallet identity: one spending key
//! (the master secret) and the derived viewing key (a read-only
//! capability the user can share with an accountant or an auditor).
//! Both are stored as lowercase hex strings for easy copy/paste
//! across platforms.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::Args;
use serde::{Deserialize, Serialize};

use tidex6_core::keys::{SpendingKey, ViewingKey};

/// Arguments for `tidex6 keygen`.
#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Where to write the identity file. Defaults to
    /// `~/.tidex6/identity.json`, creating the directory if it does
    /// not exist yet.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Overwrite the output file if it already exists. Without this
    /// flag the command refuses to clobber an existing identity to
    /// avoid accidentally destroying a user's wallet.
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

/// On-disk representation of a tidex6 wallet identity.
///
/// Deliberately stored in the clear for now — MVP assumes the user
/// keeps this file on an encrypted disk or in a trusted location.
/// Before mainnet: either encrypt at rest with a passphrase or
/// delegate to the OS keychain. Tracked in ROADMAP v0.2.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityFile {
    /// Protocol version of the identity file layout. Used for
    /// forward compatibility when the schema evolves.
    pub version: u32,
    /// Lowercase hex of the raw `SpendingKey` bytes. The `0x` prefix
    /// is omitted for easier clipboard handling.
    pub spending_key: String,
    /// Lowercase hex of the derived `ViewingKey` bytes. Shareable
    /// with a trusted third party for selective disclosure.
    pub viewing_key: String,
}

impl IdentityFile {
    pub const CURRENT_VERSION: u32 = 1;
}

/// Run `tidex6 keygen`.
pub fn run(args: KeygenArgs) -> Result<()> {
    let output_path = resolve_output_path(args.out)?;

    if output_path.exists() && !args.force {
        return Err(anyhow!(
            "identity file already exists at {}. Use --force to overwrite.",
            output_path.display()
        ));
    }

    // Make sure the parent directory exists. `~/.tidex6/` may not
    // have been created yet on a fresh machine.
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }

    // Generate the spending key from the OS CSPRNG with rejection
    // sampling against the BN254 scalar field, then derive the
    // matching viewing key via Poseidon.
    let spending_key = SpendingKey::random().context("generate spending key")?;
    let viewing_key = spending_key
        .derive_viewing_key()
        .context("derive viewing key")?;

    let identity = IdentityFile {
        version: IdentityFile::CURRENT_VERSION,
        spending_key: bytes_to_hex(spending_key.as_bytes()),
        viewing_key: bytes_to_hex(viewing_key.as_bytes()),
    };

    let json = serde_json::to_string_pretty(&identity).context("serialize identity file")?;
    fs::write(&output_path, json)
        .with_context(|| format!("write identity file to {}", output_path.display()))?;

    println!("Generated tidex6 identity.");
    println!("  file         : {}", output_path.display());
    println!(
        "  viewing key  : {}",
        ViewingKey::from_bytes(hex_to_bytes(&identity.viewing_key)?)
    );
    println!();
    println!("The spending key controls every deposit you make. Keep this file safe.");
    println!(
        "The viewing key is read-only — share it with your accountant if you want them to see your deposit history."
    );

    Ok(())
}

/// Resolve `~/.tidex6/identity.json` as the default location, or
/// use the caller-supplied path verbatim.
fn resolve_output_path(out: Option<PathBuf>) -> Result<PathBuf> {
    match out {
        Some(path) => Ok(path),
        None => {
            let home = std::env::var("HOME").context("HOME environment variable is not set")?;
            Ok(PathBuf::from(format!("{home}/.tidex6/identity.json")))
        }
    }
}

fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(HEX_CHARS[(byte >> 4) as usize] as char);
        out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_to_bytes(hex: &str) -> Result<[u8; 32]> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    if stripped.len() != 64 {
        return Err(anyhow!(
            "expected 64 hex characters, got {}",
            stripped.len()
        ));
    }
    let bytes = hex::decode(stripped).context("decode hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("decoded hex is not 32 bytes"))
}
