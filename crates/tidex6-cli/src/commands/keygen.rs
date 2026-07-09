//! `tidex6 keygen` — generate a fresh spending key, derive the matching
//! viewing key, generate a fresh ML-KEM-768 keypair, and write all of
//! it to a JSON identity file.
//!
//! The identity file is the user's offline capability set:
//!
//! - `spending_key` — authorises spending every deposit this wallet
//!   makes. Never share.
//! - `viewing_key` — read-only, shareable for selective disclosure of
//!   the user's own deposit history. Derived via Poseidon.
//! - `mlkem_public` / `mlkem_secret` — the post-quantum ML-KEM-768
//!   keypair (ADR-014). The user publishes the public key; whoever
//!   holds it can address the user as a **stealth recipient** (the
//!   note travels encrypted to this key) or as an **auditor** (memo +
//!   amount encrypted to this key). The matching secret, held only in
//!   this file, opens both: `tidex6 accountant scan` (auditor view) and
//!   the recipient scan (find my own payments).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use tidex6_core::keys::{SpendingKey, ViewingKey};
use tidex6_core::pqc::{self, PqcSecretKey};

/// Arguments for `tidex6 keygen`.
#[derive(Args, Debug)]
pub struct KeygenArgs {
    #[command(subcommand)]
    pub command: Option<KeygenCommand>,

    /// Where to write the identity file. Defaults to
    /// `~/.tidex6/identity.json`.
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Overwrite an existing identity file.
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

/// Utility subcommands that read an existing identity file.
#[derive(Subcommand, Debug)]
pub enum KeygenCommand {
    /// Print the ML-KEM-768 public key of the identity as a single hex
    /// line — the value a depositor uses with `--recipient` (stealth)
    /// or `--auditor`.
    PrintMlkemPk {
        /// Identity file to read. Defaults to `~/.tidex6/identity.json`.
        #[arg(long)]
        identity: Option<PathBuf>,
    },
}

/// On-disk representation of a tidex6 wallet identity (v3).
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityFile {
    /// Identity-file schema version. v3 replaces the v2 Baby Jubjub
    /// auditor keys with a post-quantum ML-KEM-768 keypair.
    pub version: u32,
    /// Lowercase hex of the raw `SpendingKey` bytes.
    pub spending_key: String,
    /// Lowercase hex of the derived `ViewingKey` bytes.
    pub viewing_key: String,
    /// Lowercase hex of the ML-KEM-768 public (encapsulation) key.
    pub mlkem_public: String,
    /// Lowercase hex of the ML-KEM-768 secret (decapsulation) key.
    pub mlkem_secret: String,
}

impl IdentityFile {
    pub const CURRENT_VERSION: u32 = 3;

    /// Read an identity file from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read identity file at {}", path.display()))?;
        let ident: IdentityFile = serde_json::from_str(&raw)
            .with_context(|| format!("parse identity file at {}", path.display()))?;
        Ok(ident)
    }

    /// Parse the stored ML-KEM secret key into the core type.
    pub fn load_mlkem_secret(&self) -> Result<PqcSecretKey> {
        if self.mlkem_secret.is_empty() {
            return Err(anyhow!(
                "identity file has no ML-KEM keys — regenerate with `tidex6 keygen --force`"
            ));
        }
        let bytes = hex::decode(self.mlkem_secret.trim())
            .context("invalid mlkem_secret hex in identity file")?;
        PqcSecretKey::from_bytes(&bytes)
            .map_err(|err| anyhow!("stored ML-KEM secret key is invalid: {err}"))
    }
}

/// Run `tidex6 keygen`.
pub fn run(args: KeygenArgs) -> Result<()> {
    match args.command {
        Some(KeygenCommand::PrintMlkemPk { identity }) => run_print_mlkem_pk(identity),
        None => run_generate(args.out, args.force),
    }
}

fn run_generate(out: Option<PathBuf>, force: bool) -> Result<()> {
    let output_path = resolve_output_path(out)?;

    if output_path.exists() && !force {
        return Err(anyhow!(
            "identity file already exists at {}. Use --force to overwrite.",
            output_path.display()
        ));
    }

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }

    let spending_key = SpendingKey::random().context("generate spending key")?;
    let viewing_key = spending_key
        .derive_viewing_key()
        .context("derive viewing key")?;

    // Post-quantum ML-KEM-768 keypair (ADR-014). Fresh per identity.
    let (mlkem_public, mlkem_secret) = pqc::keygen();
    // Публичный адрес = ML-KEM pk ‖ X25519 pk (X25519 из ML-KEM secret) — то,
    // что раздаётся отправителю; X25519 нужен для view-tag. Секрет остаётся один.
    let address = tidex6_core::envelope::ReaderAddress::from_secret(mlkem_public, &mlkem_secret);

    let identity = IdentityFile {
        version: IdentityFile::CURRENT_VERSION,
        spending_key: bytes_to_hex(spending_key.as_bytes()),
        viewing_key: bytes_to_hex(viewing_key.as_bytes()),
        mlkem_public: hex::encode(address.to_bytes()),
        mlkem_secret: hex::encode(mlkem_secret.as_bytes()),
    };

    let json = serde_json::to_string_pretty(&identity).context("serialize identity file")?;
    fs::write(&output_path, json)
        .with_context(|| format!("write identity file to {}", output_path.display()))?;

    println!("Generated tidex6 identity (ML-KEM-768, post-quantum).");
    println!("  file         : {}", output_path.display());
    println!(
        "  viewing key  : {}",
        ViewingKey::from_bytes(hex_to_bytes_32(&identity.viewing_key)?)
    );
    println!(
        "  ML-KEM pk    : {}…",
        &identity.mlkem_public[..32.min(identity.mlkem_public.len())]
    );
    println!();
    println!("The spending key controls every deposit you make. Keep this file safe.");
    println!("The ML-KEM public key (full value via `tidex6 keygen print-mlkem-pk`) is what");
    println!("you hand to a sender: they encrypt the payment to you (`--recipient <pk>`) or a");
    println!("memo for you as auditor (`--auditor <pk>`). The matching secret lives only here.");

    Ok(())
}

fn run_print_mlkem_pk(identity: Option<PathBuf>) -> Result<()> {
    let path = match identity {
        Some(p) => p,
        None => resolve_output_path(None)?,
    };
    let ident = IdentityFile::load(&path)?;
    if ident.mlkem_public.is_empty() {
        return Err(anyhow!(
            "identity file at {} has no ML-KEM keys; regenerate with `tidex6 keygen --force`",
            path.display()
        ));
    }
    println!("{}", ident.mlkem_public);
    Ok(())
}

/// Resolve `~/.tidex6/identity.json` as the default location.
pub fn resolve_output_path(out: Option<PathBuf>) -> Result<PathBuf> {
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

fn hex_to_bytes_32(hex: &str) -> Result<[u8; 32]> {
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

/// Parse a reader public address (`mlkem_pk ‖ x25519_pk`) from a hex string.
/// Used by the deposit subcommand to validate `--recipient` / `--auditor`.
pub fn parse_mlkem_pk(input: &str) -> Result<tidex6_core::envelope::ReaderAddress> {
    let bytes = hex::decode(input.trim()).context("decode reader address hex")?;
    tidex6_core::envelope::ReaderAddress::from_bytes(&bytes)
        .map_err(|err| anyhow!("invalid reader address: {err}"))
}
