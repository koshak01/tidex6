//! `tidex6 keygen` — generate a fresh spending key, derive the
//! matching viewing key, generate a fresh Shielded Memo auditor
//! keypair, and write all four to a JSON identity file.
//!
//! The identity file is the user's offline capability set:
//!
//! - `spending_key` — authorises spending every deposit the wallet
//!   will ever make. Never share.
//! - `viewing_key` — read-only, shareable with a trusted party for
//!   selective disclosure of the user's own deposit history.
//!   Derived from the spending key via Poseidon.
//! - `auditor_secret_key` / `auditor_public_key` — the Baby Jubjub
//!   ECDH keypair used to read encrypted memos. The user publishes
//!   the public key (Kai gives his to Lena); whoever holds the
//!   secret key can decrypt every memo addressed to the public key
//!   via `tidex6 accountant scan`.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use tidex6_core::elgamal::{AuditorPublicKey, AuditorSecretKey};
use tidex6_core::keys::{SpendingKey, ViewingKey};

/// Arguments for `tidex6 keygen` when invoked without a subcommand —
/// the default mode generates a new identity file.
#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Optional subcommand that performs a single utility action
    /// against an existing identity file (e.g., print the auditor
    /// public key). When omitted, a fresh identity is generated.
    #[command(subcommand)]
    pub command: Option<KeygenCommand>,

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

/// Utility subcommands that read an existing identity file rather
/// than generate a new one.
#[derive(Subcommand, Debug)]
pub enum KeygenCommand {
    /// Print the Baby Jubjub auditor public key of the identity
    /// file as a single hex line. This is the value the user hands
    /// to a depositor so the depositor can encrypt memos under it.
    PrintAuditorPk {
        /// Identity file to read. Defaults to `~/.tidex6/identity.json`.
        #[arg(long)]
        identity: Option<PathBuf>,
    },
}

/// On-disk representation of a tidex6 wallet identity.
///
/// Stored unencrypted in the MVP — users are expected to keep this
/// file on an encrypted disk or in a trusted location. Passphrase
/// encryption and OS-keychain delegation are tracked for v0.2.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityFile {
    /// Protocol version of the identity file layout. Used for
    /// forward compatibility when the schema evolves. v1 had only
    /// `spending_key` and `viewing_key`; v2 adds the auditor keys.
    pub version: u32,
    /// Lowercase hex of the raw `SpendingKey` bytes.
    pub spending_key: String,
    /// Lowercase hex of the derived `ViewingKey` bytes.
    pub viewing_key: String,
    /// Lowercase hex of the Baby Jubjub auditor secret key.
    /// Empty string in v1 files (pre-Shielded-Memo).
    #[serde(default)]
    pub auditor_secret_key: String,
    /// Lowercase hex of the Baby Jubjub auditor public key.
    /// Empty string in v1 files.
    #[serde(default)]
    pub auditor_public_key: String,
}

impl IdentityFile {
    pub const CURRENT_VERSION: u32 = 2;

    /// Read an identity file from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read identity file at {}", path.display()))?;
        let ident: IdentityFile = serde_json::from_str(&raw)
            .with_context(|| format!("parse identity file at {}", path.display()))?;
        Ok(ident)
    }

    /// Parse the stored auditor secret key into the core type.
    /// Returns a clear error if the identity file is from v1 and
    /// therefore has no auditor material.
    pub fn load_auditor_secret_key(&self) -> Result<AuditorSecretKey> {
        if self.auditor_secret_key.is_empty() {
            return Err(anyhow!(
                "identity file does not contain auditor keys — regenerate with `tidex6 keygen --force`"
            ));
        }
        let bytes = hex_to_bytes_32(&self.auditor_secret_key)
            .context("invalid auditor_secret_key in identity file")?;
        AuditorSecretKey::from_bytes(bytes)
            .map_err(|err| anyhow!("auditor secret key is not a valid Baby Jubjub scalar: {err}"))
    }
}

/// Run `tidex6 keygen`.
pub fn run(args: KeygenArgs) -> Result<()> {
    match args.command {
        Some(KeygenCommand::PrintAuditorPk { identity }) => run_print_auditor_pk(identity),
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

    // Generate the spending key from the OS CSPRNG with rejection
    // sampling against the BN254 scalar field, then derive the
    // matching viewing key via Poseidon.
    let spending_key = SpendingKey::random().context("generate spending key")?;
    let viewing_key = spending_key
        .derive_viewing_key()
        .context("derive viewing key")?;

    // Auditor keypair for Shielded Memo. Fresh per identity so two
    // different wallets never share the same auditor public key.
    let auditor_sk = AuditorSecretKey::random().context("generate auditor secret key")?;
    let auditor_pk = auditor_sk.public_key();

    let identity = IdentityFile {
        version: IdentityFile::CURRENT_VERSION,
        spending_key: bytes_to_hex(spending_key.as_bytes()),
        viewing_key: bytes_to_hex(viewing_key.as_bytes()),
        auditor_secret_key: bytes_to_hex(&auditor_sk.to_bytes()),
        auditor_public_key: auditor_pk.to_hex(),
    };

    let json = serde_json::to_string_pretty(&identity).context("serialize identity file")?;
    fs::write(&output_path, json)
        .with_context(|| format!("write identity file to {}", output_path.display()))?;

    println!("Generated tidex6 identity.");
    println!("  file         : {}", output_path.display());
    println!(
        "  viewing key  : {}",
        ViewingKey::from_bytes(hex_to_bytes_32(&identity.viewing_key)?)
    );
    println!("  auditor pk   : {}", identity.auditor_public_key);
    println!();
    println!("The spending key controls every deposit you make. Keep this file safe.");
    println!("The viewing key is read-only — share it with your accountant if you want");
    println!("them to see your deposit history.");
    println!();
    println!("The auditor public key (`auditor pk` above) is the value you hand to");
    println!("someone who wants to send you memo-annotated deposits (`tidex6 deposit");
    println!("--auditor <pk> --memo ...`). The matching secret lives only in this file.");

    Ok(())
}

fn run_print_auditor_pk(identity: Option<PathBuf>) -> Result<()> {
    let path = match identity {
        Some(p) => p,
        None => resolve_output_path(None)?,
    };
    let ident = IdentityFile::load(&path)?;
    if ident.auditor_public_key.is_empty() {
        return Err(anyhow!(
            "identity file at {} has no auditor keys (v1 format); regenerate with `tidex6 keygen --force`",
            path.display()
        ));
    }
    println!("{}", ident.auditor_public_key);
    Ok(())
}

/// Resolve `~/.tidex6/identity.json` as the default location, or
/// use the caller-supplied path verbatim.
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

/// Verify that an input string is a valid AuditorPublicKey hex
/// encoding. Used by the deposit subcommand to fail fast on bad
/// input before contacting the chain.
#[allow(dead_code)]
pub fn parse_auditor_pk(input: &str) -> Result<AuditorPublicKey> {
    AuditorPublicKey::from_hex(input).map_err(|err| anyhow!("invalid auditor public key: {err}"))
}
