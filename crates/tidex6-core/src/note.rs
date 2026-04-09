//! `DepositNote`: the first-class handle a user holds to spend a
//! tidex6 deposit.
//!
//! A note is produced at deposit time and given to the person who
//! will eventually withdraw. Internally it carries the
//! `(secret, nullifier)` pair that reconstructs the commitment,
//! plus the pool denomination so a receiver knows which pool to
//! withdraw from. Notes are transferred offchain through any secure
//! channel the user prefers (file, QR, encrypted message).
//!
//! The textual format is intentionally human-readable and
//! copy-pasteable:
//!
//! ```text
//! tidex6-note-v1:<denomination>:<secret-hex>:<nullifier-hex>
//! ```
//!
//! where `<denomination>` is one of `0.1`, `1`, or `10` SOL and the
//! hex fields are exactly 64 lowercase hexadecimal characters each.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::types::{Commitment, DOMAIN_VALUE_LEN, DomainError, Nullifier, Secret};

const NOTE_PREFIX: &str = "tidex6-note-v1";

/// Fixed deposit denominations supported by the MVP shielded pool.
///
/// Per ROADMAP and ADR-001, the MVP only supports three fixed
/// denominations. Variable amounts are a v0.3 item that requires a
/// new circuit and a new trusted setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Denomination {
    /// 0.1 SOL — smallest pool, meant for micro-payments and for
    /// demos that want cheap transactions.
    OneTenthSol,
    /// 1 SOL — the default pool used by the flagship example.
    OneSol,
    /// 10 SOL — larger pool for bigger transfers.
    TenSol,
}

impl Denomination {
    /// Amount in lamports that this denomination represents. The
    /// integrator program checks the deposited SOL matches this
    /// value byte-for-byte.
    pub const fn lamports(self) -> u64 {
        match self {
            Self::OneTenthSol => 100_000_000,
            Self::OneSol => 1_000_000_000,
            Self::TenSol => 10_000_000_000,
        }
    }

    /// Machine-readable tag used in the text-format `DepositNote`.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::OneTenthSol => "0.1",
            Self::OneSol => "1",
            Self::TenSol => "10",
        }
    }

    /// Parse the tag half of a text-format note back into a
    /// `Denomination`.
    pub fn from_tag(tag: &str) -> Result<Self, NoteError> {
        match tag {
            "0.1" => Ok(Self::OneTenthSol),
            "1" => Ok(Self::OneSol),
            "10" => Ok(Self::TenSol),
            _ => Err(NoteError::UnknownDenomination(tag.to_string())),
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} SOL", self.tag())
    }
}

/// Errors produced when parsing, saving, or loading a `DepositNote`.
#[derive(Debug, Error)]
pub enum NoteError {
    /// The string does not start with `tidex6-note-v1:`.
    #[error("note must begin with `{NOTE_PREFIX}:`")]
    MissingPrefix,

    /// The string did not have the expected four colon-separated
    /// fields.
    #[error("expected {NOTE_PREFIX}:<denomination>:<secret>:<nullifier>; got {field_count} fields")]
    MalformedStructure { field_count: usize },

    /// The denomination tag is not one of the accepted values.
    #[error("unknown denomination tag: `{0}`")]
    UnknownDenomination(String),

    /// A hex-encoded field did not parse into a 32-byte domain
    /// value.
    #[error("invalid hex field: {0}")]
    InvalidHex(#[from] DomainError),
}

/// A self-describing receipt for a shielded deposit. Contains every
/// piece of information the holder needs to later withdraw from the
/// pool: the (secret, nullifier) pair, the derived commitment, and
/// the pool denomination.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DepositNote {
    denomination: Denomination,
    secret: Secret,
    nullifier: Nullifier,
    commitment: Commitment,
}

impl DepositNote {
    /// Construct a note from its primary inputs. The commitment is
    /// computed automatically so the caller cannot accidentally
    /// build an inconsistent note.
    pub fn new(
        denomination: Denomination,
        secret: Secret,
        nullifier: Nullifier,
    ) -> Result<Self, NoteError> {
        let commitment = Commitment::derive(&secret, &nullifier)?;
        Ok(Self {
            denomination,
            secret,
            nullifier,
            commitment,
        })
    }

    /// Generate a fresh note by sampling a random secret and
    /// nullifier from the operating system CSPRNG. This is how a
    /// depositor normally creates a note before submitting the
    /// deposit transaction.
    pub fn random(denomination: Denomination) -> Result<Self, NoteError> {
        let secret = Secret::random()?;
        let nullifier = Nullifier::random()?;
        Self::new(denomination, secret, nullifier)
    }

    /// Denomination of the pool this note belongs to.
    pub fn denomination(&self) -> Denomination {
        self.denomination
    }

    /// The private secret half of the commitment.
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// The private nullifier half of the commitment.
    pub fn nullifier(&self) -> &Nullifier {
        &self.nullifier
    }

    /// The derived commitment. Equal to `Poseidon(secret, nullifier)`.
    pub fn commitment(&self) -> Commitment {
        self.commitment
    }

    /// Encode the note as a single-line textual representation.
    /// Safe to copy, paste, store in a file, or show in a QR code.
    pub fn to_text(&self) -> String {
        format!(
            "{NOTE_PREFIX}:{}:{}:{}",
            self.denomination.tag(),
            self.secret.to_hex(),
            self.nullifier.to_hex(),
        )
    }

    /// Parse a previously exported textual note. Rejects any input
    /// that is missing the prefix, has the wrong number of fields,
    /// uses an unknown denomination, or has malformed hex fields.
    pub fn from_text(input: &str) -> Result<Self, NoteError> {
        let fields: Vec<&str> = input.trim().split(':').collect();
        if fields.len() != 4 {
            return Err(NoteError::MalformedStructure {
                field_count: fields.len(),
            });
        }
        if fields[0] != NOTE_PREFIX {
            return Err(NoteError::MissingPrefix);
        }

        let denomination = Denomination::from_tag(fields[1])?;
        let secret = Secret::from_str(fields[2])?;
        let nullifier = Nullifier::from_str(fields[3])?;

        Self::new(denomination, secret, nullifier)
    }
}

impl fmt::Debug for DepositNote {
    /// Deliberately omits the raw secret and nullifier. A
    /// `DepositNote` is a spending capability and must never be
    /// logged. The debug output still shows the denomination and
    /// the public commitment so the note can be identified in
    /// debug contexts without leaking the spend authority.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DepositNote")
            .field("denomination", &self.denomination)
            .field("commitment", &self.commitment)
            .field("secret", &"REDACTED")
            .field("nullifier", &"REDACTED")
            .finish()
    }
}

impl fmt::Display for DepositNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl FromStr for DepositNote {
    type Err = NoteError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_text(s)
    }
}

/// Plain-text size of a `DepositNote` (helpful for capacity hints
/// and documentation): `tidex6-note-v1:` (15) + `tag` (≤ 3) + `:` +
/// 64 hex chars + `:` + 64 hex chars. Exactly `15 + 3 + 1 + 64 + 1
/// + 64 = 148` in the longest case.
pub const MAX_NOTE_TEXT_LEN: usize =
    15 + 3 + 1 + (DOMAIN_VALUE_LEN * 2) + 1 + (DOMAIN_VALUE_LEN * 2);
