//! `DepositNote`: the first-class handle a user holds to spend a
//! tidex6 deposit.
//!
//! A note is produced at deposit time and given to the person who
//! will eventually withdraw. Internally it carries the
//! `(secret, nullifier)` pair that reconstructs the commitment,
//! the pool denomination (so the receiver knows which pool to
//! withdraw from) and an optional plaintext memo the depositor
//! chose to share with the recipient ("what is this payment
//! for"). Notes are transferred offchain through any secure channel
//! the user prefers (file, QR, encrypted message).
//!
//! # Textual format
//!
//! v2 (since 2026-04-15) encodes the memo as a base64 trailer so
//! colons inside the memo cannot break the parser:
//!
//! ```text
//! tidex6-note-v2:<denomination>:<secret-hex>:<nullifier-hex>:<memo-b64>
//! ```
//!
//! v1 notes (no memo) are still accepted by [`DepositNote::from_text`]
//! so existing on-disk notes keep working:
//!
//! ```text
//! tidex6-note-v1:<denomination>:<secret-hex>:<nullifier-hex>
//! ```
//!
//! `<denomination>` is one of `0.1`, `0.5`, `1`, or `10` (SOL). The
//! hex fields are exactly 64 lowercase hexadecimal characters each.
//! `<memo-b64>` is standard base64 of the UTF-8 memo bytes; capped
//! at the same 256-plaintext-byte ceiling as Shielded Memo itself.

use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use thiserror::Error;

use crate::types::{Commitment, DOMAIN_VALUE_LEN, DomainError, Nullifier, Secret};

const NOTE_PREFIX_V1: &str = "tidex6-note-v1";
const NOTE_PREFIX_V2: &str = "tidex6-note-v2";

/// Maximum length in bytes of a plaintext memo carried inside a
/// `DepositNote`. Matches `tidex6_core::memo::MAX_PLAINTEXT_LEN` so
/// the same string can be both encrypted into an SPL Memo for the
/// auditor and written verbatim into the note for the recipient —
/// without one side silently truncating.
pub const MAX_NOTE_MEMO_LEN: usize = 256;

/// Fixed deposit denominations supported by the MVP shielded pool.
///
/// Per ROADMAP and ADR-001, the MVP only supports a handful of
/// fixed denominations. Variable amounts are a v0.3 item that
/// requires a new circuit and a new trusted setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Denomination {
    /// 0.1 SOL — smallest pool, meant for micro-payments and for
    /// demos that want cheap transactions.
    OneTenthSol,
    /// 0.5 SOL — introduced alongside the Day-14 indexer as a
    /// guaranteed-fresh pool for the integration tests. The other
    /// denominations already contain Day-5 / Day-11 / Day-12
    /// deposits with the old log format that the indexer cannot
    /// parse; this variant gives new CLI runs a clean starting
    /// tree.
    HalfSol,
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
            Self::HalfSol => 500_000_000,
            Self::OneSol => 1_000_000_000,
            Self::TenSol => 10_000_000_000,
        }
    }

    /// Machine-readable tag used in the text-format `DepositNote`.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::OneTenthSol => "0.1",
            Self::HalfSol => "0.5",
            Self::OneSol => "1",
            Self::TenSol => "10",
        }
    }

    /// Parse the tag half of a text-format note back into a
    /// `Denomination`.
    pub fn from_tag(tag: &str) -> Result<Self, NoteError> {
        match tag {
            "0.1" => Ok(Self::OneTenthSol),
            "0.5" => Ok(Self::HalfSol),
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
    /// The string does not start with a supported note prefix.
    #[error("note must begin with `{NOTE_PREFIX_V2}:` or `{NOTE_PREFIX_V1}:`")]
    MissingPrefix,

    /// The string did not have the expected number of colon-separated
    /// fields (4 for v1, 5 for v2).
    #[error("malformed note: expected 4 (v1) or 5 (v2) fields; got {field_count}")]
    MalformedStructure { field_count: usize },

    /// The denomination tag is not one of the accepted values.
    #[error("unknown denomination tag: `{0}`")]
    UnknownDenomination(String),

    /// A hex-encoded field did not parse into a 32-byte domain
    /// value.
    #[error("invalid hex field: {0}")]
    InvalidHex(#[from] DomainError),

    /// The memo trailer in a v2 note was not valid base64.
    #[error("memo field is not valid base64")]
    InvalidMemoBase64,

    /// The decoded memo was not valid UTF-8 text.
    #[error("memo field is not valid UTF-8 text")]
    InvalidMemoUtf8,

    /// The memo exceeded the hard cap.
    #[error("memo plaintext is too long: {got} bytes, max {MAX_NOTE_MEMO_LEN} bytes")]
    MemoTooLong { got: usize },
}

/// A self-describing receipt for a shielded deposit. Contains every
/// piece of information the holder needs to later withdraw from the
/// pool: the (secret, nullifier) pair, the derived commitment, the
/// pool denomination, and an optional plaintext memo describing the
/// payment ("Rent March 2026", "Medicine for mother").
#[derive(Clone, PartialEq, Eq)]
pub struct DepositNote {
    denomination: Denomination,
    secret: Secret,
    nullifier: Nullifier,
    commitment: Commitment,
    memo: Option<String>,
}

impl DepositNote {
    /// Construct a memo-less note from its primary inputs. The
    /// commitment is computed automatically so the caller cannot
    /// accidentally build an inconsistent note. Kept around for
    /// backward compatibility with v1 callers.
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
            memo: None,
        })
    }

    /// Construct a note together with a plaintext memo. The memo
    /// length is checked against [`MAX_NOTE_MEMO_LEN`] up front so
    /// a caller cannot build a note that will not serialise.
    pub fn new_with_memo(
        denomination: Denomination,
        secret: Secret,
        nullifier: Nullifier,
        memo: impl Into<String>,
    ) -> Result<Self, NoteError> {
        let memo_string = memo.into();
        if memo_string.len() > MAX_NOTE_MEMO_LEN {
            return Err(NoteError::MemoTooLong {
                got: memo_string.len(),
            });
        }
        let commitment = Commitment::derive(&secret, &nullifier)?;
        Ok(Self {
            denomination,
            secret,
            nullifier,
            commitment,
            memo: Some(memo_string),
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

    /// Generate a fresh note with a memo already attached.
    pub fn random_with_memo(
        denomination: Denomination,
        memo: impl Into<String>,
    ) -> Result<Self, NoteError> {
        let secret = Secret::random()?;
        let nullifier = Nullifier::random()?;
        Self::new_with_memo(denomination, secret, nullifier, memo)
    }

    /// Return a copy of this note with the given memo replacing any
    /// previous value. Used by [`crate::note::DepositNote::random`]
    /// call sites that learn the memo only after the note has been
    /// constructed.
    pub fn with_memo(mut self, memo: impl Into<String>) -> Result<Self, NoteError> {
        let memo_string = memo.into();
        if memo_string.len() > MAX_NOTE_MEMO_LEN {
            return Err(NoteError::MemoTooLong {
                got: memo_string.len(),
            });
        }
        self.memo = Some(memo_string);
        Ok(self)
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

    /// Plaintext memo attached to this note, if any. The recipient
    /// reads this directly out of the note file — it is not
    /// encrypted, just opaque to anyone who does not hold the note.
    pub fn memo(&self) -> Option<&str> {
        self.memo.as_deref()
    }

    /// Encode the note as a single-line textual representation.
    /// Safe to copy, paste, store in a file, or show in a QR code.
    ///
    /// Notes with a memo serialise as v2; memo-less notes serialise
    /// as v1 so the on-disk format of existing deposits does not
    /// change until an explicit v2 write.
    pub fn to_text(&self) -> String {
        match &self.memo {
            Some(memo) => {
                let encoded = BASE64.encode(memo.as_bytes());
                format!(
                    "{NOTE_PREFIX_V2}:{}:{}:{}:{}",
                    self.denomination.tag(),
                    self.secret.to_hex(),
                    self.nullifier.to_hex(),
                    encoded
                )
            }
            None => format!(
                "{NOTE_PREFIX_V1}:{}:{}:{}",
                self.denomination.tag(),
                self.secret.to_hex(),
                self.nullifier.to_hex(),
            ),
        }
    }

    /// Parse a previously exported textual note. Accepts both the
    /// v1 (no memo) and v2 (with memo) formats. Rejects any input
    /// that is missing the prefix, has the wrong number of fields,
    /// uses an unknown denomination, has malformed hex fields, or
    /// carries an invalid/too-long memo.
    pub fn from_text(input: &str) -> Result<Self, NoteError> {
        let trimmed = input.trim();
        let fields: Vec<&str> = trimmed.split(':').collect();

        match fields.as_slice() {
            [prefix, denom, secret, nullifier] if *prefix == NOTE_PREFIX_V1 => {
                let denomination = Denomination::from_tag(denom)?;
                let secret = Secret::from_str(secret)?;
                let nullifier = Nullifier::from_str(nullifier)?;
                Self::new(denomination, secret, nullifier)
            }
            [prefix, denom, secret, nullifier, memo_b64] if *prefix == NOTE_PREFIX_V2 => {
                let denomination = Denomination::from_tag(denom)?;
                let secret = Secret::from_str(secret)?;
                let nullifier = Nullifier::from_str(nullifier)?;
                let memo_bytes = BASE64
                    .decode(memo_b64.as_bytes())
                    .map_err(|_| NoteError::InvalidMemoBase64)?;
                if memo_bytes.len() > MAX_NOTE_MEMO_LEN {
                    return Err(NoteError::MemoTooLong {
                        got: memo_bytes.len(),
                    });
                }
                let memo = String::from_utf8(memo_bytes).map_err(|_| NoteError::InvalidMemoUtf8)?;
                Self::new_with_memo(denomination, secret, nullifier, memo)
            }
            [first, ..] if *first != NOTE_PREFIX_V1 && *first != NOTE_PREFIX_V2 => {
                Err(NoteError::MissingPrefix)
            }
            _ => Err(NoteError::MalformedStructure {
                field_count: fields.len(),
            }),
        }
    }
}

impl fmt::Debug for DepositNote {
    /// Deliberately omits the raw secret and nullifier. A
    /// `DepositNote` is a spending capability and must never be
    /// logged. The debug output still shows the denomination, the
    /// public commitment and the (non-sensitive) memo text so the
    /// note can be identified in debug contexts without leaking the
    /// spend authority.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DepositNote")
            .field("denomination", &self.denomination)
            .field("commitment", &self.commitment)
            .field("secret", &"REDACTED")
            .field("nullifier", &"REDACTED")
            .field("memo", &self.memo.as_deref().unwrap_or(""))
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

/// Upper bound on the textual note size. Used by UI layers that
/// need a capacity hint (QR code target size, clipboard buffer,
/// input validation). A memo-less v1 note is exactly 148 bytes:
/// `tidex6-note-v1:` (15) + `tag` (≤ 3) + `:` + 64 hex + `:` + 64
/// hex. A v2 note adds the 4-byte prefix bump, a `:` separator,
/// and up to `ceil(256 * 4 / 3) = 344` bytes of base64 memo: a
/// total that rounds up to about 500 characters.
pub const MAX_NOTE_TEXT_LEN: usize =
    15 + 3 + 1 + (DOMAIN_VALUE_LEN * 2) + 1 + (DOMAIN_VALUE_LEN * 2) + 1 + 344;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_roundtrip_without_memo() {
        let note = DepositNote::random(Denomination::HalfSol).unwrap();
        assert!(note.memo().is_none());
        let text = note.to_text();
        assert!(text.starts_with(NOTE_PREFIX_V1));
        let parsed = DepositNote::from_text(&text).unwrap();
        assert_eq!(parsed, note);
    }

    #[test]
    fn v2_roundtrip_with_memo() {
        let note = DepositNote::random_with_memo(Denomination::HalfSol, "Rent March 2026").unwrap();
        assert_eq!(note.memo(), Some("Rent March 2026"));
        let text = note.to_text();
        assert!(text.starts_with(NOTE_PREFIX_V2));
        let parsed = DepositNote::from_text(&text).unwrap();
        assert_eq!(parsed.memo(), Some("Rent March 2026"));
        assert_eq!(parsed, note);
    }

    #[test]
    fn memo_with_colons_survives_roundtrip() {
        // Base64 wrapping is exactly why colons inside a memo
        // cannot split the note into the wrong number of fields.
        let note = DepositNote::random_with_memo(
            Denomination::OneTenthSol,
            "Invoice #2026-04-15: thanks!",
        )
        .unwrap();
        let text = note.to_text();
        let parsed = DepositNote::from_text(&text).unwrap();
        assert_eq!(parsed.memo(), Some("Invoice #2026-04-15: thanks!"));
    }

    #[test]
    fn memo_length_cap_enforced() {
        let huge = "x".repeat(MAX_NOTE_MEMO_LEN + 1);
        match DepositNote::random_with_memo(Denomination::OneSol, huge) {
            Err(NoteError::MemoTooLong { got }) => {
                assert_eq!(got, MAX_NOTE_MEMO_LEN + 1)
            }
            other => panic!("expected MemoTooLong, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_prefix() {
        let err = DepositNote::from_text(
            "not-a-note:0.1:0000000000000000000000000000000000000000000000000000000000000000:\
             0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap_err();
        assert!(matches!(err, NoteError::MissingPrefix));
    }
}
