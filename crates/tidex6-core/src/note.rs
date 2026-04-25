//! `DepositNote`: the opaque handle a depositor hands to the
//! recipient.
//!
//! A note is produced at deposit time and given to the person who
//! will eventually withdraw. It carries the `(secret, nullifier)`
//! pair that reconstructs the commitment and the pool denomination.
//! Notes are transferred offchain through any secure channel the
//! user prefers (file, QR, encrypted message).
//!
//! Memo plaintext is **not** stored in the note. It lives only
//! on-chain inside an envelope encrypted under a key derived from
//! the note's secret material. The recipient decrypts the memo at
//! withdraw time. This keeps the note opaque: anyone who intercepts
//! the string sees nothing that identifies it as a tidex6 note, the
//! denomination, or any embedded message.
//!
//! # Wire format
//!
//! A note is 66 raw bytes, encoded as 132 lowercase hex characters
//! for transport:
//!
//! ```text
//! [version: 1 byte = 0x02]
//! [denomination_tag: 1 byte]
//! [secret: 32 bytes]
//! [nullifier: 32 bytes]
//! ```
//!
//! `denomination_tag` is one of `0x00 = 0.1 SOL`, `0x01 = 0.5 SOL`,
//! `0x02 = 1 SOL`, `0x03 = 10 SOL`. Sample encoded note:
//!
//! ```text
//! 027f3a8b9c2e4d5f6a1b8c9d0e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a
//! b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4
//! ```
//!
//! 132 hex chars total. No human-readable structure, no `tidex6`
//! marker, no embedded memo — copy-paste this string into Signal,
//! a text file, or a QR code; the bytes themselves leak nothing
//! beyond "this is 66 bytes of data".

use std::fmt;
use std::str::FromStr;

use thiserror::Error;

use crate::types::{Commitment, DOMAIN_VALUE_LEN, DomainError, Nullifier, Secret};

/// Numeric tags for `Denomination`. Stable forever — bumping any
/// value invalidates every existing note. New denominations are
/// appended at the end.
mod denomination_tag {
    pub const ONE_TENTH_SOL: u8 = 0x00;
    pub const HALF_SOL: u8 = 0x01;
    pub const ONE_SOL: u8 = 0x02;
    pub const TEN_SOL: u8 = 0x03;
}

/// First byte of every note. Bump only on a wire-format-breaking
/// change; old notes become unreadable.
const NOTE_VERSION_V3: u8 = 0x02;

/// Total decoded length: version + denomination + secret + nullifier.
const NOTE_BINARY_LEN: usize = 1 + 1 + DOMAIN_VALUE_LEN + DOMAIN_VALUE_LEN;

/// Hex-encoded length of a note. Always exactly this many chars.
pub const NOTE_TEXT_LEN: usize = NOTE_BINARY_LEN * 2;

/// Fixed deposit denominations supported by the MVP shielded pool.
///
/// Per ROADMAP and ADR-001, the MVP only supports a handful of
/// fixed denominations. Variable amounts are a v0.3 item that
/// requires a new circuit and a new trusted setup.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Denomination {
    /// 0.1 SOL — smallest pool.
    OneTenthSol,
    /// 0.5 SOL — introduced alongside the Day-14 indexer as a
    /// guaranteed-fresh pool for integration tests.
    HalfSol,
    /// 1 SOL — the default pool used by the flagship example.
    OneSol,
    /// 10 SOL — larger pool for bigger transfers.
    TenSol,
}

impl Denomination {
    /// Amount in lamports that this denomination represents.
    pub const fn lamports(self) -> u64 {
        match self {
            Self::OneTenthSol => 100_000_000,
            Self::HalfSol => 500_000_000,
            Self::OneSol => 1_000_000_000,
            Self::TenSol => 10_000_000_000,
        }
    }

    /// Human-readable tag for log output ("0.1", "1", "10").
    pub const fn tag(self) -> &'static str {
        match self {
            Self::OneTenthSol => "0.1",
            Self::HalfSol => "0.5",
            Self::OneSol => "1",
            Self::TenSol => "10",
        }
    }

    /// 1-byte stable binary tag used inside the v3 note blob.
    pub const fn binary_tag(self) -> u8 {
        match self {
            Self::OneTenthSol => denomination_tag::ONE_TENTH_SOL,
            Self::HalfSol => denomination_tag::HALF_SOL,
            Self::OneSol => denomination_tag::ONE_SOL,
            Self::TenSol => denomination_tag::TEN_SOL,
        }
    }

    /// Inverse of [`binary_tag`]. Reject unknown bytes loudly so a
    /// future deserialiser cannot silently misclassify a note as
    /// the wrong denomination.
    pub fn from_binary_tag(tag: u8) -> Result<Self, NoteError> {
        match tag {
            denomination_tag::ONE_TENTH_SOL => Ok(Self::OneTenthSol),
            denomination_tag::HALF_SOL => Ok(Self::HalfSol),
            denomination_tag::ONE_SOL => Ok(Self::OneSol),
            denomination_tag::TEN_SOL => Ok(Self::TenSol),
            _ => Err(NoteError::UnknownDenominationByte(tag)),
        }
    }
}

impl fmt::Display for Denomination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} SOL", self.tag())
    }
}

/// Errors produced when parsing or constructing a `DepositNote`.
#[derive(Debug, Error)]
pub enum NoteError {
    /// Hex decoding failed (non-hex character or odd length).
    #[error("note text is not valid hex")]
    InvalidHex,

    /// The decoded blob has the wrong size — neither truncation nor
    /// a future variant is allowed.
    #[error("note length mismatch: expected {expected} bytes, got {got}")]
    LenMismatch { expected: usize, got: usize },

    /// The version byte is not the one this binary recognises.
    #[error("unknown note version byte: 0x{0:02x}")]
    UnknownVersion(u8),

    /// The 1-byte denomination tag is not one of the accepted values.
    #[error("unknown denomination byte: 0x{0:02x}")]
    UnknownDenominationByte(u8),

    /// A 32-byte secret or nullifier value would not fit in the
    /// BN254 scalar field.
    #[error("invalid scalar field: {0}")]
    InvalidScalar(#[from] DomainError),
}

/// A self-describing receipt for a shielded deposit.
#[derive(Clone, PartialEq, Eq)]
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
    /// nullifier from the operating system CSPRNG.
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

    /// Encode the note as 132 lowercase hex characters.
    pub fn to_text(&self) -> String {
        let mut blob = [0u8; NOTE_BINARY_LEN];
        blob[0] = NOTE_VERSION_V3;
        blob[1] = self.denomination.binary_tag();
        blob[2..2 + DOMAIN_VALUE_LEN].copy_from_slice(self.secret.as_bytes());
        blob[2 + DOMAIN_VALUE_LEN..].copy_from_slice(self.nullifier.as_bytes());
        hex::encode(blob)
    }

    /// Parse a 132-char hex note. Whitespace at the boundaries is
    /// tolerated so users who copy-paste with stray newlines do not
    /// hit format errors.
    pub fn from_text(input: &str) -> Result<Self, NoteError> {
        let trimmed = input.trim();
        let blob = hex::decode(trimmed).map_err(|_| NoteError::InvalidHex)?;
        if blob.len() != NOTE_BINARY_LEN {
            return Err(NoteError::LenMismatch {
                expected: NOTE_BINARY_LEN,
                got: blob.len(),
            });
        }
        if blob[0] != NOTE_VERSION_V3 {
            return Err(NoteError::UnknownVersion(blob[0]));
        }
        let denomination = Denomination::from_binary_tag(blob[1])?;

        let mut secret_bytes = [0u8; DOMAIN_VALUE_LEN];
        secret_bytes.copy_from_slice(&blob[2..2 + DOMAIN_VALUE_LEN]);
        let secret = Secret::from_bytes(secret_bytes);

        let mut nullifier_bytes = [0u8; DOMAIN_VALUE_LEN];
        nullifier_bytes.copy_from_slice(&blob[2 + DOMAIN_VALUE_LEN..]);
        let nullifier = Nullifier::from_bytes(nullifier_bytes);

        Self::new(denomination, secret, nullifier)
    }
}

impl fmt::Debug for DepositNote {
    /// Deliberately omits the raw secret and nullifier. A
    /// `DepositNote` is a spending capability and must never be
    /// logged. The debug output still shows the denomination and
    /// the (non-sensitive) commitment so the note can be identified
    /// in debug contexts without leaking the spend authority.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip — serialise as hex blob, parse back, get the same
    /// secret/nullifier/denomination.
    #[test]
    fn hex_roundtrip() {
        let note = DepositNote::random(Denomination::HalfSol).unwrap();
        let text = note.to_text();
        assert_eq!(text.len(), NOTE_TEXT_LEN);
        // No human-readable structure.
        assert!(!text.contains("tidex6"));
        assert!(!text.contains(":"));
        // Pure lowercase hex.
        for ch in text.chars() {
            assert!(
                ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase(),
                "expected lowercase hex, got {ch}"
            );
        }
        let parsed = DepositNote::from_text(&text).unwrap();
        assert_eq!(parsed, note);
    }

    /// Each denomination round-trips through its 1-byte tag.
    #[test]
    fn roundtrip_all_denominations() {
        for denom in [
            Denomination::OneTenthSol,
            Denomination::HalfSol,
            Denomination::OneSol,
            Denomination::TenSol,
        ] {
            let note = DepositNote::random(denom).unwrap();
            let parsed = DepositNote::from_text(&note.to_text()).unwrap();
            assert_eq!(parsed.denomination(), denom);
        }
    }

    /// Whitespace at the boundaries (newlines from copy-paste) does
    /// not break parsing.
    #[test]
    fn whitespace_tolerated() {
        let note = DepositNote::random(Denomination::OneSol).unwrap();
        let text = note.to_text();
        let padded = format!("\n  {text}  \n");
        let parsed = DepositNote::from_text(&padded).unwrap();
        assert_eq!(parsed, note);
    }

    /// Garbage input is rejected with a clear error.
    #[test]
    fn random_garbage_rejected() {
        let err = DepositNote::from_text("totally random not a note").unwrap_err();
        assert!(matches!(err, NoteError::InvalidHex | NoteError::LenMismatch { .. }));
    }

    /// Wrong-length hex is rejected.
    #[test]
    fn wrong_length_rejected() {
        let too_short = "ab".repeat(10);
        match DepositNote::from_text(&too_short) {
            Err(NoteError::LenMismatch { expected, got }) => {
                assert_eq!(expected, NOTE_BINARY_LEN);
                assert_eq!(got, 10);
            }
            other => panic!("expected LenMismatch, got {other:?}"),
        }
    }

    /// Wrong version byte is rejected.
    #[test]
    fn wrong_version_rejected() {
        let mut blob = vec![0u8; NOTE_BINARY_LEN];
        blob[0] = 0xFF;
        let text = hex::encode(blob);
        match DepositNote::from_text(&text) {
            Err(NoteError::UnknownVersion(v)) => assert_eq!(v, 0xFF),
            other => panic!("expected UnknownVersion, got {other:?}"),
        }
    }

    /// Unknown denomination byte is rejected.
    #[test]
    fn wrong_denomination_byte_rejected() {
        let mut blob = vec![0u8; NOTE_BINARY_LEN];
        blob[0] = NOTE_VERSION_V3;
        blob[1] = 0xAA;
        let text = hex::encode(blob);
        match DepositNote::from_text(&text) {
            Err(NoteError::UnknownDenominationByte(b)) => assert_eq!(b, 0xAA),
            other => panic!("expected UnknownDenominationByte, got {other:?}"),
        }
    }

    /// Note text is exactly 132 chars — short enough to copy-paste
    /// comfortably.
    #[test]
    fn text_length_is_132_chars() {
        let note = DepositNote::random(Denomination::TenSol).unwrap();
        assert_eq!(note.to_text().len(), 132);
    }

    /// Debug output never leaks the secret or nullifier.
    #[test]
    fn debug_redacts_secrets() {
        let note = DepositNote::random(Denomination::OneSol).unwrap();
        let dbg = format!("{note:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains(&note.secret().to_hex()));
    }
}
