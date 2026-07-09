//! Multi-slot ML-KEM envelope with an X25519 view-tag (ADR-014 + roadmap A4).
//!
//! The v3 deposit stores one of these containers in a dedicated account. It
//! carries an independent [`crate::pqc`] seal per reader, and what is sealed
//! differs by capability:
//!
//! - **recipient** slot — `secret ‖ nullifier ‖ denomination ‖ memo`. Enough
//!   to scan the chain, recover the note, learn the amount and withdraw it —
//!   the stealth model where the note is never handed over.
//! - **auditor** slot — `denomination ‖ memo`. The auditor sees the amount and
//!   the memo but **cannot spend** (no `secret`/`nullifier`).
//!
//! # Wire format (v3)
//!
//! ```text
//! version(1) ‖ slot_count(1)
//!   ‖ [ kind(1) ‖ x25519_eph(32) ‖ view_tag(1) ‖ len(2 BE) ‖ pqc_envelope(len) ]*
//! ```
//!
//! `kind` is `0` for the recipient slot, `1` for an auditor slot. Multiple
//! auditor slots are allowed (multi-auditor / regulator).
//!
//! # Scanning — X25519 view-tag
//!
//! ML-KEM has no cheap "is this mine" shortcut: recovering the shared secret
//! needs a full decapsulation, so a naive scan runs one decap per envelope
//! (hundreds of seconds at 100k envelopes in a browser). So each slot also
//! carries a classical X25519 ephemeral key + a one-byte tag
//! ([`crate::viewtag`]). A reader recomputes the tag with ONE scalar-mult
//! (microseconds) and skips ~255/256 foreign slots before any ML-KEM work. The
//! payload stays post-quantum (still ML-KEM); X25519 only answers "possibly
//! yours". The reader's X25519 secret is derived from its ML-KEM secret, so the
//! user keeps a single secret; the X25519 public key rides in the address.

use rand::rngs::SysRng;
use rand::TryRng;
use thiserror::Error;

use crate::pqc::{self, PqcError, PqcPublicKey, PqcSecretKey};
use crate::viewtag::{self, X25519_PK_LEN};

/// Envelope wire-format version currently emitted (v3: X25519 view-tag).
pub const ENVELOPE_VERSION: u8 = 3;

/// Slot kind: the recipient's spend-capable slot.
pub const SLOT_KIND_RECIPIENT: u8 = 0;

/// Slot kind: an auditor's view-only slot.
pub const SLOT_KIND_AUDITOR: u8 = 1;

/// Length of the note `secret` / `nullifier` field, bytes.
const FIELD_LEN: usize = 32;

/// Recipient payload minimum: `secret(32) ‖ nullifier(32) ‖ denomination(8)`.
const RECIPIENT_PREFIX_LEN: usize = FIELD_LEN * 2 + 8;

/// Auditor payload minimum: `denomination(8)`.
const AUDITOR_PREFIX_LEN: usize = 8;

/// Per-slot header: `kind(1) ‖ x25519_eph(32) ‖ view_tag(1) ‖ len(2)`.
const SLOT_HEADER_LEN: usize = 1 + X25519_PK_LEN + 1 + 2;

/// A reader's public address (recipient or auditor): an ML-KEM public key to
/// decrypt the slot + an X25519 public key for the cheap view-tag. This is the
/// address a recipient hands to senders; both keys derive from one secret.
///
/// Wire form (what a recipient publishes): `mlkem_pk ‖ x25519_pk`.
#[derive(Clone)]
pub struct ReaderAddress {
    pub mlkem: PqcPublicKey,
    pub x25519: [u8; X25519_PK_LEN],
}

impl ReaderAddress {
    /// Build the full address from an ML-KEM keypair: the X25519 public key is
    /// derived from the ML-KEM secret, so the owner keeps a single secret.
    pub fn from_secret(mlkem_pub: PqcPublicKey, mlkem_secret: &PqcSecretKey) -> Self {
        Self {
            mlkem: mlkem_pub,
            x25519: viewtag::x25519_public_from_mlkem_sk(mlkem_secret.as_bytes()),
        }
    }

    /// Serialize as `mlkem_pk ‖ x25519_pk` — the public address a sender needs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.mlkem.as_bytes().to_vec();
        out.extend_from_slice(&self.x25519);
        out
    }

    /// Parse `mlkem_pk ‖ x25519_pk` (the trailing 32 bytes are the X25519 key).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() <= X25519_PK_LEN {
            return Err(EnvelopeError::Truncated);
        }
        let split = bytes.len() - X25519_PK_LEN;
        let mlkem = PqcPublicKey::from_bytes(&bytes[..split])?;
        let mut x25519 = [0u8; X25519_PK_LEN];
        x25519.copy_from_slice(&bytes[split..]);
        Ok(Self { mlkem, x25519 })
    }
}

/// Errors produced by the multi-slot envelope layer.
#[derive(Debug, Error)]
pub enum EnvelopeError {
    /// An underlying ML-KEM / AEAD operation failed.
    #[error(transparent)]
    Pqc(#[from] PqcError),

    /// Buffer shorter than the minimum header / a slot ran past the end.
    #[error("envelope is truncated")]
    Truncated,

    /// More readers than fit in the single-byte slot count. The recipient
    /// slot plus the auditor slots must total at most 255.
    #[error("too many readers: {got} auditors, max {max}")]
    TooManyReaders { got: usize, max: usize },

    /// Envelope version byte not understood.
    #[error("unknown envelope version: 0x{0:02x}")]
    UnknownVersion(u8),

    /// Recovered recipient payload shorter than `secret ‖ nullifier ‖ denom`.
    #[error("recipient payload too short: {got} bytes, need at least {RECIPIENT_PREFIX_LEN}")]
    RecipientPayloadTooShort { got: usize },

    /// Recovered auditor payload shorter than the denomination prefix.
    #[error("auditor payload too short: {got} bytes, need at least {AUDITOR_PREFIX_LEN}")]
    AuditorPayloadTooShort { got: usize },

    /// OS randomness for the ephemeral view-tag key failed.
    #[error("view-tag rng failed: {0}")]
    Rng(String),
}

/// What a recipient recovers from their slot: the note's spend material plus
/// the memo. Enough to reconstruct the note and withdraw.
#[derive(Clone)]
pub struct RecipientView {
    pub secret: [u8; FIELD_LEN],
    pub nullifier: [u8; FIELD_LEN],
    /// Amount sealed for the recipient.
    pub denomination: u64,
    pub memo: Vec<u8>,
}

/// What an auditor recovers from their slot: the amount and the memo.
/// Deliberately no spend material.
#[derive(Clone)]
pub struct AuditorView {
    pub denomination: u64,
    pub memo: Vec<u8>,
}

impl std::fmt::Debug for RecipientView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipientView")
            .field("memo_len", &self.memo.len())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for AuditorView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditorView")
            .field("denomination", &self.denomination)
            .field("memo_len", &self.memo.len())
            .finish()
    }
}

/// Build the multi-slot envelope for a deposit.
///
/// Always produces a recipient slot. Adds one auditor slot per entry in
/// `auditors` (zero or more), each sealing only `denomination ‖ memo`. Every
/// slot carries an X25519 ephemeral key + view-tag for its reader.
pub fn build(
    recipient: &ReaderAddress,
    secret: &[u8; FIELD_LEN],
    nullifier: &[u8; FIELD_LEN],
    denomination: u64,
    memo: &[u8],
    auditors: &[ReaderAddress],
) -> Result<Vec<u8>, EnvelopeError> {
    // The slot count is a single byte: recipient (1) + auditors must be ≤ 255.
    const MAX_AUDITORS: usize = 254;
    if auditors.len() > MAX_AUDITORS {
        return Err(EnvelopeError::TooManyReaders {
            got: auditors.len(),
            max: MAX_AUDITORS,
        });
    }

    // Recipient payload: secret ‖ nullifier ‖ denomination ‖ memo.
    let mut recipient_payload = Vec::with_capacity(RECIPIENT_PREFIX_LEN + memo.len());
    recipient_payload.extend_from_slice(secret);
    recipient_payload.extend_from_slice(nullifier);
    recipient_payload.extend_from_slice(&denomination.to_be_bytes());
    recipient_payload.extend_from_slice(memo);

    let mut out = Vec::new();
    out.push(ENVELOPE_VERSION);
    out.push((1 + auditors.len()) as u8);

    write_slot(&mut out, SLOT_KIND_RECIPIENT, recipient, &recipient_payload)?;

    // Auditor slots: denomination ‖ memo (no spend material).
    for auditor in auditors {
        let mut auditor_payload = Vec::with_capacity(AUDITOR_PREFIX_LEN + memo.len());
        auditor_payload.extend_from_slice(&denomination.to_be_bytes());
        auditor_payload.extend_from_slice(memo);
        write_slot(&mut out, SLOT_KIND_AUDITOR, auditor, &auditor_payload)?;
    }
    Ok(out)
}

/// Seal one slot for `reader` and append
/// `kind ‖ eph(32) ‖ tag(1) ‖ len(2) ‖ sealed` to `out`.
fn write_slot(
    out: &mut Vec<u8>,
    kind: u8,
    reader: &ReaderAddress,
    payload: &[u8],
) -> Result<(), EnvelopeError> {
    let sealed = pqc::seal(&reader.mlkem, payload)?;
    let mut eph_bytes = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut eph_bytes)
        .map_err(|e: rand::rngs::SysError| EnvelopeError::Rng(e.to_string()))?;
    let (eph_pub, tag) = viewtag::seal_tag(&reader.x25519, eph_bytes);
    out.push(kind);
    out.extend_from_slice(&eph_pub);
    out.push(tag);
    out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(())
}

/// Try to recover the recipient slot under `recipient_secret`.
///
/// The X25519 view-tag is checked first (one scalar-mult): a mismatching tag
/// means "not mine", skipped before any ML-KEM decap. On a tag match the ML-KEM
/// decap runs; a foreign decrypt (rare tag collision) yields `Ok(None)` via the
/// AEAD filter. Returns `Ok(Some(_))` on the first recipient slot that opens.
pub fn open_as_recipient(
    envelope: &[u8],
    recipient_secret: &PqcSecretKey,
) -> Result<Option<RecipientView>, EnvelopeError> {
    let x25519_sk = viewtag::derive_x25519_secret(recipient_secret.as_bytes());
    for (kind, eph, tag, slot) in parse_slots(envelope)? {
        if kind != SLOT_KIND_RECIPIENT {
            continue;
        }
        if viewtag::open_tag(&x25519_sk, &eph) != tag {
            continue; // cheap filter — not addressed to us
        }
        match pqc::open(recipient_secret, slot) {
            Ok(payload) => {
                if payload.len() < RECIPIENT_PREFIX_LEN {
                    return Err(EnvelopeError::RecipientPayloadTooShort { got: payload.len() });
                }
                let mut secret = [0u8; FIELD_LEN];
                secret.copy_from_slice(&payload[..FIELD_LEN]);
                let mut nullifier = [0u8; FIELD_LEN];
                nullifier.copy_from_slice(&payload[FIELD_LEN..FIELD_LEN * 2]);
                let denomination = u64::from_be_bytes(
                    payload[FIELD_LEN * 2..RECIPIENT_PREFIX_LEN]
                        .try_into()
                        .expect("slice is 8 bytes"),
                );
                let memo = payload[RECIPIENT_PREFIX_LEN..].to_vec();
                return Ok(Some(RecipientView {
                    secret,
                    nullifier,
                    denomination,
                    memo,
                }));
            }
            Err(PqcError::Decrypt) => continue,
            Err(other) => return Err(other.into()),
        }
    }
    Ok(None)
}

/// Try to recover an auditor slot under `auditor_secret`. Same view-tag + AEAD
/// filter semantics as [`open_as_recipient`].
pub fn open_as_auditor(
    envelope: &[u8],
    auditor_secret: &PqcSecretKey,
) -> Result<Option<AuditorView>, EnvelopeError> {
    let x25519_sk = viewtag::derive_x25519_secret(auditor_secret.as_bytes());
    for (kind, eph, tag, slot) in parse_slots(envelope)? {
        if kind != SLOT_KIND_AUDITOR {
            continue;
        }
        if viewtag::open_tag(&x25519_sk, &eph) != tag {
            continue;
        }
        match pqc::open(auditor_secret, slot) {
            Ok(payload) => {
                if payload.len() < AUDITOR_PREFIX_LEN {
                    return Err(EnvelopeError::AuditorPayloadTooShort { got: payload.len() });
                }
                let denomination = u64::from_be_bytes(
                    payload[..AUDITOR_PREFIX_LEN]
                        .try_into()
                        .expect("slice is 8 bytes"),
                );
                let memo = payload[AUDITOR_PREFIX_LEN..].to_vec();
                return Ok(Some(AuditorView { denomination, memo }));
            }
            Err(PqcError::Decrypt) => continue,
            Err(other) => return Err(other.into()),
        }
    }
    Ok(None)
}

/// Split the container into `(kind, x25519_eph, view_tag, sealed_slot_bytes)`.
fn parse_slots(
    envelope: &[u8],
) -> Result<Vec<(u8, [u8; X25519_PK_LEN], u8, &[u8])>, EnvelopeError> {
    if envelope.len() < 2 {
        return Err(EnvelopeError::Truncated);
    }
    if envelope[0] != ENVELOPE_VERSION {
        return Err(EnvelopeError::UnknownVersion(envelope[0]));
    }
    let count = envelope[1] as usize;
    let mut slots = Vec::with_capacity(count);
    let mut offset = 2;
    for _ in 0..count {
        if offset + SLOT_HEADER_LEN > envelope.len() {
            return Err(EnvelopeError::Truncated);
        }
        let kind = envelope[offset];
        let mut eph = [0u8; X25519_PK_LEN];
        eph.copy_from_slice(&envelope[offset + 1..offset + 1 + X25519_PK_LEN]);
        let tag = envelope[offset + 1 + X25519_PK_LEN];
        let len_off = offset + 1 + X25519_PK_LEN + 1;
        let len = u16::from_be_bytes([envelope[len_off], envelope[len_off + 1]]) as usize;
        offset += SLOT_HEADER_LEN;
        if offset + len > envelope.len() {
            return Err(EnvelopeError::Truncated);
        }
        slots.push((kind, eph, tag, &envelope[offset..offset + len]));
        offset += len;
    }
    Ok(slots)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader() -> (ReaderAddress, PqcSecretKey) {
        let (pk, sk) = pqc::keygen();
        let x25519 = viewtag::x25519_public_from_mlkem_sk(sk.as_bytes());
        (ReaderAddress { mlkem: pk, x25519 }, sk)
    }

    #[test]
    fn recipient_roundtrip_with_denomination_and_tag() {
        let (rcpt, rcpt_sk) = reader();
        let secret = [7u8; FIELD_LEN];
        let nullifier = [9u8; FIELD_LEN];
        let env = build(&rcpt, &secret, &nullifier, 1_000_000, b"rent", &[]).expect("build");
        assert_eq!(env[0], ENVELOPE_VERSION);
        let view = open_as_recipient(&env, &rcpt_sk)
            .expect("open")
            .expect("some");
        assert_eq!(view.secret, secret);
        assert_eq!(view.nullifier, nullifier);
        assert_eq!(view.denomination, 1_000_000);
        assert_eq!(view.memo, b"rent");
    }

    #[test]
    fn foreign_recipient_gets_nothing() {
        let (rcpt, _) = reader();
        let (_, foreign_sk) = reader();
        let env = build(&rcpt, &[1u8; FIELD_LEN], &[2u8; FIELD_LEN], 5, b"x", &[]).expect("build");
        assert!(open_as_recipient(&env, &foreign_sk)
            .expect("open")
            .is_none());
    }

    #[test]
    fn auditor_sees_amount_not_spend_material() {
        let (rcpt, _) = reader();
        let (auditor, auditor_sk) = reader();
        let env = build(
            &rcpt,
            &[3u8; FIELD_LEN],
            &[4u8; FIELD_LEN],
            42,
            b"memo",
            &[auditor],
        )
        .expect("build");
        let a = open_as_auditor(&env, &auditor_sk)
            .expect("open")
            .expect("some");
        assert_eq!(a.denomination, 42);
        assert_eq!(a.memo, b"memo");
    }
}
