//! Multi-slot ML-KEM envelope for the v2 memo account (ADR-014).
//!
//! The v2 deposit stores one of these containers in a dedicated account.
//! It carries an independent [`crate::pqc`] seal per reader, and **what
//! is sealed differs by capability**:
//!
//! - **recipient** slot — `secret ‖ nullifier ‖ memo`. Enough to scan
//!   the chain, recover the note and withdraw it — the stealth model
//!   where the note is never handed over.
//! - **auditor** slot — `denomination ‖ memo`. The auditor sees the
//!   amount and the memo but **cannot spend** (no `secret`/`nullifier`).
//!
//! # Wire format
//!
//! ```text
//! version(1) ‖ slot_count(1) ‖ [ kind(1) ‖ len(2 BE) ‖ pqc_envelope(len) ]*
//! ```
//!
//! `kind` is `0` for the recipient slot and `1` for an auditor slot.
//! Multiple auditor slots are allowed (multi-auditor / regulator).
//!
//! # Scanning
//!
//! There is no view tag: ML-KEM has no cheap "is this mine" shortcut, so
//! a reader runs a full `pqc::open` on each slot of its kind and lets the
//! AEAD authentication tag be the filter (a decrypt error means "not
//! mine"). See ADR-014 for why a view tag would save nothing here.

use thiserror::Error;

use crate::pqc::{self, PqcError, PqcPublicKey, PqcSecretKey};

/// Envelope wire-format version currently emitted.
pub const ENVELOPE_VERSION: u8 = 1;

/// Slot kind: the recipient's spend-capable slot.
pub const SLOT_KIND_RECIPIENT: u8 = 0;

/// Slot kind: an auditor's view-only slot.
pub const SLOT_KIND_AUDITOR: u8 = 1;

/// Length of the note `secret` / `nullifier` field, bytes.
const FIELD_LEN: usize = 32;

/// Recipient payload minimum: `secret(32) ‖ nullifier(32)`.
const RECIPIENT_PREFIX_LEN: usize = FIELD_LEN * 2;

/// Auditor payload minimum: `denomination(8)`.
const AUDITOR_PREFIX_LEN: usize = 8;

/// Per-slot header: `kind(1) ‖ len(2)`.
const SLOT_HEADER_LEN: usize = 3;

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

    /// Recovered recipient payload shorter than `secret ‖ nullifier`.
    #[error("recipient payload too short: {got} bytes, need at least {RECIPIENT_PREFIX_LEN}")]
    RecipientPayloadTooShort { got: usize },

    /// Recovered auditor payload shorter than the denomination prefix.
    #[error("auditor payload too short: {got} bytes, need at least {AUDITOR_PREFIX_LEN}")]
    AuditorPayloadTooShort { got: usize },
}

/// What a recipient recovers from their slot: the note's spend material
/// plus the memo. Enough to reconstruct the note and withdraw.
#[derive(Clone)]
pub struct RecipientView {
    pub secret: [u8; FIELD_LEN],
    pub nullifier: [u8; FIELD_LEN],
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
/// `auditor_pubs` (zero or more), each sealing only `denomination ‖ memo`.
pub fn build(
    recipient_pub: &PqcPublicKey,
    secret: &[u8; FIELD_LEN],
    nullifier: &[u8; FIELD_LEN],
    denomination: u64,
    memo: &[u8],
    auditor_pubs: &[PqcPublicKey],
) -> Result<Vec<u8>, EnvelopeError> {
    // The slot count is serialised as a single byte: recipient slot (1)
    // plus the auditor slots must not exceed 255. Guard so a caller
    // cannot silently truncate via u8 wraparound.
    const MAX_AUDITORS: usize = 254;
    if auditor_pubs.len() > MAX_AUDITORS {
        return Err(EnvelopeError::TooManyReaders {
            got: auditor_pubs.len(),
            max: MAX_AUDITORS,
        });
    }

    // Recipient slot: secret ‖ nullifier ‖ memo.
    let mut recipient_payload = Vec::with_capacity(RECIPIENT_PREFIX_LEN + memo.len());
    recipient_payload.extend_from_slice(secret);
    recipient_payload.extend_from_slice(nullifier);
    recipient_payload.extend_from_slice(memo);
    let recipient_slot = pqc::seal(recipient_pub, &recipient_payload)?;

    let mut slots: Vec<(u8, Vec<u8>)> = Vec::with_capacity(1 + auditor_pubs.len());
    slots.push((SLOT_KIND_RECIPIENT, recipient_slot));

    // Auditor slots: denomination ‖ memo (no spend material).
    for auditor_pub in auditor_pubs {
        let mut auditor_payload = Vec::with_capacity(AUDITOR_PREFIX_LEN + memo.len());
        auditor_payload.extend_from_slice(&denomination.to_be_bytes());
        auditor_payload.extend_from_slice(memo);
        let auditor_slot = pqc::seal(auditor_pub, &auditor_payload)?;
        slots.push((SLOT_KIND_AUDITOR, auditor_slot));
    }

    let mut out = Vec::new();
    out.push(ENVELOPE_VERSION);
    out.push(slots.len() as u8);
    for (kind, sealed) in &slots {
        out.push(*kind);
        out.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
        out.extend_from_slice(sealed);
    }
    Ok(out)
}

/// Try to recover the recipient slot under `recipient_secret`.
///
/// Returns `Ok(Some(_))` on the first recipient slot that decrypts,
/// `Ok(None)` if no recipient slot is addressed to this key. The AEAD
/// tag is the filter — a foreign slot yields [`PqcError::Decrypt`],
/// which is treated as "skip", not an error.
pub fn open_as_recipient(
    envelope: &[u8],
    recipient_secret: &PqcSecretKey,
) -> Result<Option<RecipientView>, EnvelopeError> {
    for (kind, slot) in parse_slots(envelope)? {
        if kind != SLOT_KIND_RECIPIENT {
            continue;
        }
        match pqc::open(recipient_secret, slot) {
            Ok(payload) => {
                if payload.len() < RECIPIENT_PREFIX_LEN {
                    return Err(EnvelopeError::RecipientPayloadTooShort { got: payload.len() });
                }
                let mut secret = [0u8; FIELD_LEN];
                secret.copy_from_slice(&payload[..FIELD_LEN]);
                let mut nullifier = [0u8; FIELD_LEN];
                nullifier.copy_from_slice(&payload[FIELD_LEN..RECIPIENT_PREFIX_LEN]);
                let memo = payload[RECIPIENT_PREFIX_LEN..].to_vec();
                return Ok(Some(RecipientView {
                    secret,
                    nullifier,
                    memo,
                }));
            }
            Err(PqcError::Decrypt) => continue,
            Err(other) => return Err(other.into()),
        }
    }
    Ok(None)
}

/// Try to recover an auditor slot under `auditor_secret`. Same filter
/// semantics as [`open_as_recipient`].
pub fn open_as_auditor(
    envelope: &[u8],
    auditor_secret: &PqcSecretKey,
) -> Result<Option<AuditorView>, EnvelopeError> {
    for (kind, slot) in parse_slots(envelope)? {
        if kind != SLOT_KIND_AUDITOR {
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

/// Split the container into `(kind, sealed_slot_bytes)` pairs.
fn parse_slots(envelope: &[u8]) -> Result<Vec<(u8, &[u8])>, EnvelopeError> {
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
        let len = u16::from_be_bytes([envelope[offset + 1], envelope[offset + 2]]) as usize;
        offset += SLOT_HEADER_LEN;
        if offset + len > envelope.len() {
            return Err(EnvelopeError::Truncated);
        }
        slots.push((kind, &envelope[offset..offset + len]));
        offset += len;
    }
    Ok(slots)
}
