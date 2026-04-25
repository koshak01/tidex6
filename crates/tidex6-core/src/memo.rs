//! Shielded Memo encryption layer.
//!
//! Binds together the Baby Jubjub ECDH primitives from
//! `crate::elgamal` with AES-256-GCM to produce a compact, base64-safe
//! payload that fits inside a single SPL Memo instruction.
//!
//! # The wire format
//!
//! A [`MemoPayload`] serialises to a fixed-layout byte string:
//!
//! ```text
//! [ ephemeral_pk | iv | tag | ciphertext ]
//!       32         12    16     variable
//! ```
//!
//! That binary string is then base64-encoded (standard alphabet,
//! padded) for transport through the SPL Memo Program, whose
//! instruction data must be a UTF-8 string. The fixed-length prefix
//! is 60 bytes; the ciphertext is the same length as the plaintext
//! because AES-GCM is a stream cipher. In practice memos stay under
//! ~200 bytes of plaintext, which encodes to roughly 348 base64
//! characters — well below the SPL Memo ~566-character ceiling.
//!
//! # KDF
//!
//! The AES key is derived from the ECDH shared secret and a fixed
//! domain tag via plain SHA-256:
//!
//! ```text
//! aes_key = SHA256(shared_secret_x_be || MEMO_DOMAIN_V1)
//! ```
//!
//! Poseidon was considered for the KDF because the shared secret is
//! already a BN254 scalar, but SHA-256 is simpler, standard, and
//! matches the "audited primitives outside the consensus path" rule
//! from ADR-005. We keep the x-coordinate-as-shared-secret convention
//! from `crate::elgamal` so that, when we eventually pull memo-check
//! logic into a circuit (ADR-007 v0.2), the shared-secret recomputation
//! can run in Poseidon without bridging encodings.
//!
//! # The filter-for-free trick
//!
//! AES-GCM rejects tampered ciphertexts in constant time via the
//! authentication tag. That same rejection serves as an "addressed
//! to me" check for the accountant: the accountant tries to decrypt
//! every memo instruction in the pool, and the ones that return
//! `Err` are simply not for them. No separate filter field is
//! needed — this is why the wire format has no explicit "auditor
//! tag" byte.
//!
//! # References
//!
//! - ADR-007 — Shielded Memo in the MVP.
//! - ADR-010 — SPL Memo Program as the memo transport.
//! - `docs/release/security.md` §2.5, §2.7 for threat-model notes
//!   on the auditor and viewing-key capability split.

use std::convert::TryInto;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::elgamal::{
    self, AuditorPublicKey, AuditorSecretKey, ElGamalError, EphemeralPublicKey, POINT_LEN,
    SharedSecret,
};

/// Length of the AES-256 key in bytes.
pub const AES_KEY_LEN: usize = 32;

/// Length of the AES-GCM nonce (IV) in bytes. 12 is the only value
/// AES-GCM recommends; anything else reduces security.
pub const IV_LEN: usize = 12;

/// Length of the AES-GCM authentication tag in bytes.
pub const TAG_LEN: usize = 16;

/// Fixed-size prefix of every serialised [`MemoPayload`]:
/// `ephemeral_pk || iv || tag`.
pub const PAYLOAD_PREFIX_LEN: usize = POINT_LEN + IV_LEN + TAG_LEN;

/// Soft upper bound on plaintext length. The SPL Memo Program caps
/// the UTF-8 instruction string at ~566 characters, which translates
/// to roughly 420 base64 bytes of payload after accounting for
/// padding; subtract the 60-byte prefix to get ~360 bytes of
/// plaintext available. We cap at 256 to leave headroom for future
/// schema evolution and stay far away from the hard limit.
pub const MAX_PLAINTEXT_LEN: usize = 256;

/// Domain tag baked into every memo KDF. Bumping the version suffix
/// invalidates every previously encrypted memo under the old scheme.
const MEMO_DOMAIN_V1: &[u8] = b"tidex6-memo-v1";

/// Errors produced by the Shielded Memo layer.
#[derive(Debug, Error)]
pub enum MemoError {
    /// An underlying ECDH operation failed. Wraps
    /// [`ElGamalError`] so callers see a unified error type but can
    /// still unwrap the cause when they need to.
    #[error(transparent)]
    ElGamal(#[from] ElGamalError),

    /// AES-GCM encryption reported an internal failure. In practice
    /// only fires if the key or nonce length is wrong, which we
    /// guarantee statically — so reaching this variant in production
    /// indicates a library regression.
    #[error("AES-GCM encryption failed")]
    EncryptionFailed,

    /// AES-GCM authentication tag check failed. This is the expected
    /// outcome when an auditor tries to decrypt a memo that was not
    /// addressed to them — it is not a bug, the caller should treat
    /// this as "skip".
    #[error("AES-GCM authentication failed — memo is not addressed to this key")]
    DecryptionFailed,

    /// Plaintext exceeded [`MAX_PLAINTEXT_LEN`].
    #[error(
        "memo plaintext is too long: {got} bytes, max {} bytes",
        MAX_PLAINTEXT_LEN
    )]
    PlaintextTooLong { got: usize },

    /// The binary payload was shorter than the fixed prefix.
    #[error(
        "payload is too short: {got} bytes, need at least {} bytes",
        PAYLOAD_PREFIX_LEN
    )]
    PayloadTooShort { got: usize },

    /// Base64 decoding failed.
    #[error("payload is not valid base64")]
    InvalidBase64,

    /// The OS random number generator failed.
    #[error("OS random number generator failed: {0}")]
    Rand(String),

    /// Envelope version byte unknown.
    #[error("unknown envelope version: 0x{0:02x}")]
    UnknownEnvelopeVersion(u8),

    /// Envelope flags byte set bits we do not understand.
    #[error("unknown envelope flag bits: 0x{0:02x}")]
    UnknownEnvelopeFlags(u8),

    /// Envelope binary blob shorter than the minimum legal size.
    #[error("envelope is too short: {got} bytes, need at least {needed}")]
    EnvelopeTooShort { got: usize, needed: usize },

    /// Envelope length-prefix points past the buffer end.
    #[error("envelope ciphertext_len ({claimed}) exceeds buffer ({available})")]
    EnvelopeCiphertextLenOutOfRange { claimed: usize, available: usize },

    /// Envelope ciphertext_len smaller than nonce + tag.
    #[error("envelope ciphertext_len ({got}) is below the nonce+tag minimum ({minimum})")]
    EnvelopeCiphertextLenTooSmall { got: usize, minimum: usize },

    /// Memo plaintext contains a character outside the supported
    /// charset (Latin + Cyrillic). Emoji and CJK are rejected to keep
    /// every memo within a small, padded byte budget — a 4-byte emoji
    /// would consume four times the slot of an ASCII character. We
    /// expose the offending Unicode codepoint so the UI can highlight
    /// the bad position.
    #[error("memo contains an unsupported character: U+{codepoint:04X}")]
    UnsupportedMemoChar { codepoint: u32 },

    /// Padded plaintext blob is shorter than the 2-byte length prefix.
    #[error("padded memo plaintext is shorter than the 2-byte length prefix")]
    PaddedPlaintextTruncated,

    /// Padded plaintext blob has a `len` field that exceeds either
    /// the buffer size or `MAX_PLAINTEXT_LEN`. Indicates a wrong key,
    /// corruption, or pre-padding-format envelope.
    #[error("padded plaintext length field invalid: claimed {claimed}, max {max}")]
    PaddedPlaintextLengthInvalid { claimed: usize, max: usize },
}

/// A single encrypted memo ready to travel through the SPL Memo
/// Program instruction data.
///
/// Implements a small, stable wire format so the same struct can be
/// produced by the CLI, consumed by the indexer, and eventually
/// reconstructed inside a circuit without an intermediate parser.
#[derive(Clone, PartialEq, Eq)]
pub struct MemoPayload {
    ephemeral_pk: EphemeralPublicKey,
    iv: [u8; IV_LEN],
    tag: [u8; TAG_LEN],
    ciphertext: Vec<u8>,
}

impl MemoPayload {
    /// Encrypt `plaintext` so that only the holder of the secret key
    /// corresponding to `auditor_pk` can recover it.
    ///
    /// Generates a fresh ephemeral scalar per call — never reuse a
    /// `MemoPayload` between memos even for the same auditor, because
    /// that would reuse the AES key and IV and break confidentiality.
    pub fn encrypt(auditor_pk: &AuditorPublicKey, plaintext: &[u8]) -> Result<Self, MemoError> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(MemoError::PlaintextTooLong {
                got: plaintext.len(),
            });
        }

        let (ephemeral_pk, shared) = elgamal::ecdh_send(auditor_pk)?;
        let key_bytes = derive_aes_key(&shared);

        let mut iv = [0u8; IV_LEN];
        SysRng
            .try_fill_bytes(&mut iv)
            .map_err(|err: rand::rngs::SysError| MemoError::Rand(err.to_string()))?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&iv);
        let ct_with_tag = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| MemoError::EncryptionFailed)?;

        // aes-gcm concatenates the 16-byte tag after the ciphertext.
        // Split the two halves so the wire format has a stable prefix.
        let split = ct_with_tag
            .len()
            .checked_sub(TAG_LEN)
            .ok_or(MemoError::EncryptionFailed)?;
        let tag: [u8; TAG_LEN] = ct_with_tag[split..]
            .try_into()
            .map_err(|_| MemoError::EncryptionFailed)?;
        let ciphertext = ct_with_tag[..split].to_vec();

        Ok(Self {
            ephemeral_pk,
            iv,
            tag,
            ciphertext,
        })
    }

    /// Attempt to decrypt under `auditor_sk`. Returns
    /// [`MemoError::DecryptionFailed`] on authentication-tag mismatch,
    /// which is the signal to the accountant that this memo is not
    /// for them.
    pub fn decrypt(&self, auditor_sk: &AuditorSecretKey) -> Result<Vec<u8>, MemoError> {
        let shared = elgamal::ecdh_recv(auditor_sk, &self.ephemeral_pk)?;
        let key_bytes = derive_aes_key(&shared);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
        let nonce = Nonce::from_slice(&self.iv);

        let mut ct_with_tag = Vec::with_capacity(self.ciphertext.len() + TAG_LEN);
        ct_with_tag.extend_from_slice(&self.ciphertext);
        ct_with_tag.extend_from_slice(&self.tag);

        cipher
            .decrypt(nonce, ct_with_tag.as_ref())
            .map_err(|_| MemoError::DecryptionFailed)
    }

    /// Borrow the ephemeral public key carried by this payload.
    pub fn ephemeral_public_key(&self) -> &EphemeralPublicKey {
        &self.ephemeral_pk
    }

    /// Serialise to the fixed-layout byte string described in the
    /// module docs.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PAYLOAD_PREFIX_LEN + self.ciphertext.len());
        out.extend_from_slice(self.ephemeral_pk.as_bytes());
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse the fixed-layout byte string produced by [`to_bytes`].
    ///
    /// Validates lengths and the embedded ephemeral public key; the
    /// authentication tag is only checked during [`decrypt`] against
    /// a specific auditor secret.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
        if bytes.len() < PAYLOAD_PREFIX_LEN {
            return Err(MemoError::PayloadTooShort { got: bytes.len() });
        }

        let mut ephemeral_bytes = [0u8; POINT_LEN];
        ephemeral_bytes.copy_from_slice(&bytes[0..POINT_LEN]);
        let ephemeral_pk = EphemeralPublicKey::from_bytes(ephemeral_bytes)?;

        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&bytes[POINT_LEN..POINT_LEN + IV_LEN]);

        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&bytes[POINT_LEN + IV_LEN..PAYLOAD_PREFIX_LEN]);

        let ciphertext = bytes[PAYLOAD_PREFIX_LEN..].to_vec();

        Ok(Self {
            ephemeral_pk,
            iv,
            tag,
            ciphertext,
        })
    }

    /// Encode as the base64 string that goes inside the SPL Memo
    /// Program instruction data.
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.to_bytes())
    }

    /// Decode a base64 string pulled off the chain.
    pub fn from_base64(input: &str) -> Result<Self, MemoError> {
        let bytes = BASE64
            .decode(input.as_bytes())
            .map_err(|_| MemoError::InvalidBase64)?;
        Self::from_bytes(&bytes)
    }
}

impl std::fmt::Debug for MemoPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoPayload")
            .field("ephemeral_pk", &self.ephemeral_pk)
            .field("ciphertext_len", &self.ciphertext.len())
            .finish_non_exhaustive()
    }
}

/// Derive the 32-byte AES-256 key from an ECDH shared secret.
///
/// Public mostly so the v0.2 in-circuit gadget can target the same
/// KDF output when the memo check gets pulled onchain.
pub fn derive_aes_key(shared: &SharedSecret) -> [u8; AES_KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(shared.as_bytes());
    hasher.update(MEMO_DOMAIN_V1);
    let digest = hasher.finalize();
    let mut out = [0u8; AES_KEY_LEN];
    out.copy_from_slice(&digest);
    out
}

// ════════════════════════════════════════════════════════════════════
// ADR-012 — MemoEnvelope (v0.2 wire format)
// ════════════════════════════════════════════════════════════════════
//
// Single memo plaintext, encrypted ONCE under a per-deposit random
// AES key K. K is then "wrapped" (re-encrypted) for each authorised
// reader: always for the note holder (key derived from the note's
// secret + nullifier), optionally also for an auditor (ECDH on Baby
// Jubjub). Both paths recover the same K and decrypt the same memo.
//
// Wire format:
//
//   version    : u8       0x01
//   flags      : u8       bit 0 = auditor present
//   cipher_len : u16 BE   length of the AES-GCM ciphertext block
//                         (= 12 nonce + 16 tag + N data bytes)
//   ciphertext : variable AES-GCM(K, plaintext)
//   wrap_recipient : 60   nonce(12) || tag(16) || ENC(seal_key, K)(32)
//   wrap_auditor   : 92   ephemeral_pk(32) || nonce(12) || tag(16) || ENC(K)(32)
//                         (only when flags & 0x01)
//
// `seal_key` is derived from the note's secret + nullifier via
// SHA-256(secret || nullifier || ENVELOPE_SEAL_DOMAIN_V1).

/// Envelope wire-format version we currently emit.
pub const ENVELOPE_VERSION_V1: u8 = 0x01;

/// Bit 0 of the flags byte: auditor wrap-K slot is present.
pub const ENVELOPE_FLAG_AUDITOR: u8 = 0x01;

/// Domain separator for the recipient seal key. Bumping the suffix
/// invalidates every previously written envelope under the old key.
const ENVELOPE_SEAL_DOMAIN_V1: &[u8] = b"tidex6-memo-seal-v1";

/// AES-GCM ciphertext block overhead = nonce + tag.
const ENVELOPE_AEAD_OVERHEAD: usize = IV_LEN + TAG_LEN;

/// Length of the recipient wrap-K slot: nonce + tag + 32-byte wrapped key.
pub const ENVELOPE_WRAP_RECIPIENT_LEN: usize = IV_LEN + TAG_LEN + AES_KEY_LEN;

/// Length of the auditor wrap-K slot: ephemeral_pk + nonce + tag + 32-byte wrapped key.
pub const ENVELOPE_WRAP_AUDITOR_LEN: usize = POINT_LEN + IV_LEN + TAG_LEN + AES_KEY_LEN;

/// Header size: version (1) + flags (1) + cipher_len (2).
pub const ENVELOPE_HEADER_LEN: usize = 1 + 1 + 2;

/// Minimum legal envelope: header + empty ciphertext block + recipient wrap.
pub const ENVELOPE_MIN_LEN: usize =
    ENVELOPE_HEADER_LEN + ENVELOPE_AEAD_OVERHEAD + ENVELOPE_WRAP_RECIPIENT_LEN;

/// Maximum legal envelope: header + max ciphertext + both wraps.
pub const ENVELOPE_MAX_LEN: usize = ENVELOPE_HEADER_LEN
    + ENVELOPE_AEAD_OVERHEAD
    + PADDED_PLAINTEXT_LEN
    + ENVELOPE_WRAP_RECIPIENT_LEN
    + ENVELOPE_WRAP_AUDITOR_LEN;

/// Length-prefix size used by the padded-plaintext scheme. Two bytes
/// big-endian — covers any plaintext up to 65535, which is far above
/// `MAX_PLAINTEXT_LEN`.
pub const PLAINTEXT_LEN_PREFIX: usize = 2;

/// Total length of the padded plaintext that goes into AES-GCM.
/// Always exactly this many bytes regardless of how short the user's
/// memo is — the goal is to leak zero information about plaintext
/// length to a passive observer of the on-chain envelope.
pub const PADDED_PLAINTEXT_LEN: usize = PLAINTEXT_LEN_PREFIX + MAX_PLAINTEXT_LEN;

/// Allowed Unicode ranges for memo plaintext. We restrict to Latin
/// and Cyrillic only — emoji, CJK and other large-codepoint scripts
/// are rejected so every memo fits in a small, fixed-size padded
/// buffer. See `validate_memo_charset` for the per-character check.
fn is_allowed_memo_char(c: char) -> bool {
    let cp = c as u32;
    matches!(
        cp,
        // Whitespace.
        0x09 | 0x0A | 0x0D
        // ASCII printable.
        | 0x20..=0x7E
        // Latin-1 Supplement (printable).
        | 0xA0..=0xFF
        // Latin Extended-A.
        | 0x0100..=0x017F
        // Latin Extended-B.
        | 0x0180..=0x024F
        // Cyrillic.
        | 0x0400..=0x04FF
        // Cyrillic Supplement.
        | 0x0500..=0x052F
    )
}

/// Reject any plaintext that contains characters outside the Latin +
/// Cyrillic union. Returns `Ok(())` on success, `UnsupportedMemoChar`
/// with the first offending codepoint on failure.
pub fn validate_memo_charset(plaintext: &str) -> Result<(), MemoError> {
    for c in plaintext.chars() {
        if !is_allowed_memo_char(c) {
            return Err(MemoError::UnsupportedMemoChar {
                codepoint: c as u32,
            });
        }
    }
    Ok(())
}

/// Build the fixed-length padded plaintext that goes into AES-GCM:
/// `[u16 BE actual_len][user bytes][random pad to MAX_PLAINTEXT_LEN]`.
/// Always returns exactly `PADDED_PLAINTEXT_LEN` bytes.
fn pad_plaintext_for_envelope(plaintext: &[u8]) -> Result<[u8; PADDED_PLAINTEXT_LEN], MemoError> {
    if plaintext.len() > MAX_PLAINTEXT_LEN {
        return Err(MemoError::PlaintextTooLong {
            got: plaintext.len(),
        });
    }
    let mut padded = [0u8; PADDED_PLAINTEXT_LEN];
    let actual_len = plaintext.len() as u16;
    padded[0..2].copy_from_slice(&actual_len.to_be_bytes());
    padded[2..2 + plaintext.len()].copy_from_slice(plaintext);
    // Random padding — not zeros, not user-visible characters. Random
    // because zeros leak entropy patterns to a future cryptanalyst,
    // however small. A few hundred random bytes per deposit cost
    // nothing.
    SysRng
        .try_fill_bytes(&mut padded[2 + plaintext.len()..])
        .map_err(|err: rand::rngs::SysError| MemoError::Rand(err.to_string()))?;
    Ok(padded)
}

/// Inverse of [`pad_plaintext_for_envelope`]. Reads the 2-byte length
/// prefix, validates it, returns the trimmed user plaintext.
fn unpad_envelope_plaintext(padded: &[u8]) -> Result<Vec<u8>, MemoError> {
    if padded.len() < PLAINTEXT_LEN_PREFIX {
        return Err(MemoError::PaddedPlaintextTruncated);
    }
    let claimed = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if claimed > MAX_PLAINTEXT_LEN || PLAINTEXT_LEN_PREFIX + claimed > padded.len() {
        return Err(MemoError::PaddedPlaintextLengthInvalid {
            claimed,
            max: MAX_PLAINTEXT_LEN,
        });
    }
    Ok(padded[PLAINTEXT_LEN_PREFIX..PLAINTEXT_LEN_PREFIX + claimed].to_vec())
}

/// Symmetric "seal key" derived from a note's secret material.
/// Anyone holding the note can reproduce it; nobody else.
pub struct NoteSealKey([u8; AES_KEY_LEN]);

impl NoteSealKey {
    /// Derive from `secret` and `nullifier` using SHA-256 with a
    /// fixed domain tag. Same algorithmic shape as `derive_aes_key`,
    /// just with different inputs and a different domain so the two
    /// keys never collide.
    pub fn from_note_material(secret: &[u8; 32], nullifier: &[u8; 32]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(secret);
        hasher.update(nullifier);
        hasher.update(ENVELOPE_SEAL_DOMAIN_V1);
        let digest = hasher.finalize();
        let mut out = [0u8; AES_KEY_LEN];
        out.copy_from_slice(&digest);
        Self(out)
    }

    fn as_bytes(&self) -> &[u8; AES_KEY_LEN] {
        &self.0
    }
}

/// A single memo envelope addressed to one or two readers.
#[derive(Clone, PartialEq, Eq)]
pub struct MemoEnvelope {
    flags: u8,
    /// AES-GCM ciphertext block: nonce (12) || tag (16) || data (N).
    /// Includes empty data for placeholder envelopes.
    ciphertext_block: Vec<u8>,
    /// Recipient wrap: nonce (12) || tag (16) || wrapped K (32).
    wrap_recipient: [u8; ENVELOPE_WRAP_RECIPIENT_LEN],
    /// Auditor wrap: present when `flags & ENVELOPE_FLAG_AUDITOR`.
    wrap_auditor: Option<[u8; ENVELOPE_WRAP_AUDITOR_LEN]>,
}

impl MemoEnvelope {
    /// Encrypt `plaintext` so only the note holder can decrypt.
    ///
    /// Padding-by-default: `plaintext` is wrapped in a length-prefixed
    /// fixed-size 258-byte buffer before encryption, so every envelope
    /// produced by this function has the same on-chain footprint
    /// regardless of how short the actual memo is.
    pub fn encrypt_for_recipient_only(
        plaintext: &[u8],
        secret: &[u8; 32],
        nullifier: &[u8; 32],
    ) -> Result<Self, MemoError> {
        let padded = pad_plaintext_for_envelope(plaintext)?;
        let memo_key = generate_random_key()?;
        let ciphertext_block = aead_seal(&memo_key, &padded)?;
        let seal_key = NoteSealKey::from_note_material(secret, nullifier);
        let wrap_recipient = wrap_key_with_aes(seal_key.as_bytes(), &memo_key)?;
        Ok(Self {
            flags: 0,
            ciphertext_block,
            wrap_recipient,
            wrap_auditor: None,
        })
    }

    /// Encrypt `plaintext` so both the note holder and the named
    /// auditor can decrypt. Same plaintext, two wrap-K slots.
    ///
    /// Padding-by-default: see [`Self::encrypt_for_recipient_only`].
    pub fn encrypt_for_recipient_and_auditor(
        plaintext: &[u8],
        secret: &[u8; 32],
        nullifier: &[u8; 32],
        auditor_pk: &AuditorPublicKey,
    ) -> Result<Self, MemoError> {
        let padded = pad_plaintext_for_envelope(plaintext)?;
        let memo_key = generate_random_key()?;
        let ciphertext_block = aead_seal(&memo_key, &padded)?;

        let seal_key = NoteSealKey::from_note_material(secret, nullifier);
        let wrap_recipient = wrap_key_with_aes(seal_key.as_bytes(), &memo_key)?;
        let wrap_auditor = wrap_key_with_auditor(auditor_pk, &memo_key)?;

        Ok(Self {
            flags: ENVELOPE_FLAG_AUDITOR,
            ciphertext_block,
            wrap_recipient,
            wrap_auditor: Some(wrap_auditor),
        })
    }

    /// Decrypt under the note's seal key. Returns the user plaintext
    /// trimmed of the length-prefix padding that was added at
    /// encryption time.
    pub fn decrypt_with_note(
        &self,
        secret: &[u8; 32],
        nullifier: &[u8; 32],
    ) -> Result<Vec<u8>, MemoError> {
        let seal_key = NoteSealKey::from_note_material(secret, nullifier);
        let memo_key = unwrap_key_with_aes(seal_key.as_bytes(), &self.wrap_recipient)?;
        let padded = aead_open(&memo_key, &self.ciphertext_block)?;
        unpad_envelope_plaintext(&padded)
    }

    /// Try to decrypt under an auditor secret key.
    /// Returns `Ok(Some(_))` on success, `Ok(None)` if there is no
    /// auditor slot or the slot is not addressed to this key,
    /// `Err(_)` on malformed inputs. Plaintext is unpadded — the
    /// length-prefix scheme used at encryption time is reversed here.
    pub fn decrypt_with_auditor(
        &self,
        auditor_sk: &AuditorSecretKey,
    ) -> Result<Option<Vec<u8>>, MemoError> {
        let Some(wrap) = self.wrap_auditor else {
            return Ok(None);
        };
        let memo_key = match unwrap_key_with_auditor(auditor_sk, &wrap) {
            Ok(key) => key,
            Err(MemoError::DecryptionFailed) => return Ok(None),
            Err(other) => return Err(other),
        };
        let padded = aead_open(&memo_key, &self.ciphertext_block)?;
        let pt = unpad_envelope_plaintext(&padded)?;
        Ok(Some(pt))
    }

    /// Whether this envelope carries an auditor wrap-K slot.
    pub fn has_auditor(&self) -> bool {
        self.wrap_auditor.is_some()
    }

    /// Serialise to the binary wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let cipher_len: u16 = self.ciphertext_block.len() as u16;
        let mut out = Vec::with_capacity(self.byte_len());
        out.push(ENVELOPE_VERSION_V1);
        out.push(self.flags);
        out.extend_from_slice(&cipher_len.to_be_bytes());
        out.extend_from_slice(&self.ciphertext_block);
        out.extend_from_slice(&self.wrap_recipient);
        if let Some(ref wa) = self.wrap_auditor {
            out.extend_from_slice(wa);
        }
        out
    }

    /// Parse the wire format produced by `to_bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MemoError> {
        if bytes.len() < ENVELOPE_MIN_LEN {
            return Err(MemoError::EnvelopeTooShort {
                got: bytes.len(),
                needed: ENVELOPE_MIN_LEN,
            });
        }
        let version = bytes[0];
        if version != ENVELOPE_VERSION_V1 {
            return Err(MemoError::UnknownEnvelopeVersion(version));
        }
        let flags = bytes[1];
        if flags & !ENVELOPE_FLAG_AUDITOR != 0 {
            return Err(MemoError::UnknownEnvelopeFlags(flags));
        }
        let cipher_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        if cipher_len < ENVELOPE_AEAD_OVERHEAD {
            return Err(MemoError::EnvelopeCiphertextLenTooSmall {
                got: cipher_len,
                minimum: ENVELOPE_AEAD_OVERHEAD,
            });
        }
        let cipher_end = ENVELOPE_HEADER_LEN + cipher_len;
        let wrap_recipient_end = cipher_end + ENVELOPE_WRAP_RECIPIENT_LEN;
        let auditor_present = (flags & ENVELOPE_FLAG_AUDITOR) != 0;
        let total_expected = if auditor_present {
            wrap_recipient_end + ENVELOPE_WRAP_AUDITOR_LEN
        } else {
            wrap_recipient_end
        };
        if total_expected > bytes.len() {
            return Err(MemoError::EnvelopeCiphertextLenOutOfRange {
                claimed: total_expected,
                available: bytes.len(),
            });
        }

        let ciphertext_block = bytes[ENVELOPE_HEADER_LEN..cipher_end].to_vec();

        let mut wrap_recipient = [0u8; ENVELOPE_WRAP_RECIPIENT_LEN];
        wrap_recipient.copy_from_slice(&bytes[cipher_end..wrap_recipient_end]);

        let wrap_auditor = if auditor_present {
            let mut wa = [0u8; ENVELOPE_WRAP_AUDITOR_LEN];
            wa.copy_from_slice(&bytes[wrap_recipient_end..wrap_recipient_end + ENVELOPE_WRAP_AUDITOR_LEN]);
            Some(wa)
        } else {
            None
        };

        Ok(Self {
            flags,
            ciphertext_block,
            wrap_recipient,
            wrap_auditor,
        })
    }

    fn byte_len(&self) -> usize {
        ENVELOPE_HEADER_LEN
            + self.ciphertext_block.len()
            + ENVELOPE_WRAP_RECIPIENT_LEN
            + if self.wrap_auditor.is_some() {
                ENVELOPE_WRAP_AUDITOR_LEN
            } else {
                0
            }
    }
}

impl std::fmt::Debug for MemoEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoEnvelope")
            .field("flags", &format_args!("0x{:02x}", self.flags))
            .field("ciphertext_len", &self.ciphertext_block.len())
            .field("has_auditor", &self.has_auditor())
            .finish_non_exhaustive()
    }
}

/// Build an envelope that nobody can decrypt — for fully anonymous
/// deposits where the sender does not want to attach a memo at all.
/// The on-chain bytes are syntactically a real envelope so an
/// observer cannot bucket users by "this one always skips memo".
///
/// Generates random ephemeral key material and tosses it. The note
/// holder cannot recover anything because the wrap-K slot was sealed
/// with a key derived from random scratch material instead of their
/// own secret/nullifier.
pub fn placeholder_envelope_for_anonymous() -> Result<Vec<u8>, MemoError> {
    // Random "secret" and "nullifier" — they never match anything
    // the actual note holder has, so the wrap-K slot is unrecoverable.
    let mut fake_secret = [0u8; 32];
    let mut fake_nullifier = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut fake_secret)
        .map_err(|err: rand::rngs::SysError| MemoError::Rand(err.to_string()))?;
    SysRng
        .try_fill_bytes(&mut fake_nullifier)
        .map_err(|err: rand::rngs::SysError| MemoError::Rand(err.to_string()))?;

    // Encrypt a small random-length plaintext so size patterns do not
    // give the placeholder away.
    let mut len_byte = [0u8; 1];
    SysRng
        .try_fill_bytes(&mut len_byte)
        .map_err(|err: rand::rngs::SysError| MemoError::Rand(err.to_string()))?;
    let pad_len = (len_byte[0] as usize) % 64; // 0..63 bytes
    let mut padding = vec![0u8; pad_len];
    if pad_len > 0 {
        SysRng
            .try_fill_bytes(&mut padding)
            .map_err(|err: rand::rngs::SysError| MemoError::Rand(err.to_string()))?;
    }

    Ok(MemoEnvelope::encrypt_for_recipient_only(&padding, &fake_secret, &fake_nullifier)?
        .to_bytes())
}

// ════════════════════════════════════════════════════════════════════
// Internal AEAD helpers used by the envelope code.
// ════════════════════════════════════════════════════════════════════

fn generate_random_key() -> Result<[u8; AES_KEY_LEN], MemoError> {
    let mut k = [0u8; AES_KEY_LEN];
    SysRng
        .try_fill_bytes(&mut k)
        .map_err(|err: rand::rngs::SysError| MemoError::Rand(err.to_string()))?;
    Ok(k)
}

/// AES-256-GCM seal that returns nonce || tag || data as a single
/// Vec, matching the layout `MemoEnvelope::ciphertext_block` expects.
fn aead_seal(key: &[u8; AES_KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, MemoError> {
    let mut iv = [0u8; IV_LEN];
    SysRng
        .try_fill_bytes(&mut iv)
        .map_err(|err: rand::rngs::SysError| MemoError::Rand(err.to_string()))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(&iv);
    let ct_with_tag = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| MemoError::EncryptionFailed)?;
    // aes-gcm appends tag after ciphertext. We want nonce || tag ||
    // data so split and re-concat.
    let split = ct_with_tag
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(MemoError::EncryptionFailed)?;
    let mut out = Vec::with_capacity(IV_LEN + TAG_LEN + split);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct_with_tag[split..]);
    out.extend_from_slice(&ct_with_tag[..split]);
    Ok(out)
}

/// Inverse of `aead_seal`. Expects nonce(12) || tag(16) || data(N).
fn aead_open(key: &[u8; AES_KEY_LEN], block: &[u8]) -> Result<Vec<u8>, MemoError> {
    if block.len() < ENVELOPE_AEAD_OVERHEAD {
        return Err(MemoError::EnvelopeCiphertextLenTooSmall {
            got: block.len(),
            minimum: ENVELOPE_AEAD_OVERHEAD,
        });
    }
    let iv = &block[..IV_LEN];
    let tag = &block[IV_LEN..IV_LEN + TAG_LEN];
    let data = &block[IV_LEN + TAG_LEN..];

    // aes-gcm wants ct || tag, we have tag separated.
    let mut ct_with_tag = Vec::with_capacity(data.len() + TAG_LEN);
    ct_with_tag.extend_from_slice(data);
    ct_with_tag.extend_from_slice(tag);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, ct_with_tag.as_ref())
        .map_err(|_| MemoError::DecryptionFailed)
}

/// Wrap a 32-byte memo key under a symmetric seal_key. Output layout:
/// nonce(12) || tag(16) || wrapped_K(32).
fn wrap_key_with_aes(
    seal_key: &[u8; AES_KEY_LEN],
    memo_key: &[u8; AES_KEY_LEN],
) -> Result<[u8; ENVELOPE_WRAP_RECIPIENT_LEN], MemoError> {
    let block = aead_seal(seal_key, memo_key)?;
    if block.len() != ENVELOPE_WRAP_RECIPIENT_LEN {
        return Err(MemoError::EncryptionFailed);
    }
    let mut out = [0u8; ENVELOPE_WRAP_RECIPIENT_LEN];
    out.copy_from_slice(&block);
    Ok(out)
}

fn unwrap_key_with_aes(
    seal_key: &[u8; AES_KEY_LEN],
    wrap: &[u8; ENVELOPE_WRAP_RECIPIENT_LEN],
) -> Result<[u8; AES_KEY_LEN], MemoError> {
    let pt = aead_open(seal_key, wrap)?;
    if pt.len() != AES_KEY_LEN {
        return Err(MemoError::DecryptionFailed);
    }
    let mut out = [0u8; AES_KEY_LEN];
    out.copy_from_slice(&pt);
    Ok(out)
}

/// Wrap a 32-byte memo key for an auditor via Baby Jubjub ECDH.
/// Output: ephemeral_pk(32) || nonce(12) || tag(16) || wrapped_K(32).
fn wrap_key_with_auditor(
    auditor_pk: &AuditorPublicKey,
    memo_key: &[u8; AES_KEY_LEN],
) -> Result<[u8; ENVELOPE_WRAP_AUDITOR_LEN], MemoError> {
    let (ephemeral_pk, shared) = elgamal::ecdh_send(auditor_pk)?;
    let aes_key = derive_aes_key(&shared);
    let block = aead_seal(&aes_key, memo_key)?;
    if block.len() != ENVELOPE_WRAP_RECIPIENT_LEN {
        return Err(MemoError::EncryptionFailed);
    }
    let mut out = [0u8; ENVELOPE_WRAP_AUDITOR_LEN];
    out[..POINT_LEN].copy_from_slice(ephemeral_pk.as_bytes());
    out[POINT_LEN..].copy_from_slice(&block);
    Ok(out)
}

fn unwrap_key_with_auditor(
    auditor_sk: &AuditorSecretKey,
    wrap: &[u8; ENVELOPE_WRAP_AUDITOR_LEN],
) -> Result<[u8; AES_KEY_LEN], MemoError> {
    let mut ephemeral_bytes = [0u8; POINT_LEN];
    ephemeral_bytes.copy_from_slice(&wrap[..POINT_LEN]);
    let ephemeral_pk = EphemeralPublicKey::from_bytes(ephemeral_bytes)?;
    let shared = elgamal::ecdh_recv(auditor_sk, &ephemeral_pk)?;
    let aes_key = derive_aes_key(&shared);

    let mut block = [0u8; ENVELOPE_WRAP_RECIPIENT_LEN];
    block.copy_from_slice(&wrap[POINT_LEN..]);
    unwrap_key_with_aes(&aes_key, &block)
}

/// Build a minimal valid `MemoPayload` for tests and live-flight
/// harnesses that do not care about memo content but still need to
/// satisfy the on-chain length bounds of
/// `tidex6_verifier::pool::MEMO_PAYLOAD_MIN_LEN`.
///
/// Generates a fresh auditor keypair in memory, encrypts a short
/// fixed plaintext under it, and returns the binary payload. No
/// persistence: the key is dropped at function return, so the
/// resulting memo is cryptographically unreadable — which is
/// exactly what we want for a harness that only exercises the
/// transport path.
pub fn placeholder_payload_for_harness() -> Vec<u8> {
    use crate::elgamal::AuditorSecretKey;
    let sk = AuditorSecretKey::random().expect("OS CSPRNG must succeed");
    let pk = sk.public_key();
    MemoPayload::encrypt(&pk, b"flight-harness-placeholder")
        .expect("encrypting a 26-byte plaintext cannot fail")
        .to_bytes()
}

/// High-level helper: encrypt `plaintext` under `auditor_pk` and
/// return the base64 string ready for an SPL Memo instruction.
///
/// This is the entry point the CLI and the indexer both use; there
/// is no reason to build a `MemoPayload` by hand outside of tests.
pub fn encrypt_for_auditor(
    auditor_pk: &AuditorPublicKey,
    plaintext: &[u8],
) -> Result<String, MemoError> {
    Ok(MemoPayload::encrypt(auditor_pk, plaintext)?.to_base64())
}

/// Try to decrypt a base64 memo string under `auditor_sk`.
///
/// Returns `Ok(Some(plaintext))` on success, `Ok(None)` when the
/// payload parses but the authentication tag rejects the key (the
/// "not addressed to me" case the accountant hits constantly), and
/// `Err` only for malformed payloads that the caller should surface
/// as hard errors.
pub fn try_decrypt_for_auditor(
    auditor_sk: &AuditorSecretKey,
    base64_input: &str,
) -> Result<Option<Vec<u8>>, MemoError> {
    let payload = MemoPayload::from_base64(base64_input)?;
    match payload.decrypt(auditor_sk) {
        Ok(pt) => Ok(Some(pt)),
        Err(MemoError::DecryptionFailed) => Ok(None),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IV_LEN, MAX_PLAINTEXT_LEN, MemoError, MemoPayload, PAYLOAD_PREFIX_LEN, TAG_LEN,
        encrypt_for_auditor, try_decrypt_for_auditor,
    };
    use crate::elgamal::{AuditorSecretKey, POINT_LEN};

    /// Encrypt → decrypt must recover the original bytes byte-for-byte.
    #[test]
    fn encrypt_decrypt_roundtrip() {
        let auditor_sk = AuditorSecretKey::random().unwrap();
        let auditor_pk = auditor_sk.public_key();
        let plaintext = b"Rent March 2026 / parents";
        let payload = MemoPayload::encrypt(&auditor_pk, plaintext).unwrap();
        let recovered = payload.decrypt(&auditor_sk).unwrap();
        assert_eq!(&recovered[..], &plaintext[..]);
    }

    /// The wrong auditor key produces `DecryptionFailed`, not an
    /// obscure panic. This is load-bearing — the accountant scan
    /// relies on it as its "skip" signal.
    #[test]
    fn wrong_key_rejected_cleanly() {
        let alice_sk = AuditorSecretKey::random().unwrap();
        let bob_sk = AuditorSecretKey::random().unwrap();
        let alice_pk = alice_sk.public_key();
        let payload = MemoPayload::encrypt(&alice_pk, b"for alice only").unwrap();
        match payload.decrypt(&bob_sk) {
            Err(MemoError::DecryptionFailed) => {}
            other => panic!("expected DecryptionFailed, got {other:?}"),
        }
    }

    /// Fresh ephemeral scalars per call mean every ciphertext of the
    /// same plaintext under the same auditor key must differ.
    #[test]
    fn ciphertexts_are_randomised() {
        let auditor_sk = AuditorSecretKey::random().unwrap();
        let auditor_pk = auditor_sk.public_key();
        let a = MemoPayload::encrypt(&auditor_pk, b"same plaintext").unwrap();
        let b = MemoPayload::encrypt(&auditor_pk, b"same plaintext").unwrap();
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    /// The binary wire format round-trips cleanly.
    #[test]
    fn bytes_roundtrip() {
        let auditor_sk = AuditorSecretKey::random().unwrap();
        let auditor_pk = auditor_sk.public_key();
        let payload = MemoPayload::encrypt(&auditor_pk, b"hello").unwrap();
        let bytes = payload.to_bytes();
        assert_eq!(bytes.len(), PAYLOAD_PREFIX_LEN + b"hello".len());
        let parsed = MemoPayload::from_bytes(&bytes).unwrap();
        assert_eq!(payload, parsed);
    }

    /// The base64 wire format round-trips and produces a string short
    /// enough for SPL Memo.
    #[test]
    fn base64_roundtrip() {
        let auditor_sk = AuditorSecretKey::random().unwrap();
        let auditor_pk = auditor_sk.public_key();
        let plaintext = b"Rent March 2026 / parents";
        let encoded = encrypt_for_auditor(&auditor_pk, plaintext).unwrap();
        // Well under the 566 SPL Memo limit.
        assert!(encoded.len() < 400);
        let decoded = try_decrypt_for_auditor(&auditor_sk, &encoded)
            .unwrap()
            .unwrap();
        assert_eq!(&decoded[..], &plaintext[..]);
    }

    /// Wrong key through the high-level helper returns `Ok(None)`,
    /// not an error.
    #[test]
    fn try_decrypt_returns_none_on_wrong_key() {
        let alice_sk = AuditorSecretKey::random().unwrap();
        let bob_sk = AuditorSecretKey::random().unwrap();
        let alice_pk = alice_sk.public_key();
        let encoded = encrypt_for_auditor(&alice_pk, b"for alice").unwrap();
        let result = try_decrypt_for_auditor(&bob_sk, &encoded).unwrap();
        assert!(result.is_none());
    }

    /// Hard-error path: malformed base64 must surface as an error.
    #[test]
    fn try_decrypt_errors_on_bad_base64() {
        let sk = AuditorSecretKey::random().unwrap();
        match try_decrypt_for_auditor(&sk, "not valid base64 !!!") {
            Err(MemoError::InvalidBase64) => {}
            other => panic!("expected InvalidBase64, got {other:?}"),
        }
    }

    /// Payloads shorter than the fixed prefix must be rejected
    /// before any cryptographic operation.
    #[test]
    fn short_payload_rejected() {
        let too_short = vec![0u8; PAYLOAD_PREFIX_LEN - 1];
        match MemoPayload::from_bytes(&too_short) {
            Err(MemoError::PayloadTooShort { got }) => {
                assert_eq!(got, PAYLOAD_PREFIX_LEN - 1)
            }
            other => panic!("expected PayloadTooShort, got {other:?}"),
        }
    }

    /// The plaintext length cap is enforced before encryption so a
    /// caller cannot produce a payload that would not fit in SPL
    /// Memo.
    #[test]
    fn plaintext_length_cap_enforced() {
        let auditor_sk = AuditorSecretKey::random().unwrap();
        let auditor_pk = auditor_sk.public_key();
        let huge = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        match MemoPayload::encrypt(&auditor_pk, &huge) {
            Err(MemoError::PlaintextTooLong { got }) => assert_eq!(got, huge.len()),
            other => panic!("expected PlaintextTooLong, got {other:?}"),
        }
    }

    /// Prefix lengths add up to the advertised constant — catches
    /// accidental drift in the wire format.
    #[test]
    fn payload_prefix_layout_is_stable() {
        assert_eq!(PAYLOAD_PREFIX_LEN, POINT_LEN + IV_LEN + TAG_LEN);
    }

    // ════════════════════════════════════════════════════════════════
    // ADR-012 — MemoEnvelope tests
    // ════════════════════════════════════════════════════════════════

    use super::{
        ENVELOPE_HEADER_LEN, ENVELOPE_MAX_LEN, ENVELOPE_MIN_LEN, ENVELOPE_VERSION_V1,
        ENVELOPE_WRAP_AUDITOR_LEN, ENVELOPE_WRAP_RECIPIENT_LEN, MemoEnvelope,
        PADDED_PLAINTEXT_LEN, PLAINTEXT_LEN_PREFIX, pad_plaintext_for_envelope,
        placeholder_envelope_for_anonymous, unpad_envelope_plaintext, validate_memo_charset,
    };

    fn fresh_secrets() -> ([u8; 32], [u8; 32]) {
        use rand::TryRng;
        use rand::rngs::SysRng;
        let mut secret = [0u8; 32];
        let mut nullifier = [0u8; 32];
        SysRng.try_fill_bytes(&mut secret).unwrap();
        SysRng.try_fill_bytes(&mut nullifier).unwrap();
        (secret, nullifier)
    }

    /// Round-trip a recipient-only envelope and confirm the plaintext
    /// comes back byte-for-byte through the note's seal key.
    #[test]
    fn envelope_recipient_only_roundtrip() {
        let (secret, nullifier) = fresh_secrets();
        let plaintext = b"Rand Match 2026";
        let env = MemoEnvelope::encrypt_for_recipient_only(plaintext, &secret, &nullifier).unwrap();
        let recovered = env.decrypt_with_note(&secret, &nullifier).unwrap();
        assert_eq!(&recovered[..], &plaintext[..]);
        assert!(!env.has_auditor());
    }

    /// Envelope with both recipient and auditor slots: both decrypt
    /// paths recover the same plaintext.
    #[test]
    fn envelope_both_slots_roundtrip() {
        let (secret, nullifier) = fresh_secrets();
        let auditor_sk = AuditorSecretKey::random().unwrap();
        let auditor_pk = auditor_sk.public_key();
        let plaintext = b"Rent April 2026";

        let env = MemoEnvelope::encrypt_for_recipient_and_auditor(
            plaintext,
            &secret,
            &nullifier,
            &auditor_pk,
        )
        .unwrap();
        assert!(env.has_auditor());

        let recipient_pt = env.decrypt_with_note(&secret, &nullifier).unwrap();
        assert_eq!(&recipient_pt[..], &plaintext[..]);

        let auditor_pt = env.decrypt_with_auditor(&auditor_sk).unwrap().unwrap();
        assert_eq!(&auditor_pt[..], &plaintext[..]);
    }

    /// Different note material cannot decrypt someone else's envelope.
    #[test]
    fn envelope_rejects_wrong_note() {
        let (secret_a, nullifier_a) = fresh_secrets();
        let (secret_b, nullifier_b) = fresh_secrets();
        let env =
            MemoEnvelope::encrypt_for_recipient_only(b"secret", &secret_a, &nullifier_a).unwrap();
        let attempt = env.decrypt_with_note(&secret_b, &nullifier_b);
        assert!(matches!(attempt, Err(MemoError::DecryptionFailed)));
    }

    /// Wrong auditor returns Ok(None), not an error.
    #[test]
    fn envelope_wrong_auditor_returns_none() {
        let (secret, nullifier) = fresh_secrets();
        let alice_sk = AuditorSecretKey::random().unwrap();
        let bob_sk = AuditorSecretKey::random().unwrap();
        let env = MemoEnvelope::encrypt_for_recipient_and_auditor(
            b"hi",
            &secret,
            &nullifier,
            &alice_sk.public_key(),
        )
        .unwrap();
        assert!(env.decrypt_with_auditor(&bob_sk).unwrap().is_none());
    }

    /// Recipient-only envelope returns Ok(None) when an auditor tries.
    #[test]
    fn envelope_no_auditor_slot_returns_none() {
        let (secret, nullifier) = fresh_secrets();
        let auditor_sk = AuditorSecretKey::random().unwrap();
        let env =
            MemoEnvelope::encrypt_for_recipient_only(b"hi", &secret, &nullifier).unwrap();
        assert!(env.decrypt_with_auditor(&auditor_sk).unwrap().is_none());
    }

    /// Wire format round-trip: serialise, parse, decrypt — same plaintext.
    #[test]
    fn envelope_wire_roundtrip_recipient_only() {
        let (secret, nullifier) = fresh_secrets();
        let plaintext = b"hello world";
        let env =
            MemoEnvelope::encrypt_for_recipient_only(plaintext, &secret, &nullifier).unwrap();
        let bytes = env.to_bytes();
        assert!(bytes.len() >= ENVELOPE_MIN_LEN);
        assert!(bytes.len() <= ENVELOPE_MAX_LEN);
        assert_eq!(bytes[0], ENVELOPE_VERSION_V1);
        assert_eq!(bytes[1] & 0x01, 0);

        let parsed = MemoEnvelope::from_bytes(&bytes).unwrap();
        assert!(!parsed.has_auditor());
        let recovered = parsed.decrypt_with_note(&secret, &nullifier).unwrap();
        assert_eq!(&recovered[..], &plaintext[..]);
    }

    /// Wire format round-trip with auditor slot.
    #[test]
    fn envelope_wire_roundtrip_with_auditor() {
        let (secret, nullifier) = fresh_secrets();
        let auditor_sk = AuditorSecretKey::random().unwrap();
        let env = MemoEnvelope::encrypt_for_recipient_and_auditor(
            b"audit me",
            &secret,
            &nullifier,
            &auditor_sk.public_key(),
        )
        .unwrap();
        let bytes = env.to_bytes();
        assert_eq!(bytes[1] & 0x01, 1);
        let parsed = MemoEnvelope::from_bytes(&bytes).unwrap();
        assert!(parsed.has_auditor());
        let r = parsed.decrypt_with_note(&secret, &nullifier).unwrap();
        assert_eq!(&r[..], b"audit me");
        let a = parsed.decrypt_with_auditor(&auditor_sk).unwrap().unwrap();
        assert_eq!(&a[..], b"audit me");
    }

    /// Truncated wire format → `EnvelopeTooShort`.
    #[test]
    fn envelope_short_bytes_rejected() {
        let too_short = vec![0u8; ENVELOPE_MIN_LEN - 1];
        match MemoEnvelope::from_bytes(&too_short) {
            Err(MemoError::EnvelopeTooShort { got, needed }) => {
                assert_eq!(got, ENVELOPE_MIN_LEN - 1);
                assert_eq!(needed, ENVELOPE_MIN_LEN);
            }
            other => panic!("expected EnvelopeTooShort, got {other:?}"),
        }
    }

    /// Unknown version byte → `UnknownEnvelopeVersion`.
    #[test]
    fn envelope_unknown_version_rejected() {
        let mut bytes = vec![0u8; ENVELOPE_MIN_LEN];
        bytes[0] = 0xFF;
        match MemoEnvelope::from_bytes(&bytes) {
            Err(MemoError::UnknownEnvelopeVersion(v)) => assert_eq!(v, 0xFF),
            other => panic!("expected UnknownEnvelopeVersion, got {other:?}"),
        }
    }

    /// Plaintext over the cap is rejected.
    #[test]
    fn envelope_plaintext_cap_enforced() {
        let (secret, nullifier) = fresh_secrets();
        let huge = vec![0u8; MAX_PLAINTEXT_LEN + 1];
        match MemoEnvelope::encrypt_for_recipient_only(&huge, &secret, &nullifier) {
            Err(MemoError::PlaintextTooLong { got }) => assert_eq!(got, huge.len()),
            other => panic!("expected PlaintextTooLong, got {other:?}"),
        }
    }

    /// Placeholder envelope is syntactically valid but unrecoverable
    /// by anyone — even with random brute-force.
    #[test]
    fn envelope_placeholder_is_unrecoverable_but_parseable() {
        let bytes = placeholder_envelope_for_anonymous().unwrap();
        let env = MemoEnvelope::from_bytes(&bytes).unwrap();
        // Should not have an auditor slot in the placeholder.
        assert!(!env.has_auditor());
        // No real note material should match its random seal.
        let (secret, nullifier) = fresh_secrets();
        let attempt = env.decrypt_with_note(&secret, &nullifier);
        assert!(matches!(attempt, Err(MemoError::DecryptionFailed)));
    }

    /// Layout constants do not drift from the documented format.
    #[test]
    fn envelope_layout_constants_stable() {
        assert_eq!(ENVELOPE_HEADER_LEN, 4);
        assert_eq!(ENVELOPE_WRAP_RECIPIENT_LEN, IV_LEN + TAG_LEN + 32);
        assert_eq!(
            ENVELOPE_WRAP_AUDITOR_LEN,
            POINT_LEN + IV_LEN + TAG_LEN + 32
        );
        assert_eq!(PADDED_PLAINTEXT_LEN, PLAINTEXT_LEN_PREFIX + MAX_PLAINTEXT_LEN);
    }

    /// Every recipient-only envelope has the same byte length on the
    /// wire regardless of how short the user's plaintext is. Privacy
    /// property: no information about plaintext length leaks.
    #[test]
    fn envelope_size_is_constant_across_plaintext_lengths() {
        let (secret, nullifier) = fresh_secrets();
        let empty = MemoEnvelope::encrypt_for_recipient_only(b"", &secret, &nullifier)
            .unwrap()
            .to_bytes();
        let short = MemoEnvelope::encrypt_for_recipient_only(b"hi", &secret, &nullifier)
            .unwrap()
            .to_bytes();
        let max = MemoEnvelope::encrypt_for_recipient_only(
            &vec![b'a'; MAX_PLAINTEXT_LEN],
            &secret,
            &nullifier,
        )
        .unwrap()
        .to_bytes();
        assert_eq!(empty.len(), short.len());
        assert_eq!(short.len(), max.len());
    }

    /// Same property with the auditor slot present.
    #[test]
    fn envelope_with_auditor_size_is_constant() {
        let (secret, nullifier) = fresh_secrets();
        let auditor_sk = AuditorSecretKey::random().unwrap();
        let auditor_pk = auditor_sk.public_key();
        let a = MemoEnvelope::encrypt_for_recipient_and_auditor(
            b"x",
            &secret,
            &nullifier,
            &auditor_pk,
        )
        .unwrap()
        .to_bytes();
        let b = MemoEnvelope::encrypt_for_recipient_and_auditor(
            &vec![b'y'; MAX_PLAINTEXT_LEN],
            &secret,
            &nullifier,
            &auditor_pk,
        )
        .unwrap()
        .to_bytes();
        assert_eq!(a.len(), b.len());
    }

    /// The padded blob uses random bytes, not zeros, so two
    /// successive encryptions of the same plaintext produce different
    /// padded buffers. The Aes-GCM nonce already provides this property
    /// for the ciphertext, but the underlying padding randomness is a
    /// belt-and-braces extra layer.
    #[test]
    fn pad_produces_random_filler() {
        let a = pad_plaintext_for_envelope(b"hello").unwrap();
        let b = pad_plaintext_for_envelope(b"hello").unwrap();
        assert_eq!(&a[..2 + 5], &b[..2 + 5]);
        // Randomness collision after byte 7 is astronomically
        // unlikely (256-7 = 249 bytes of OS entropy).
        assert_ne!(a[2 + 5..], b[2 + 5..]);
    }

    /// pad → unpad recovers the original plaintext byte-for-byte for
    /// every length we care about.
    #[test]
    fn pad_unpad_roundtrip() {
        for len in [0, 1, 2, 7, 32, 128, 256] {
            let pt: Vec<u8> = (0..len as u8).collect();
            let padded = pad_plaintext_for_envelope(&pt).unwrap();
            let recovered = unpad_envelope_plaintext(&padded).unwrap();
            assert_eq!(recovered, pt, "length {} did not roundtrip", len);
        }
    }

    /// Charset filter: ASCII Latin and Cyrillic are accepted, the
    /// frontier ranges around them are reachable.
    #[test]
    fn charset_accepts_latin_and_cyrillic() {
        validate_memo_charset("Hello world").unwrap();
        validate_memo_charset("Привет мир").unwrap();
        validate_memo_charset("Mixed: Ñ, ü, é, ą, ż, и Кирилл").unwrap();
        validate_memo_charset("Numbers and punctuation: 1234567890 !?,.;:").unwrap();
    }

    /// Charset filter: emoji and CJK are rejected with a clear error
    /// pointing at the offending codepoint.
    #[test]
    fn charset_rejects_emoji_and_cjk() {
        match validate_memo_charset("Hello 🎉").unwrap_err() {
            MemoError::UnsupportedMemoChar { codepoint } => {
                assert_eq!(codepoint, '🎉' as u32);
            }
            other => panic!("unexpected error: {:?}", other),
        }
        match validate_memo_charset("привет 中国").unwrap_err() {
            MemoError::UnsupportedMemoChar { codepoint } => {
                assert_eq!(codepoint, '中' as u32);
            }
            other => panic!("unexpected error: {:?}", other),
        }
    }

    /// Round-trip through the full envelope path including the
    /// padding-aware decrypt.
    #[test]
    fn envelope_padded_roundtrip_short_text() {
        let (secret, nullifier) = fresh_secrets();
        let envelope = MemoEnvelope::encrypt_for_recipient_only(
            "Аренда март".as_bytes(),
            &secret,
            &nullifier,
        )
        .unwrap();
        let recovered = envelope.decrypt_with_note(&secret, &nullifier).unwrap();
        assert_eq!(recovered, "Аренда март".as_bytes());
    }
}
