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
}
