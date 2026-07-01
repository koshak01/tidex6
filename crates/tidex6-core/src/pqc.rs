//! Post-quantum encryption — ML-KEM-768 + ChaCha20-Poly1305.
//!
//! This is the quantum-resistant replacement for the Baby Jubjub ECDH
//! auditor path (`crate::elgamal`). Anything encrypted **for** a reader
//! (auditor, or a stealth recipient who scans the chain for their own
//! payments) is sealed under that reader's ML-KEM-768 public key, so
//! that even a future quantum computer cannot recover it — defending
//! against "harvest now, decrypt later".
//!
//! # The hybrid
//!
//! ML-KEM is a key-encapsulation mechanism, not a cipher: it agrees on
//! a shared secret using the recipient's public key. We then encrypt
//! the actual payload with ChaCha20-Poly1305 under that shared secret.
//! Only the holder of the ML-KEM secret key can decapsulate and recover
//! the shared secret, hence the plaintext.
//!
//! # Wire format
//!
//! ```text
//! [ ml_kem_ciphertext | nonce | aead_ciphertext ]
//!         1088            12        variable
//! ```
//!
//! # Sizes (NIST FIPS 203, ML-KEM-768)
//!
//! - public (encapsulation) key: 1184 bytes
//! - secret (decapsulation) key: 2400 bytes
//! - KEM ciphertext: 1088 bytes
//!
//! The envelope is ~1.2 KB and **incompressible** (encrypted bytes are
//! noise). That exceeds the 1232-byte Solana transaction limit, which
//! is why on-chain delivery needs a dedicated account written in
//! chunks — a new-verifier concern, tracked in the roadmap. Off-chain
//! delivery (envelope handed straight to the auditor/recipient) has no
//! size constraint and is what ships first.

use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ml_kem::array::Array;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use thiserror::Error;

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

/// ML-KEM-768 encapsulation (public) key length, bytes.
pub const ML_KEM_768_EK_LEN: usize = 1184;

/// ML-KEM-768 decapsulation (secret) key length, bytes.
pub const ML_KEM_768_DK_LEN: usize = 2400;

/// ML-KEM-768 ciphertext length, bytes. Fixed prefix of every envelope.
pub const ML_KEM_768_CT_LEN: usize = 1088;

/// ChaCha20-Poly1305 nonce length, bytes.
pub const NONCE_LEN: usize = 12;

/// Minimum legal envelope: KEM ciphertext + nonce (+ empty AEAD body).
pub const ENVELOPE_MIN_LEN: usize = ML_KEM_768_CT_LEN + NONCE_LEN;

/// Errors produced by the post-quantum envelope layer.
#[derive(Debug, Error)]
pub enum PqcError {
    /// Public-key byte length did not match ML-KEM-768.
    #[error("invalid ML-KEM-768 public key: got {got} bytes, expected {ML_KEM_768_EK_LEN}")]
    BadPublicKey { got: usize },

    /// Secret-key byte length did not match ML-KEM-768.
    #[error("invalid ML-KEM-768 secret key: got {got} bytes, expected {ML_KEM_768_DK_LEN}")]
    BadSecretKey { got: usize },

    /// Envelope shorter than the fixed KEM-ciphertext + nonce prefix.
    #[error("envelope too short: got {got} bytes, need at least {ENVELOPE_MIN_LEN}")]
    EnvelopeTooShort { got: usize },

    /// ML-KEM encapsulation failed (malformed public key).
    #[error("ML-KEM encapsulate failed")]
    Encapsulate,

    /// ML-KEM decapsulation failed (malformed ciphertext or key).
    #[error("ML-KEM decapsulate failed")]
    Decapsulate,

    /// ChaCha20-Poly1305 encryption reported an internal failure.
    #[error("ChaCha20-Poly1305 encrypt failed")]
    Encrypt,

    /// AEAD authentication failed — wrong key, or the envelope was not
    /// addressed to this secret. The "skip" signal for a scanner.
    #[error("ChaCha20-Poly1305 decrypt failed (wrong key or corrupt envelope)")]
    Decrypt,
}

/// ML-KEM-768 public (encapsulation) key. Publishable — encrypting
/// *for* this key never reveals the secret. This is the key an auditor
/// or stealth recipient hands out / publishes once.
#[derive(Clone, PartialEq, Eq)]
pub struct PqcPublicKey(Vec<u8>);

/// ML-KEM-768 secret (decapsulation) key. Held only by the reader who
/// recovers their own envelopes.
pub struct PqcSecretKey(Vec<u8>);

impl PqcPublicKey {
    /// Borrow the raw key bytes (1184 bytes).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Reconstruct from raw bytes, validating the length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_768_EK_LEN {
            return Err(PqcError::BadPublicKey { got: bytes.len() });
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl PqcSecretKey {
    /// Borrow the raw key bytes (2400 bytes).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Reconstruct from raw bytes, validating the length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() != ML_KEM_768_DK_LEN {
            return Err(PqcError::BadSecretKey { got: bytes.len() });
        }
        Ok(Self(bytes.to_vec()))
    }
}

impl std::fmt::Debug for PqcPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqcPublicKey").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PqcSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PqcSecretKey").finish_non_exhaustive()
    }
}

/// Generate a fresh ML-KEM-768 keypair from the OS CSPRNG.
///
/// Returns `(public, secret)`. The public key is published / handed to
/// senders; the secret stays with the reader and is the only thing that
/// can open envelopes sealed for the public key.
pub fn keygen() -> (PqcPublicKey, PqcSecretKey) {
    let (dk, ek) = MlKem768::generate(&mut OsRng);
    (
        PqcPublicKey(ek.as_bytes().to_vec()),
        PqcSecretKey(dk.as_bytes().to_vec()),
    )
}

/// Seal `plaintext` so that only the holder of the secret key matching
/// `recipient_pub` can recover it. Envelope = `kem_ct || nonce || aead_ct`.
///
/// A fresh KEM encapsulation and a fresh nonce are produced per call, so
/// two seals of the same plaintext under the same key differ.
pub fn seal(recipient_pub: &PqcPublicKey, plaintext: &[u8]) -> Result<Vec<u8>, PqcError> {
    let encoded =
        Array::try_from(recipient_pub.0.as_slice()).map_err(|_| PqcError::BadPublicKey {
            got: recipient_pub.0.len(),
        })?;
    let ek = Ek::from_bytes(&encoded);

    let (kem_ct, shared) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| PqcError::Encapsulate)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_slice()));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let aead_ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| PqcError::Encrypt)?;

    let mut out = Vec::with_capacity(kem_ct.len() + NONCE_LEN + aead_ct.len());
    out.extend_from_slice(kem_ct.as_slice());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&aead_ct);
    Ok(out)
}

/// Open an envelope produced by [`seal`] under `recipient_secret`.
///
/// Returns [`PqcError::Decrypt`] on an authentication-tag mismatch,
/// which is the "not addressed to me" signal a scanner uses to skip.
pub fn open(recipient_secret: &PqcSecretKey, envelope: &[u8]) -> Result<Vec<u8>, PqcError> {
    let encoded =
        Array::try_from(recipient_secret.0.as_slice()).map_err(|_| PqcError::BadSecretKey {
            got: recipient_secret.0.len(),
        })?;
    let dk = Dk::from_bytes(&encoded);

    if envelope.len() < ENVELOPE_MIN_LEN {
        return Err(PqcError::EnvelopeTooShort {
            got: envelope.len(),
        });
    }
    let kem_ct_bytes = &envelope[..ML_KEM_768_CT_LEN];
    let nonce_bytes = &envelope[ML_KEM_768_CT_LEN..ML_KEM_768_CT_LEN + NONCE_LEN];
    let aead_ct = &envelope[ML_KEM_768_CT_LEN + NONCE_LEN..];

    let kem_ct = Array::try_from(kem_ct_bytes).map_err(|_| PqcError::Decapsulate)?;
    let shared = dk.decapsulate(&kem_ct).map_err(|_| PqcError::Decapsulate)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(shared.as_slice()));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), aead_ct)
        .map_err(|_| PqcError::Decrypt)?;
    Ok(plaintext)
}
