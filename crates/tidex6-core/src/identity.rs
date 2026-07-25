//! Deriving a tidex6 identity from a wallet signature (ADR-018 §3).
//!
//! # Why derive instead of generate
//!
//! The alternative is what the project did before: generate random keys, write
//! them to `identity.json`, and tell the user not to lose the file. That makes
//! a key file — something to back up, something to leak, something to lose
//! along with the money it controls, and something to carry between devices.
//!
//! Here the identity is a *function* of a wallet signature. Connect the wallet
//! on any machine, sign the same phrase, get the same keys. Nothing is stored,
//! so nothing can be stolen from storage and nothing has to be backed up.
//!
//! # Why it is deterministic
//!
//! Ed25519 signatures are deterministic by RFC 8032 — the nonce is derived from
//! the private key and the message, not from randomness. One phrase and one
//! wallet therefore always produce the same 64 bytes, on every device and in
//! every wallet implementation that follows the standard.
//!
//! # The derivation
//!
//! ```text
//! sig      = wallet.sign(IDENTITY_MESSAGE)          64 bytes, deterministic
//! spend    = rejection-sample over SHA-512(DOMAIN_SPEND ‖ sig ‖ counter)
//! mlkem    = keygen_from_seed(SHA-512(DOMAIN_MLKEM ‖ sig))
//! view     = Poseidon(spend, VIEWING_KEY_DOMAIN_TAG)   — as always
//! ```
//!
//! Each key gets its own domain tag, so knowing one tells you nothing about the
//! other: the spending key and the ML-KEM secret are independent outputs of the
//! same signature rather than transformations of one another.
//!
//! # What this inherits
//!
//! The identity is now only as safe as the wallet. A compromised wallet loses
//! both the funds and the privacy at once, where a separate key file could in
//! principle be compromised on its own. That is the price of having nothing to
//! store, and it is worth paying: in practice key files are lost far more often
//! than wallets are stolen. Rotation is possible by bumping the version in the
//! signed phrase.

use sha2::{Digest, Sha512};

use crate::keys::{SpendingKey, ViewingKey};
use crate::pqc::{self, PqcPublicKey, PqcSecretKey};
use crate::types::{DOMAIN_VALUE_LEN, DomainError, is_below_bn254_modulus};

/// The phrase the wallet signs. Versioned: bumping the suffix produces an
/// entirely different identity, which is how rotation works.
pub const IDENTITY_MESSAGE: &str = "tidex6 identity v1";

/// Ed25519 signature length — what a wallet's `signMessage` returns.
pub const SIGNATURE_LEN: usize = 64;

const DOMAIN_SPEND: &[u8] = b"tidex6/identity/v1/spend";
const DOMAIN_MLKEM: &[u8] = b"tidex6/identity/v1/mlkem";

/// A complete tidex6 identity: what to spend with, what to read with, and the
/// address to hand out.
pub struct DerivedIdentity {
    pub spending_key: SpendingKey,
    pub viewing_key: ViewingKey,
    pub mlkem_public: PqcPublicKey,
    pub mlkem_secret: PqcSecretKey,
}

/// Errors from deriving an identity.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    /// The signature was not 64 bytes — not an ed25519 signature.
    #[error("signature must be {SIGNATURE_LEN} bytes, got {got}")]
    BadSignatureLength { got: usize },

    /// Rejection sampling failed to find a valid field element. With a uniform
    /// hash this needs ~2^-2000 luck; if it happens, something is wrong with
    /// the input rather than with the odds.
    #[error("could not derive a valid field element from this signature")]
    Exhausted,

    /// Poseidon failed while deriving the viewing key.
    #[error(transparent)]
    Domain(#[from] DomainError),
}

/// Derive the full identity from a wallet signature over [`IDENTITY_MESSAGE`].
///
/// The signature must be over exactly that phrase: signing anything else yields
/// a different, unrelated identity — which is a feature for rotation and a
/// footgun otherwise, so callers should not invent their own message.
pub fn from_signature(signature: &[u8]) -> Result<DerivedIdentity, IdentityError> {
    if signature.len() != SIGNATURE_LEN {
        return Err(IdentityError::BadSignatureLength {
            got: signature.len(),
        });
    }

    let spending_key = SpendingKey::from_bytes(derive_field_element(signature)?);
    let viewing_key = spending_key.derive_viewing_key()?;

    let mut hasher = Sha512::new();
    hasher.update(DOMAIN_MLKEM);
    hasher.update(signature);
    let mlkem_seed: [u8; 64] = hasher.finalize().into();
    let (mlkem_public, mlkem_secret) = pqc::keygen_from_seed(&mlkem_seed);

    Ok(DerivedIdentity {
        spending_key,
        viewing_key,
        mlkem_public,
        mlkem_secret,
    })
}

/// Rejection-sample a BN254 scalar deterministically.
///
/// Same discipline as [`crate::types::sample_field_element_bytes`], but the
/// entropy comes from the signature instead of the OS: hash with a counter,
/// take the first 32 bytes, retry if they are not below the modulus. About one
/// candidate in ten is rejected, so the loop practically never runs twice — but
/// it must exist, or the derived key would be biased.
fn derive_field_element(signature: &[u8]) -> Result<[u8; DOMAIN_VALUE_LEN], IdentityError> {
    for counter in 0u8..64 {
        let mut hasher = Sha512::new();
        hasher.update(DOMAIN_SPEND);
        hasher.update(signature);
        hasher.update([counter]);
        let digest = hasher.finalize();

        let mut candidate = [0u8; DOMAIN_VALUE_LEN];
        candidate.copy_from_slice(&digest[..DOMAIN_VALUE_LEN]);

        if is_below_bn254_modulus(&candidate) {
            return Ok(candidate);
        }
    }
    Err(IdentityError::Exhausted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(byte: u8) -> [u8; SIGNATURE_LEN] {
        [byte; SIGNATURE_LEN]
    }

    #[test]
    fn same_signature_gives_same_identity() {
        let a = from_signature(&sig(7)).expect("derive");
        let b = from_signature(&sig(7)).expect("derive");

        assert_eq!(a.spending_key.as_bytes(), b.spending_key.as_bytes());
        assert_eq!(a.viewing_key.as_bytes(), b.viewing_key.as_bytes());
        assert_eq!(a.mlkem_public.as_bytes(), b.mlkem_public.as_bytes());
        assert_eq!(a.mlkem_secret.as_bytes(), b.mlkem_secret.as_bytes());
    }

    #[test]
    fn different_signatures_give_different_identities() {
        let a = from_signature(&sig(7)).expect("derive");
        let b = from_signature(&sig(8)).expect("derive");

        assert_ne!(a.spending_key.as_bytes(), b.spending_key.as_bytes());
        assert_ne!(a.mlkem_public.as_bytes(), b.mlkem_public.as_bytes());
    }

    #[test]
    fn spending_key_and_mlkem_seed_are_independent() {
        // The two keys must not be transformations of each other: a leaked
        // view key should say nothing about the spending key.
        let id = from_signature(&sig(3)).expect("derive");
        assert_ne!(
            &id.spending_key.as_bytes()[..],
            &id.mlkem_secret.as_bytes()[..DOMAIN_VALUE_LEN]
        );
    }

    #[test]
    fn wrong_signature_length_is_rejected() {
        assert!(matches!(
            from_signature(&[0u8; 32]),
            Err(IdentityError::BadSignatureLength { got: 32 })
        ));
    }

    #[test]
    fn derived_mlkem_keypair_actually_works() {
        let id = from_signature(&sig(42)).expect("derive");
        let sealed = pqc::seal(&id.mlkem_public, b"payment for february").expect("seal");
        let opened = pqc::open(&id.mlkem_secret, &sealed).expect("open");
        assert_eq!(opened, b"payment for february");
    }
}
