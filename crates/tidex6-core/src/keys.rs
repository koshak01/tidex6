//! Key hierarchy for the tidex6 privacy framework.
//!
//! The MVP uses a simplified one-level viewing key derivation: a
//! `SpendingKey` can be turned into exactly one `ViewingKey` via a
//! Poseidon-based pseudo-random function. The full Sapling split
//! (`SpendingKey` → `FullViewingKey` → `IncomingViewingKey` +
//! `NullifierKey`) is deferred to v0.2. See ADR-007 for the rationale.
//!
//! A `SpendingKey` authorises spending deposits. A `ViewingKey`
//! authorises reading deposit history and decrypting auditor tags,
//! but cannot spend. Compromise of a viewing key is not recoverable
//! — old ciphertexts stay readable forever — but it cannot drain
//! funds. See `docs/release/security.md` section 2.7.

use std::fmt;
use std::str::FromStr;

use rand::TryRng;
use rand::rngs::SysRng;

use crate::poseidon;
use crate::types::{DOMAIN_VALUE_LEN, DomainError};

/// Domain separator mixed into the viewing-key derivation so the
/// result cannot be confused with any other Poseidon hash in the
/// protocol. The constant value is the ASCII bytes of
/// `"tidex6-viewing-key-v1"` right-aligned in a 32-byte big-endian
/// field element, with zero bytes padded on the left.
///
/// The left-padding matters: Poseidon over BN254 rejects any 32-byte
/// value that exceeds the scalar field modulus. Because the modulus
/// starts with `0x30...`, any tag whose first byte is larger than
/// `0x30` (e.g., the ASCII `'t'` at `0x74`) would be rejected. Zero
/// padding at the high end guarantees the encoded tag is a valid
/// field element.
const VIEWING_KEY_DOMAIN_TAG: [u8; DOMAIN_VALUE_LEN] = {
    let mut buffer = [0u8; DOMAIN_VALUE_LEN];
    let tag = b"tidex6-viewing-key-v1";
    let offset = DOMAIN_VALUE_LEN - tag.len();
    let mut index = 0;
    while index < tag.len() {
        buffer[offset + index] = tag[index];
        index += 1;
    }
    buffer
};

/// A spending key: the master secret of a tidex6 wallet.
///
/// Held exclusively offchain by the user. Any party that holds a
/// `SpendingKey` can spend every deposit that belongs to it. Never
/// transmit this type over the network, never log it, never serialise
/// it into anything that touches the chain.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpendingKey([u8; DOMAIN_VALUE_LEN]);

/// A viewing key: a read-only capability derived from a
/// `SpendingKey`.
///
/// Shareable with a trusted party (accountant, auditor, family
/// member). Grants the holder the ability to decrypt auditor tags
/// and reconstruct deposit history, but never the ability to spend
/// deposits. See `docs/release/THE_LEGEND.md` for the user-facing
/// framing.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ViewingKey([u8; DOMAIN_VALUE_LEN]);

impl SpendingKey {
    /// Wrap raw bytes into a `SpendingKey`. Mostly used for loading
    /// a previously generated key from disk.
    pub const fn from_bytes(bytes: [u8; DOMAIN_VALUE_LEN]) -> Self {
        Self(bytes)
    }

    /// Return the raw byte representation. Intended for secure
    /// local storage, not for logs or network transmission.
    pub const fn to_bytes(&self) -> [u8; DOMAIN_VALUE_LEN] {
        self.0
    }

    /// Borrow the raw bytes without copying.
    pub const fn as_bytes(&self) -> &[u8; DOMAIN_VALUE_LEN] {
        &self.0
    }

    /// Generate a fresh `SpendingKey` from the operating system's
    /// CSPRNG. This is the only correct way to create a new wallet.
    pub fn random() -> Result<Self, DomainError> {
        let mut bytes = [0u8; DOMAIN_VALUE_LEN];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|err: rand::rngs::SysError| DomainError::Rand(err.to_string()))?;
        Ok(Self(bytes))
    }

    /// Derive the unique `ViewingKey` that corresponds to this
    /// `SpendingKey`. Computed as
    /// `Poseidon(spending_key, VIEWING_KEY_DOMAIN_TAG)` so that the
    /// derivation is deterministic, injective per domain, and
    /// distinct from any other Poseidon use in the protocol.
    pub fn derive_viewing_key(&self) -> Result<ViewingKey, DomainError> {
        let bytes = poseidon::hash_pair(&self.0, &VIEWING_KEY_DOMAIN_TAG)?;
        Ok(ViewingKey(bytes))
    }
}

impl ViewingKey {
    /// Wrap raw bytes into a `ViewingKey`. Used when importing a
    /// viewing key received from a key holder.
    pub const fn from_bytes(bytes: [u8; DOMAIN_VALUE_LEN]) -> Self {
        Self(bytes)
    }

    /// Return the raw byte representation for export.
    pub const fn to_bytes(&self) -> [u8; DOMAIN_VALUE_LEN] {
        self.0
    }

    /// Borrow the raw bytes without copying.
    pub const fn as_bytes(&self) -> &[u8; DOMAIN_VALUE_LEN] {
        &self.0
    }

    /// Encode the viewing key as a lowercase hex string for transfer
    /// over text-based channels (file, clipboard, encrypted chat).
    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.0)
    }
}

impl fmt::Debug for SpendingKey {
    /// Deliberately redacts the contents. A `SpendingKey` must never
    /// be logged, and `{:?}` is the most common way secrets leak into
    /// logs. The Debug impl prints a fingerprint based on the public
    /// `ViewingKey` so two `SpendingKey`s can still be distinguished
    /// in logs without revealing the secret itself.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fingerprint = match self.derive_viewing_key() {
            Ok(vk) => vk.to_hex().chars().take(8).collect::<String>(),
            Err(_) => "derivation-failed".to_string(),
        };
        write!(f, "SpendingKey(REDACTED, fingerprint={fingerprint})")
    }
}

impl fmt::Debug for ViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ViewingKey({})", self.to_hex())
    }
}

impl fmt::Display for ViewingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for ViewingKey {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex_to_bytes(s)?;
        Ok(Self(bytes))
    }
}

fn bytes_to_hex(bytes: &[u8; DOMAIN_VALUE_LEN]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(DOMAIN_VALUE_LEN * 2);
    for byte in bytes {
        out.push(HEX_CHARS[(byte >> 4) as usize] as char);
        out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_to_bytes(input: &str) -> Result<[u8; DOMAIN_VALUE_LEN], DomainError> {
    let stripped = input.strip_prefix("0x").unwrap_or(input);
    if stripped.len() != DOMAIN_VALUE_LEN * 2 {
        return Err(DomainError::InvalidHexLength {
            got_chars: stripped.len(),
        });
    }
    let source = stripped.as_bytes();
    let mut bytes = [0u8; DOMAIN_VALUE_LEN];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex_nibble(source[index * 2]).ok_or(DomainError::InvalidHexCharacter)?;
        let low = hex_nibble(source[index * 2 + 1]).ok_or(DomainError::InvalidHexCharacter)?;
        *byte = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
