//! Domain types for the tidex6 privacy framework.
//!
//! Every value that is "32 bytes with a specific meaning" in the
//! protocol gets its own newtype here. This catches argument-order
//! mistakes at compile time — a function that expects a `Commitment`
//! cannot be called with a `Nullifier`, even though both wrap
//! `[u8; 32]` internally.
//!
//! See ADR-001 for the commitment scheme these types implement.

use std::fmt;
use std::str::FromStr;

use rand::TryRng;
use rand::rngs::SysRng;
use thiserror::Error;

use crate::poseidon::{self, PoseidonError};

/// Length in bytes of every domain value: one BN254 scalar field
/// element encoded big-endian.
pub const DOMAIN_VALUE_LEN: usize = 32;

/// Errors produced by domain type parsing and conversion.
#[derive(Debug, Error)]
pub enum DomainError {
    /// A hex string did not decode to the expected 32-byte length.
    #[error("expected hex string of {DOMAIN_VALUE_LEN} bytes ({} chars), got {got_chars} chars", DOMAIN_VALUE_LEN * 2)]
    InvalidHexLength { got_chars: usize },

    /// A hex string contained a non-hex character.
    #[error("invalid hex character in input")]
    InvalidHexCharacter,

    /// The OS random number generator failed.
    #[error("OS random number generator failed: {0}")]
    Rand(String),

    /// A Poseidon call during a derivation failed.
    #[error("Poseidon derivation failed: {0}")]
    Poseidon(#[from] PoseidonError),
}

/// Define a `[u8; 32]` newtype together with the standard trait set
/// every domain type needs: `Clone`, `Copy`, `PartialEq`, `Eq`,
/// `Hash`, `Debug`, `Display`, `FromStr`, plus `to_bytes`, `from_bytes`
/// and `zero` constructors.
macro_rules! define_domain_bytes {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; DOMAIN_VALUE_LEN]);

        impl $name {
            /// Wrap raw bytes into this domain type without any check.
            pub const fn from_bytes(bytes: [u8; DOMAIN_VALUE_LEN]) -> Self {
                Self(bytes)
            }

            /// Return the raw byte representation.
            pub const fn to_bytes(&self) -> [u8; DOMAIN_VALUE_LEN] {
                self.0
            }

            /// Borrow the raw bytes without copying.
            pub const fn as_bytes(&self) -> &[u8; DOMAIN_VALUE_LEN] {
                &self.0
            }

            /// The all-zero value. Useful for tests and as an
            /// unmistakable placeholder.
            pub const fn zero() -> Self {
                Self([0u8; DOMAIN_VALUE_LEN])
            }

            /// Encode the value as a lowercase hex string of 64
            /// characters. Does not allocate on the heap for the
            /// output buffer; only the final `String` allocation.
            pub fn to_hex(&self) -> String {
                const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
                let mut out = String::with_capacity(DOMAIN_VALUE_LEN * 2);
                for byte in self.0 {
                    out.push(HEX_CHARS[(byte >> 4) as usize] as char);
                    out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
                }
                out
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let stripped = s.strip_prefix("0x").unwrap_or(s);
                if stripped.len() != DOMAIN_VALUE_LEN * 2 {
                    return Err(DomainError::InvalidHexLength {
                        got_chars: stripped.len(),
                    });
                }
                let mut bytes = [0u8; DOMAIN_VALUE_LEN];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    let high =
                        hex_nibble(stripped.as_bytes()[index * 2]).ok_or(DomainError::InvalidHexCharacter)?;
                    let low =
                        hex_nibble(stripped.as_bytes()[index * 2 + 1]).ok_or(DomainError::InvalidHexCharacter)?;
                    *byte = (high << 4) | low;
                }
                Ok(Self(bytes))
            }
        }

        impl From<[u8; DOMAIN_VALUE_LEN]> for $name {
            fn from(bytes: [u8; DOMAIN_VALUE_LEN]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; DOMAIN_VALUE_LEN] {
            fn from(value: $name) -> [u8; DOMAIN_VALUE_LEN] {
                value.0
            }
        }
    };
}

define_domain_bytes! {
    /// A secret random value held by the depositor and never revealed
    /// onchain. Combined with the `Nullifier` to form a `Commitment`.
    Secret
}

define_domain_bytes! {
    /// A secret random value held by the depositor. Its hash becomes
    /// public at withdrawal time to prevent double-spending.
    Nullifier
}

define_domain_bytes! {
    /// The public representation of a deposit: `Poseidon(secret, nullifier)`.
    /// Commitments are the leaves of the shielded pool Merkle tree.
    /// See ADR-001.
    Commitment
}

define_domain_bytes! {
    /// The public hash of a `Nullifier`, revealed at withdrawal time
    /// and stored in a per-nullifier PDA to prevent a second
    /// withdrawal of the same deposit. See ADR-003.
    NullifierHash
}

define_domain_bytes! {
    /// The root of the shielded pool Merkle tree at some point in
    /// time. The onchain program stores a ring buffer of the most
    /// recent roots. See ADR-002.
    MerkleRoot
}

impl Secret {
    /// Generate a fresh `Secret` from the operating system's CSPRNG.
    /// Only used offchain — the onchain program never generates
    /// random secrets.
    pub fn random() -> Result<Self, DomainError> {
        let mut bytes = [0u8; DOMAIN_VALUE_LEN];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|err: rand::rngs::SysError| DomainError::Rand(err.to_string()))?;
        Ok(Self(bytes))
    }
}

impl Nullifier {
    /// Generate a fresh `Nullifier` from the operating system's CSPRNG.
    pub fn random() -> Result<Self, DomainError> {
        let mut bytes = [0u8; DOMAIN_VALUE_LEN];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|err: rand::rngs::SysError| DomainError::Rand(err.to_string()))?;
        Ok(Self(bytes))
    }

    /// Derive the public `NullifierHash` that identifies this
    /// `Nullifier` at withdrawal time. Computed as
    /// `Poseidon(nullifier)` so the hash is a single field element
    /// even though the nullifier is an arbitrary 32-byte secret.
    pub fn derive_hash(&self) -> Result<NullifierHash, DomainError> {
        let bytes = poseidon::hash(&[self.as_bytes()])?;
        Ok(NullifierHash(bytes))
    }
}

impl Commitment {
    /// Compute the commitment for a `(secret, nullifier)` pair per
    /// ADR-001: `commitment = Poseidon(secret, nullifier)`. This is
    /// the only supported way to construct a `Commitment` from its
    /// inputs in the MVP.
    pub fn derive(secret: &Secret, nullifier: &Nullifier) -> Result<Self, DomainError> {
        let bytes = poseidon::hash_pair(secret.as_bytes(), nullifier.as_bytes())?;
        Ok(Self(bytes))
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
