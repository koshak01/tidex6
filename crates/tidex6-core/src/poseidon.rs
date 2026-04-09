//! Offchain Poseidon hash wrapper.
//!
//! This module is a thin, opinionated wrapper around `light-poseidon`
//! configured with circom-compatible parameters. Using this module rather
//! than calling `light-poseidon` directly is the single way to hash field
//! elements in tidex6 offchain code.
//!
//! The wrapper guarantees two properties:
//!
//! 1. **Byte-for-byte equivalence with the onchain `solana-poseidon`
//!    syscall.** Both libraries use the same circom-compatible parameter
//!    set over the BN254 scalar field (x^5 S-box, 8 full rounds, partial
//!    rounds as in the standard specification). The equivalence is
//!    enforced by a test in `tests/poseidon_equivalence.rs` that validates
//!    against a canonical vector documented in both upstream crates.
//!
//! 2. **Circom compatibility only.** The wrapper always constructs the
//!    hasher via `Poseidon::<Fr>::new_circom(n)`. It never exposes the
//!    generic `Poseidon::new(params)` constructor or the
//!    `ark-crypto-primitives` sponge, because those use different round
//!    constants and produce incompatible output. See
//!    `docs/release/security.md` section 2.2 for why this matters.
//!
//! The two public entry points are `hash` for the general case and
//! `hash_pair` for the two-input case used to compute commitments
//! (`Poseidon(secret, nullifier)`, per ADR-001).

use ark_bn254::Fr;
use light_poseidon::{Poseidon, PoseidonBytesHasher, PoseidonError as LightPoseidonError};
use thiserror::Error;

/// Length of a Poseidon hash over the BN254 scalar field, in bytes.
pub const HASH_LEN: usize = 32;

/// Maximum number of field elements accepted as input in a single hash call.
///
/// This bound comes from the circom-compatible parameter set used by
/// `light-poseidon`, which supports widths 2 through 13 (corresponding
/// to 1 through 12 inputs plus one domain-tag slot).
pub const MAX_INPUTS: usize = 12;

/// Errors that can occur while computing a Poseidon hash.
#[derive(Debug, Error)]
pub enum PoseidonError {
    /// The underlying `light-poseidon` hasher returned an error.
    ///
    /// This happens when an input byte slice does not represent a valid
    /// BN254 scalar field element (for example, when the value is greater
    /// than or equal to the field modulus), or when the input length does
    /// not match the 32-byte field-element encoding.
    #[error("light-poseidon hasher failed: {0}")]
    Hasher(#[from] LightPoseidonError),

    /// The caller passed an unsupported number of inputs.
    ///
    /// Poseidon over BN254 with circom parameters supports between 1 and
    /// 12 inputs. Zero inputs and more than 12 inputs are rejected.
    #[error("unsupported input count: {0}; expected 1..=12")]
    UnsupportedInputCount(usize),
}

/// Compute the Poseidon hash of one or more 32-byte field elements.
///
/// Each input must be a 32-byte big-endian encoding of a valid BN254
/// scalar field element. Values greater than or equal to the field
/// modulus are rejected with `PoseidonError::Hasher`.
///
/// Returns the 32-byte big-endian encoding of the resulting field element.
///
/// # Errors
///
/// - `PoseidonError::UnsupportedInputCount` if `inputs` is empty or has
///   more than `MAX_INPUTS` elements.
/// - `PoseidonError::Hasher` if any input is not a valid field element.
pub fn hash(inputs: &[&[u8; HASH_LEN]]) -> Result<[u8; HASH_LEN], PoseidonError> {
    let count = inputs.len();
    if count == 0 || count > MAX_INPUTS {
        return Err(PoseidonError::UnsupportedInputCount(count));
    }

    let mut hasher = Poseidon::<Fr>::new_circom(count)?;

    // light-poseidon's hash_bytes_be takes `&[&[u8]]`, so we convert our
    // fixed-size references to byte-slice references without copying.
    let slices: [&[u8]; MAX_INPUTS] = [&[]; MAX_INPUTS];
    let mut slices = slices;
    for (target, source) in slices.iter_mut().zip(inputs.iter()) {
        *target = source.as_slice();
    }
    let output = hasher.hash_bytes_be(&slices[..count])?;
    Ok(output)
}

/// Compute `Poseidon(a, b)` — the two-input case used throughout tidex6.
///
/// This is the commitment hash from ADR-001:
/// `commitment = Poseidon(secret, nullifier)`. It is also the form used
/// inside the Merkle tree for internal-node hashing.
///
/// # Errors
///
/// Same conditions as `hash`: any input that is not a valid BN254 scalar
/// field element is rejected.
pub fn hash_pair(a: &[u8; HASH_LEN], b: &[u8; HASH_LEN]) -> Result<[u8; HASH_LEN], PoseidonError> {
    hash(&[a, b])
}
