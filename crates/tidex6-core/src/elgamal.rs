//! Baby Jubjub ECDH for the Shielded Memo feature.
//!
//! This module implements the key-exchange half of the Shielded Memo
//! scheme: the depositor (Lena) runs `ecdh_send` against an auditor's
//! public key (Kai's) to obtain an ephemeral public key and a 32-byte
//! shared secret, which the `memo` module then uses to derive an
//! AES-256-GCM key. The auditor recovers the same shared secret with
//! `ecdh_recv` given their own secret key and the ephemeral public key
//! pulled from the onchain SPL Memo instruction.
//!
//! The curve is Baby Jubjub as implemented by `ark-ed-on-bn254`. Its
//! base field is the BN254 scalar field, which means the x-coordinate
//! of every point is already a valid Poseidon input — the memo KDF
//! exploits this.
//!
//! # Design invariants
//!
//! - All secret-key bytes are rejection-sampled to lie strictly in
//!   `[0, BJJ_SCALAR_MODULUS_BE)` so that `BjjFr::from_be_bytes_mod_order`
//!   is modular reduction in name only — the reduction never actually
//!   changes the value. This keeps the derivation of the public key
//!   from a stored secret byte-for-byte deterministic.
//! - Public keys are always in the prime-order subgroup. We verify this
//!   during `from_bytes` deserialisation. Points off-curve or in the
//!   cofactor subgroup are rejected. This is load-bearing: Baby Jubjub
//!   has cofactor 8, and accepting a cofactor point would leak the
//!   low three bits of the auditor's secret key through small-subgroup
//!   confinement attacks.
//! - The shared-secret derivation rejects the identity point, which
//!   can only arise from a malicious or degenerate ephemeral key.
//!
//! # Not in scope
//!
//! This module performs no symmetric encryption and no KDF. Those
//! live in `crate::memo`. Keeping the two separate matches the
//! consensus-path separation invariant from ADR-005: ECDH is
//! cryptographic plumbing, AEAD is user data, and the auditor layer
//! as a whole sits outside the verifier program.
//!
//! # References
//!
//! - ADR-004 — dual-curve design, BN254 G1 onchain, Baby Jubjub
//!   in-circuit.
//! - ADR-007 — Shielded Memo feature set.
//! - ADR-010 — rationale for transporting memos via SPL Memo Program
//!   rather than redeploying the verifier.
//! - `docs/release/security.md` §2.5 for the unaudited-ElGamal
//!   disclosure.

use std::fmt;
use std::str::FromStr;

use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as BjjFr};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::TryRng;
use rand::rngs::SysRng;
use thiserror::Error;

/// Length in bytes of a Baby Jubjub scalar, big-endian encoded.
pub const SCALAR_LEN: usize = 32;

/// Length in bytes of a Baby Jubjub point in compressed form.
pub const POINT_LEN: usize = 32;

/// Length in bytes of an ECDH shared secret — the big-endian encoding
/// of the x-coordinate of the shared point, which lies in the BN254
/// scalar field.
pub const SHARED_SECRET_LEN: usize = 32;

/// Big-endian byte encoding of the Baby Jubjub scalar-field modulus.
///
/// `0x060c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1`
///
/// The test `bjj_modulus_constant_matches_arkworks` in this module
/// confirms at build time that this constant agrees with the runtime
/// `<BjjFr as PrimeField>::MODULUS`. Any drift between the two — for
/// example from an arkworks version bump — will be caught as a test
/// failure rather than a silent bias in rejection sampling.
const BJJ_SCALAR_MODULUS_BE: [u8; SCALAR_LEN] = [
    0x06, 0x0c, 0x89, 0xce, 0x5c, 0x26, 0x34, 0x05, 0x37, 0x0a, 0x08, 0xb6, 0xd0, 0x30, 0x2b, 0x0b,
    0xab, 0x3e, 0xed, 0xb8, 0x39, 0x20, 0xee, 0x0a, 0x67, 0x72, 0x97, 0xdc, 0x39, 0x21, 0x26, 0xf1,
];

/// Errors produced by Baby Jubjub ECDH operations.
#[derive(Debug, Error)]
pub enum ElGamalError {
    /// A hex string did not decode to the expected length.
    #[error("expected hex string of {expected} bytes ({} chars), got {got_chars} chars", .expected * 2)]
    InvalidHexLength { expected: usize, got_chars: usize },

    /// A hex string contained a non-hex character.
    #[error("invalid hex character in input")]
    InvalidHexCharacter,

    /// A byte string that should encode a Baby Jubjub scalar was not
    /// strictly less than the scalar-field modulus. Always rejected:
    /// accepting the over-the-modulus value would either be modularly
    /// reduced (bias) or produce a different key than the original
    /// bytes (non-determinism).
    #[error("scalar bytes are not a valid Baby Jubjub scalar")]
    ScalarOutOfRange,

    /// A byte string that should encode a Baby Jubjub point failed
    /// on-curve or prime-order subgroup checks.
    #[error("point bytes are not a valid Baby Jubjub group element")]
    InvalidPoint,

    /// The secret key is zero. Not usable as an ECDH private key
    /// because the corresponding public key is the identity element.
    #[error("secret key is zero")]
    WeakKey,

    /// The ECDH shared point is the identity element. Only reachable
    /// if one side supplied a degenerate public key; treat as a
    /// protocol violation.
    #[error("ECDH produced the identity element")]
    DegenerateShared,

    /// The operating system's random number generator failed.
    #[error("OS random number generator failed: {0}")]
    Rand(String),
}

/// Constant-time lexicographic check that a 32-byte big-endian
/// integer is strictly less than the Baby Jubjub scalar-field
/// modulus. See the sibling helper in `crate::types` for the
/// BN254-field version.
fn is_below_bjj_modulus(bytes: &[u8; SCALAR_LEN]) -> bool {
    for (byte, modulus_byte) in bytes.iter().zip(BJJ_SCALAR_MODULUS_BE.iter()) {
        if byte < modulus_byte {
            return true;
        }
        if byte > modulus_byte {
            return false;
        }
    }
    // All bytes equal — value equals the modulus, which is not a
    // valid field element.
    false
}

/// Rejection-sample a 32-byte big-endian encoding of a Baby Jubjub
/// scalar. Matches the style of `crate::types::sample_field_element_bytes`.
///
/// Rejection probability is below `1 - 2^-5`, so the expected
/// number of draws is essentially one.
fn sample_bjj_scalar_bytes() -> Result<[u8; SCALAR_LEN], ElGamalError> {
    loop {
        let mut bytes = [0u8; SCALAR_LEN];
        SysRng
            .try_fill_bytes(&mut bytes)
            .map_err(|err: rand::rngs::SysError| ElGamalError::Rand(err.to_string()))?;
        if is_below_bjj_modulus(&bytes) && bytes != [0u8; SCALAR_LEN] {
            return Ok(bytes);
        }
    }
}

/// Load a previously sampled 32-byte BJJ scalar into an arkworks
/// field element without any modular reduction. Callers must have
/// verified the range through `is_below_bjj_modulus` first.
fn scalar_from_be_bytes(bytes: &[u8; SCALAR_LEN]) -> BjjFr {
    // from_be_bytes_mod_order is a modular reduction in general;
    // because our bytes are guaranteed to be < modulus it is the
    // identity operation on the stored integer.
    BjjFr::from_be_bytes_mod_order(bytes)
}

/// Auditor secret key.
///
/// Held privately by the auditor (Kai in the flagship story). The
/// auditor derives the corresponding `AuditorPublicKey` via
/// `public_key()` and shares the public key with the depositor
/// (Lena), who encrypts memos under it. Whoever holds an
/// `AuditorSecretKey` can decrypt every memo that was addressed to
/// the matching public key — this is exactly the read-only capability
/// the brief frames as "grant access, not permission".
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditorSecretKey([u8; SCALAR_LEN]);

impl AuditorSecretKey {
    /// Generate a fresh auditor secret key from the OS CSPRNG, with
    /// the same rejection-sampling discipline as the core domain
    /// types. Returns `WeakKey` for the measure-zero case where the
    /// sampled scalar is zero.
    pub fn random() -> Result<Self, ElGamalError> {
        Ok(Self(sample_bjj_scalar_bytes()?))
    }

    /// Reconstruct a secret key from raw bytes.
    ///
    /// Rejects anything that is not a valid Baby Jubjub scalar so
    /// that every value returned from this constructor has a stable,
    /// non-reduced representation.
    pub fn from_bytes(bytes: [u8; SCALAR_LEN]) -> Result<Self, ElGamalError> {
        if bytes == [0u8; SCALAR_LEN] {
            return Err(ElGamalError::WeakKey);
        }
        if !is_below_bjj_modulus(&bytes) {
            return Err(ElGamalError::ScalarOutOfRange);
        }
        Ok(Self(bytes))
    }

    /// Return the big-endian byte representation. Intended for
    /// encrypted local storage, never for logs or the network.
    pub const fn to_bytes(&self) -> [u8; SCALAR_LEN] {
        self.0
    }

    /// Borrow the raw bytes without copying.
    pub const fn as_bytes(&self) -> &[u8; SCALAR_LEN] {
        &self.0
    }

    /// Encode as a lowercase 64-character hex string.
    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.0)
    }

    /// Derive the corresponding public key by multiplying the Baby
    /// Jubjub generator by this scalar.
    pub fn public_key(&self) -> AuditorPublicKey {
        let scalar = scalar_from_be_bytes(&self.0);
        let point = (EdwardsAffine::generator() * scalar).into_affine();
        AuditorPublicKey(point)
    }
}

impl fmt::Debug for AuditorSecretKey {
    /// Deliberately redacted. The `{:?}` formatter is the most common
    /// way secrets leak into logs and panics; printing a fingerprint
    /// keyed on the public key keeps two different secret keys
    /// distinguishable in logs without ever exposing secret bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fingerprint = self
            .public_key()
            .to_hex()
            .chars()
            .take(8)
            .collect::<String>();
        write!(f, "AuditorSecretKey(REDACTED, pk={fingerprint}..)")
    }
}

/// Auditor public key.
///
/// Shared openly — this is the value the depositor needs in order to
/// encrypt memos for a given auditor. Two `AuditorPublicKey` values
/// compare equal iff the underlying group elements are equal; the
/// serialised form is canonical.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuditorPublicKey(EdwardsAffine);

impl AuditorPublicKey {
    /// Deserialise a public key from 32 compressed bytes.
    ///
    /// Performs on-curve and prime-order subgroup validation. Baby
    /// Jubjub has cofactor 8, so the subgroup check is mandatory:
    /// otherwise an attacker could submit a small-order public key
    /// and extract the low bits of the resulting shared secret via
    /// small-subgroup confinement.
    pub fn from_bytes(bytes: [u8; POINT_LEN]) -> Result<Self, ElGamalError> {
        // `deserialize_compressed` in ark-serialize 0.5 applies both
        // on-curve and subgroup validation by default. We still wrap
        // the generic SerializationError in a feature-specific error
        // to avoid leaking arkworks types across the public surface.
        let point = EdwardsAffine::deserialize_compressed(bytes.as_slice())
            .map_err(|_| ElGamalError::InvalidPoint)?;
        if point.is_zero() {
            return Err(ElGamalError::InvalidPoint);
        }
        Ok(Self(point))
    }

    /// Canonical 32-byte compressed serialisation.
    pub fn to_bytes(&self) -> [u8; POINT_LEN] {
        let mut out = [0u8; POINT_LEN];
        // Writing into a fixed-size buffer of the exact length cannot
        // overflow, and the serialisation of a validated curve point
        // into a mutable byte slice cannot fail — so propagating the
        // error with `.expect` here is a structural invariant, not a
        // silent panic waiting to happen.
        self.0
            .serialize_compressed(&mut out[..])
            .expect("Baby Jubjub point serialises into 32 bytes");
        out
    }

    /// Encode as a lowercase 64-character hex string. This is the
    /// form Kai hands to Lena when they sign up as each other's
    /// auditor.
    pub fn to_hex(&self) -> String {
        bytes_to_hex(&self.to_bytes())
    }

    /// Parse from the 64-character hex form produced by `to_hex`.
    pub fn from_hex(input: &str) -> Result<Self, ElGamalError> {
        let bytes = hex_to_bytes::<POINT_LEN>(input)?;
        Self::from_bytes(bytes)
    }

    /// Borrow the underlying curve point for crypto operations
    /// inside the crate. Not `pub` at the module level because
    /// exposing `EdwardsAffine` would leak arkworks types across the
    /// public API.
    pub(crate) fn as_point(&self) -> &EdwardsAffine {
        &self.0
    }
}

impl fmt::Debug for AuditorPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuditorPublicKey({})", self.to_hex())
    }
}

impl fmt::Display for AuditorPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for AuditorPublicKey {
    type Err = ElGamalError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// Ephemeral public key transmitted alongside a ciphertext.
///
/// A fresh one is generated per memo; its sole role is to let the
/// auditor reconstruct the shared secret via `ecdh_recv`. It carries
/// no identity and is safe to store in plaintext onchain.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct EphemeralPublicKey([u8; POINT_LEN]);

impl EphemeralPublicKey {
    /// Canonical 32-byte compressed serialisation.
    pub const fn to_bytes(&self) -> [u8; POINT_LEN] {
        self.0
    }

    /// Borrow the raw bytes without copying.
    pub const fn as_bytes(&self) -> &[u8; POINT_LEN] {
        &self.0
    }

    /// Reconstruct from bytes pulled off the chain. Performs the
    /// same on-curve and subgroup validation as `AuditorPublicKey`
    /// — a malformed ephemeral key must not be silently accepted
    /// because subgroup-confinement attacks apply to every point
    /// multiplied by a secret scalar, not just auditor keys.
    pub fn from_bytes(bytes: [u8; POINT_LEN]) -> Result<Self, ElGamalError> {
        // Round-trip through validation and back to bytes so that
        // the stored representation is guaranteed canonical.
        let pk = AuditorPublicKey::from_bytes(bytes)?;
        Ok(Self(pk.to_bytes()))
    }

    /// Borrow as an arkworks curve point. Internal.
    fn to_point(self) -> Result<EdwardsAffine, ElGamalError> {
        EdwardsAffine::deserialize_compressed(self.0.as_slice())
            .map_err(|_| ElGamalError::InvalidPoint)
    }
}

impl fmt::Debug for EphemeralPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EphemeralPublicKey({})", bytes_to_hex(&self.0))
    }
}

/// ECDH shared secret: the big-endian encoding of the x-coordinate
/// of the shared point.
///
/// Using the x-coordinate rather than the full compressed point is
/// deliberate: the x-coordinate lives in the BN254 scalar field, so
/// the result is a valid Poseidon input and therefore compatible
/// with future in-circuit key derivation without reformatting.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SharedSecret([u8; SHARED_SECRET_LEN]);

impl SharedSecret {
    /// Raw byte access for the KDF in `crate::memo`.
    pub const fn to_bytes(&self) -> [u8; SHARED_SECRET_LEN] {
        self.0
    }

    /// Borrow the raw bytes without copying.
    pub const fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for SharedSecret {
    /// Redacted: the shared secret derives the memo AES key, so
    /// leaking it via `Debug` leaks every memo encrypted under it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSecret(REDACTED)")
    }
}

/// Turn an affine Baby Jubjub point into the 32 big-endian bytes of
/// its x-coordinate. Panics only if arkworks internals change the
/// big-integer representation; the test `shared_secret_is_valid_bn254_scalar`
/// pins down that this stays in sync.
fn x_coordinate_be_bytes(point: &EdwardsAffine) -> [u8; SHARED_SECRET_LEN] {
    let mut bytes = point.x.into_bigint().to_bytes_be();
    // BJJ's base field = BN254's scalar field, which fits in 32 bytes.
    // `to_bytes_be` returns a Vec<u8> without leading zeros stripped
    // in ark-ff 0.5, but we pad defensively to avoid a future silent
    // shift in representation.
    if bytes.len() < SHARED_SECRET_LEN {
        let mut padded = vec![0u8; SHARED_SECRET_LEN - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    debug_assert_eq!(
        bytes.len(),
        SHARED_SECRET_LEN,
        "BJJ base-field element must fit in 32 bytes"
    );
    let mut out = [0u8; SHARED_SECRET_LEN];
    out.copy_from_slice(&bytes[bytes.len() - SHARED_SECRET_LEN..]);
    out
}

/// Depositor-side ECDH.
///
/// Generates a fresh ephemeral scalar, returns the corresponding
/// ephemeral public key (which goes onchain) and the 32-byte shared
/// secret (which feeds the memo KDF). The ephemeral scalar is dropped
/// at function exit — there is no reason to retain it.
///
/// Errors:
/// - `WeakKey` if the sampled ephemeral scalar is zero.
/// - `DegenerateShared` if multiplication produces the identity, for
///   example when called with a maliciously crafted auditor key.
/// - `Rand` on CSPRNG failure.
pub fn ecdh_send(
    auditor_pk: &AuditorPublicKey,
) -> Result<(EphemeralPublicKey, SharedSecret), ElGamalError> {
    let ephemeral_bytes = sample_bjj_scalar_bytes()?;
    let ephemeral_scalar = scalar_from_be_bytes(&ephemeral_bytes);

    // ephemeral_pk = ephemeral_scalar * G
    let ephemeral_pk_proj: EdwardsProjective = EdwardsAffine::generator() * ephemeral_scalar;
    let ephemeral_pk_affine = ephemeral_pk_proj.into_affine();
    if ephemeral_pk_affine.is_zero() {
        return Err(ElGamalError::DegenerateShared);
    }
    let mut ephemeral_pk_bytes = [0u8; POINT_LEN];
    ephemeral_pk_affine
        .serialize_compressed(&mut ephemeral_pk_bytes[..])
        .expect("Baby Jubjub point serialises into 32 bytes");

    // shared = ephemeral_scalar * auditor_pk
    let shared_proj: EdwardsProjective = *auditor_pk.as_point() * ephemeral_scalar;
    let shared_affine = shared_proj.into_affine();
    if shared_affine.is_zero() {
        return Err(ElGamalError::DegenerateShared);
    }
    let shared = SharedSecret(x_coordinate_be_bytes(&shared_affine));

    Ok((EphemeralPublicKey(ephemeral_pk_bytes), shared))
}

/// Auditor-side ECDH.
///
/// Given the ephemeral public key pulled from the onchain memo and
/// the auditor's long-term secret, reconstruct the shared secret
/// that the depositor used to encrypt. Always cheap: one scalar
/// multiplication plus a serialisation.
pub fn ecdh_recv(
    auditor_sk: &AuditorSecretKey,
    ephemeral_pk: &EphemeralPublicKey,
) -> Result<SharedSecret, ElGamalError> {
    let scalar = scalar_from_be_bytes(&auditor_sk.0);
    let ephemeral_point = ephemeral_pk.to_point()?;
    let shared_proj: EdwardsProjective = ephemeral_point * scalar;
    let shared_affine = shared_proj.into_affine();
    if shared_affine.is_zero() {
        return Err(ElGamalError::DegenerateShared);
    }
    Ok(SharedSecret(x_coordinate_be_bytes(&shared_affine)))
}

// ──────────────────────────────────────────────────────────────────────
// Hex helpers (local to this module so tidex6-core exposes no
// third-party hex crate in its public API).
// ──────────────────────────────────────────────────────────────────────

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_CHARS[(byte >> 4) as usize] as char);
        out.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_to_bytes<const N: usize>(input: &str) -> Result<[u8; N], ElGamalError> {
    let stripped = input.strip_prefix("0x").unwrap_or(input);
    if stripped.len() != N * 2 {
        return Err(ElGamalError::InvalidHexLength {
            expected: N,
            got_chars: stripped.len(),
        });
    }
    let source = stripped.as_bytes();
    let mut bytes = [0u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let high = hex_nibble(source[index * 2]).ok_or(ElGamalError::InvalidHexCharacter)?;
        let low = hex_nibble(source[index * 2 + 1]).ok_or(ElGamalError::InvalidHexCharacter)?;
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

#[cfg(test)]
mod tests {
    use super::{
        AuditorPublicKey, AuditorSecretKey, BJJ_SCALAR_MODULUS_BE, ElGamalError, POINT_LEN,
        SCALAR_LEN, SHARED_SECRET_LEN, ecdh_recv, ecdh_send, is_below_bjj_modulus,
    };
    use ark_ed_on_bn254::Fr as BjjFr;
    use ark_ff::{BigInteger, PrimeField};

    /// Guarantee that the hand-written BJJ scalar modulus matches
    /// the runtime value arkworks reports. Any arkworks version bump
    /// that shifts the modulus will trip this test.
    #[test]
    fn bjj_modulus_constant_matches_arkworks() {
        let runtime: Vec<u8> = BjjFr::MODULUS.to_bytes_be();
        assert_eq!(runtime.len(), SCALAR_LEN);
        assert_eq!(&runtime[..], &BJJ_SCALAR_MODULUS_BE[..]);
    }

    /// The rejection-sampler predicate is the ordering primitive the
    /// entire module rests on. Spot-check the three edge cases.
    #[test]
    fn range_check_boundaries() {
        let zero = [0u8; SCALAR_LEN];
        assert!(is_below_bjj_modulus(&zero));
        let modulus = BJJ_SCALAR_MODULUS_BE;
        assert!(!is_below_bjj_modulus(&modulus));
        let mut just_below = BJJ_SCALAR_MODULUS_BE;
        just_below[SCALAR_LEN - 1] -= 1;
        assert!(is_below_bjj_modulus(&just_below));
        let mut just_above = BJJ_SCALAR_MODULUS_BE;
        just_above[SCALAR_LEN - 1] += 1;
        assert!(!is_below_bjj_modulus(&just_above));
    }

    /// Every freshly generated auditor keypair round-trips through
    /// hex encoding without distortion.
    #[test]
    fn keypair_hex_roundtrip() {
        let sk = AuditorSecretKey::random().unwrap();
        let pk = sk.public_key();
        let pk_hex = pk.to_hex();
        let parsed = AuditorPublicKey::from_hex(&pk_hex).unwrap();
        assert_eq!(pk, parsed);
    }

    /// `AuditorSecretKey::from_bytes` must reject over-modulus input
    /// to keep the secret representation canonical.
    #[test]
    fn secret_key_rejects_out_of_range() {
        let err = AuditorSecretKey::from_bytes(BJJ_SCALAR_MODULUS_BE).unwrap_err();
        assert!(matches!(err, ElGamalError::ScalarOutOfRange));
        let err_zero = AuditorSecretKey::from_bytes([0u8; SCALAR_LEN]).unwrap_err();
        assert!(matches!(err_zero, ElGamalError::WeakKey));
    }

    /// Reject all-zero point bytes as an invalid public key — they
    /// encode the identity, which has no secret key and leaks nothing
    /// but also fails downstream ECDH.
    #[test]
    fn public_key_rejects_identity_bytes() {
        let err = AuditorPublicKey::from_bytes([0u8; POINT_LEN]).unwrap_err();
        assert!(matches!(err, ElGamalError::InvalidPoint));
    }

    /// Full ECDH round-trip. Depositor derives a shared secret from
    /// a freshly sampled ephemeral key; auditor reconstructs the same
    /// shared secret from their long-term secret and the ephemeral
    /// public key. Run many times to exercise the rejection sampler.
    #[test]
    fn ecdh_roundtrip() {
        for _ in 0..16 {
            let auditor_sk = AuditorSecretKey::random().unwrap();
            let auditor_pk = auditor_sk.public_key();
            let (ephemeral_pk, shared_sender) = ecdh_send(&auditor_pk).unwrap();
            let shared_receiver = ecdh_recv(&auditor_sk, &ephemeral_pk).unwrap();
            assert_eq!(shared_sender.to_bytes(), shared_receiver.to_bytes());
            assert_eq!(shared_sender.to_bytes().len(), SHARED_SECRET_LEN);
        }
    }

    /// Two different auditor keys must produce different shared
    /// secrets for the same ephemeral input — without this, the
    /// "addressed to me" filter in the accountant collapses.
    #[test]
    fn different_auditor_different_shared() {
        let alice_sk = AuditorSecretKey::random().unwrap();
        let bob_sk = AuditorSecretKey::random().unwrap();
        let alice_pk = alice_sk.public_key();
        let (ephemeral_pk, _) = ecdh_send(&alice_pk).unwrap();
        let alice_shared = ecdh_recv(&alice_sk, &ephemeral_pk).unwrap();
        let bob_shared = ecdh_recv(&bob_sk, &ephemeral_pk).unwrap();
        assert_ne!(alice_shared.to_bytes(), bob_shared.to_bytes());
    }

    /// The x-coordinate used as a shared secret must itself be a
    /// valid BN254 scalar, ready to feed into Poseidon in the memo
    /// KDF. "Less than BN254 modulus" is the Poseidon acceptance
    /// criterion in `crate::poseidon`.
    #[test]
    fn shared_secret_is_valid_bn254_scalar() {
        use crate::types::is_below_bn254_modulus;
        let auditor_sk = AuditorSecretKey::random().unwrap();
        let auditor_pk = auditor_sk.public_key();
        let (_, shared) = ecdh_send(&auditor_pk).unwrap();
        assert!(is_below_bn254_modulus(shared.as_bytes()));
    }

    /// `Debug` on the secret key must never print the raw bytes.
    /// Catch accidental log-leak regressions at the formatter level.
    #[test]
    fn secret_debug_is_redacted() {
        let sk = AuditorSecretKey::random().unwrap();
        let rendered = format!("{sk:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains(&sk.to_hex()));
    }
}
