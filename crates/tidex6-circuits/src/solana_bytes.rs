//! Convert arkworks Groth16 proofs and verifying keys into the
//! byte layout that the `groth16-solana` crate consumes.
//!
//! The onchain `tidex6-verifier` program uses
//! `groth16_solana::groth16::Groth16Verifier`, which expects:
//!
//! - `proof_a: [u8; 64]` — a BN254 G1 point, uncompressed,
//!   big-endian, **already negated**.
//! - `proof_b: [u8; 128]` — a BN254 G2 point, uncompressed,
//!   big-endian.
//! - `proof_c: [u8; 64]` — a BN254 G1 point, uncompressed,
//!   big-endian.
//! - `vk_alpha_g1`, `vk_beta_g2`, `vk_gamme_g2`, `vk_delta_g2`
//!   — same encodings.
//! - `vk_ic` — a slice of `[u8; 64]` G1 points.
//!
//! arkworks internally uses little-endian encoding via
//! `ark-serialize`, so this module handles the endianness swap
//! for every G1/G2 point, plus the proof_a negation that the
//! groth16-solana verifier expects.

use std::ops::Neg;

use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalSerialize, Compress};
use thiserror::Error;

/// The concrete byte layouts an onchain verifier consumes.
pub struct Groth16SolanaBytes {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
    pub vk_alpha_g1: [u8; 64],
    pub vk_beta_g2: [u8; 128],
    pub vk_gamma_g2: [u8; 128],
    pub vk_delta_g2: [u8; 128],
    pub vk_ic: Vec<[u8; 64]>,
}

/// Errors produced while converting an arkworks proof / VK into
/// the groth16-solana byte layout.
#[derive(Debug, Error)]
pub enum ConvertError {
    /// Arkworks `ark-serialize` returned an error while writing a
    /// curve point.
    #[error("arkworks serialization failed: {0}")]
    Serialize(String),

    /// A fixed-size buffer expected a specific number of bytes and
    /// got a different count.
    #[error("unexpected serialized length: expected {expected}, got {got}")]
    UnexpectedLength { expected: usize, got: usize },
}

/// Convert an arkworks Groth16 proof and verifying key into the
/// byte layouts that the onchain `groth16-solana` verifier
/// consumes. Negates `proof_a` as the onchain verifier requires.
pub fn groth16_to_solana_bytes(
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> Result<Groth16SolanaBytes, ConvertError> {
    let proof_a = g1_to_be_negated(&proof.a)?;
    let proof_b = g2_to_be(&proof.b)?;
    let proof_c = g1_to_be(&proof.c)?;

    let vk_alpha_g1 = g1_to_be(&vk.alpha_g1)?;
    let vk_beta_g2 = g2_to_be(&vk.beta_g2)?;
    let vk_gamma_g2 = g2_to_be(&vk.gamma_g2)?;
    let vk_delta_g2 = g2_to_be(&vk.delta_g2)?;

    let mut vk_ic = Vec::with_capacity(vk.gamma_abc_g1.len());
    for point in &vk.gamma_abc_g1 {
        vk_ic.push(g1_to_be(point)?);
    }

    Ok(Groth16SolanaBytes {
        proof_a,
        proof_b,
        proof_c,
        vk_alpha_g1,
        vk_beta_g2,
        vk_gamma_g2,
        vk_delta_g2,
        vk_ic,
    })
}

/// Serialize a G1 point to 64 bytes in the uncompressed big-endian
/// layout groth16-solana consumes.
fn g1_to_be(point: &G1Affine) -> Result<[u8; 64], ConvertError> {
    let mut bytes_le = [0u8; 64];
    point
        .serialize_with_mode(&mut bytes_le[..], Compress::No)
        .map_err(|err| ConvertError::Serialize(format!("G1: {err}")))?;

    let mut bytes_be = [0u8; 64];
    // Each coordinate is 32 bytes; reverse each half independently.
    reverse_bytes_halves_64(&bytes_le, &mut bytes_be);
    Ok(bytes_be)
}

/// Negate a G1 point and serialize it into groth16-solana byte
/// layout. The groth16-solana verifier expects `proof_a` to be
/// negated so the pairing equation reduces to a product that
/// equals the identity.
fn g1_to_be_negated(point: &G1Affine) -> Result<[u8; 64], ConvertError> {
    let negated = point.into_group().neg().into_affine();
    g1_to_be(&negated)
}

/// Serialize a G2 point to 128 bytes in the uncompressed
/// big-endian layout groth16-solana consumes.
///
/// BN254 G2 has two `Fq2` coordinates `(x, y)` where each `Fq2` is
/// `c0 + c1 * u`. Arkworks' little-endian layout and
/// groth16-solana's big-endian layout differ in coordinate order
/// within each `Fq2`: arkworks serializes as `[c0_le, c1_le]`,
/// while groth16-solana expects `[c1_be, c0_be]`. This helper
/// handles both the endianness swap and the coordinate swap.
fn g2_to_be(point: &G2Affine) -> Result<[u8; 128], ConvertError> {
    let mut bytes_le = [0u8; 128];
    point
        .serialize_with_mode(&mut bytes_le[..], Compress::No)
        .map_err(|err| ConvertError::Serialize(format!("G2: {err}")))?;

    // Layout in bytes_le:
    //   [0..32]   = x.c0 LE
    //   [32..64]  = x.c1 LE
    //   [64..96]  = y.c0 LE
    //   [96..128] = y.c1 LE
    //
    // groth16-solana expects:
    //   [0..32]   = x.c1 BE
    //   [32..64]  = x.c0 BE
    //   [64..96]  = y.c1 BE
    //   [96..128] = y.c0 BE

    let mut bytes_be = [0u8; 128];
    reverse_32_into(&bytes_le[0..32], &mut bytes_be[32..64]);
    reverse_32_into(&bytes_le[32..64], &mut bytes_be[0..32]);
    reverse_32_into(&bytes_le[64..96], &mut bytes_be[96..128]);
    reverse_32_into(&bytes_le[96..128], &mut bytes_be[64..96]);
    Ok(bytes_be)
}

fn reverse_bytes_halves_64(source: &[u8; 64], destination: &mut [u8; 64]) {
    for half in 0..2 {
        let start = half * 32;
        for i in 0..32 {
            destination[start + i] = source[start + 31 - i];
        }
    }
}

fn reverse_32_into(source: &[u8], destination: &mut [u8]) {
    debug_assert_eq!(source.len(), 32);
    debug_assert_eq!(destination.len(), 32);
    for i in 0..32 {
        destination[i] = source[31 - i];
    }
}
