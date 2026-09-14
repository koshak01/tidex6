//! Groth16 verification over the BN254 precompiles, shared by every verifier
//! contract in this workspace.
//!
//! A verifier contract is one verifying key behind one `verifyProof`. The
//! fixed-denomination pool needs one (five inputs), the hidden-amount pool two
//! (eight for withdraw, four for join-split). The pairing arithmetic is the
//! same in all of them; only the key differs. It lives here once, and each
//! contract crate is a `vk.rs` plus a few lines that hand the key and its
//! precompile access to [`verify`].
//!
//! No VM access here: the caller passes a closure that performs a static call
//! to a precompile address, so this module stays pure and testable.

use alloc::vec::Vec;

use alloy_primitives::{Address, U256};

use crate::field::{is_field_element, Q};

/// `ecAdd` — G1 addition.
pub const EC_ADD: Address = Address::with_last_byte(0x06);
/// `ecMul` — G1 scalar multiplication.
pub const EC_MUL: Address = Address::with_last_byte(0x07);
/// `ecPairing` — pairing check.
pub const EC_PAIRING: Address = Address::with_last_byte(0x08);

/// A verifying key by reference. G2 points are in EVM pairing order
/// `(x.c1, x.c0, y.c1, y.c0)`; `ic` holds `IC[0]` followed by one point per
/// public input.
pub struct VerifyingKey<'a> {
    pub alpha: &'a [U256; 2],
    pub beta: &'a [U256; 4],
    pub gamma: &'a [U256; 4],
    pub delta: &'a [U256; 4],
    pub ic: &'a [[U256; 2]],
}

/// Append a `U256` as a 32-byte big-endian word.
#[inline]
fn push_word(buf: &mut Vec<u8>, value: U256) {
    buf.extend_from_slice(&value.to_be_bytes::<32>());
}

/// Read a G1 point `(x, y)` from the first 64 bytes of precompile output.
fn read_g1(bytes: &[u8]) -> Option<[U256; 2]> {
    if bytes.len() < 64 {
        return None;
    }
    Some([
        U256::from_be_slice(&bytes[0..32]),
        U256::from_be_slice(&bytes[32..64]),
    ])
}

/// `vk_x = IC[0] + Σ IC[i+1] · input[i]`, one `ecMul` and one `ecAdd` per input.
fn public_input_commitment<F>(vk: &VerifyingKey<'_>, precompile: &F, inputs: &[U256]) -> Option<[U256; 2]>
where
    F: Fn(Address, &[u8]) -> Option<Vec<u8>>,
{
    let mut acc = vk.ic[0];
    for (point, scalar) in vk.ic[1..].iter().zip(inputs.iter()) {
        let mut mul_in = Vec::with_capacity(96);
        push_word(&mut mul_in, point[0]);
        push_word(&mut mul_in, point[1]);
        push_word(&mut mul_in, *scalar);
        let product = read_g1(&precompile(EC_MUL, &mul_in)?)?;

        let mut add_in = Vec::with_capacity(128);
        push_word(&mut add_in, product[0]);
        push_word(&mut add_in, product[1]);
        push_word(&mut add_in, acc[0]);
        push_word(&mut add_in, acc[1]);
        acc = read_g1(&precompile(EC_ADD, &add_in)?)?;
    }
    Some(acc)
}

/// `e(-A, B) · e(alpha, beta) · e(vk_x, gamma) · e(C, delta) == 1`.
fn pairing_ok<F>(vk: &VerifyingKey<'_>, precompile: &F, pa: [U256; 2], pb: [[U256; 2]; 2], pc: [U256; 2], vk_x: [U256; 2]) -> bool
where
    F: Fn(Address, &[u8]) -> Option<Vec<u8>>,
{
    let mut input = Vec::with_capacity(768);
    // -A
    push_word(&mut input, pa[0]);
    let neg_y = if pa[1].is_zero() { U256::ZERO } else { Q.wrapping_sub(pa[1]) };
    push_word(&mut input, neg_y);
    // B
    for coordinate in pb.iter().flatten() {
        push_word(&mut input, *coordinate);
    }
    // alpha1, beta2
    for w in vk.alpha {
        push_word(&mut input, *w);
    }
    for w in vk.beta {
        push_word(&mut input, *w);
    }
    // vk_x, gamma2
    push_word(&mut input, vk_x[0]);
    push_word(&mut input, vk_x[1]);
    for w in vk.gamma {
        push_word(&mut input, *w);
    }
    // C, delta2
    push_word(&mut input, pc[0]);
    push_word(&mut input, pc[1]);
    for w in vk.delta {
        push_word(&mut input, *w);
    }

    match precompile(EC_PAIRING, &input) {
        Some(out) if out.len() >= 32 => out[31] == 1 && out[..31].iter().all(|b| *b == 0),
        _ => false,
    }
}

/// Verify a Groth16 proof against `vk`.
///
/// 1. Every public input must be a scalar-field element, or the proof is
///    rejected before any precompile runs.
/// 2. The public-input commitment `vk_x` is accumulated through `ecMul`/`ecAdd`.
/// 3. The four-term pairing product is checked through `ecPairing`.
///
/// # Параметры
/// * `vk` — the verifying key; `vk.ic.len()` must equal `inputs.len() + 1`.
/// * `precompile` — performs a static call to a precompile and returns its
///   output, or `None` on failure.
/// * `pa`, `pb`, `pc` — the proof, `pb` in EVM pairing order.
/// * `inputs` — the public inputs, in the circuit's order.
///
/// # Возвращает
/// * `bool` — `true` only when the proof verifies; every failure is `false`.
pub fn verify<F>(vk: &VerifyingKey<'_>, precompile: F, pa: [U256; 2], pb: [[U256; 2]; 2], pc: [U256; 2], inputs: &[U256]) -> bool
where
    F: Fn(Address, &[u8]) -> Option<Vec<u8>>,
{
    if vk.ic.len() != inputs.len() + 1 {
        return false;
    }
    if inputs.iter().any(|s| !is_field_element(*s)) {
        return false;
    }
    let Some(vk_x) = public_input_commitment(vk, &precompile, inputs) else {
        return false;
    };
    pairing_ok(vk, &precompile, pa, pb, pc, vk_x)
}
