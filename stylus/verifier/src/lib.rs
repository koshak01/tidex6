//! Groth16 verifier for the tidex6 withdraw circuit (BN254), on Stylus.
//!
//! Mirrors `contracts/src/Tidex6Verifier.sol` step for step and answers to the
//! same ABI: `verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[5])`.
//! The elliptic-curve work goes to the EVM precompiles every Arbitrum chain
//! exposes — `0x06` add, `0x07` scalar multiply, `0x08` pairing — so the WASM
//! only marshals bytes and checks that the public inputs are field elements.
//!
//! Returns `false` instead of reverting on a malformed proof, exactly like the
//! Solidity version: the pool decides what to do with a `false`.

#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
extern crate alloc;

mod vk;

use alloc::vec::Vec;

use alloy_primitives::{Address, U256};
use stylus_sdk::call::RawCall;
use stylus_sdk::prelude::*;

use tidex6_stylus_common::field::{is_field_element, Q};

/// G1 addition precompile.
const EC_ADD: Address = Address::with_last_byte(0x06);
/// G1 scalar multiplication precompile.
const EC_MUL: Address = Address::with_last_byte(0x07);
/// Pairing check precompile.
const EC_PAIRING: Address = Address::with_last_byte(0x08);

/// The contract holds no state: the verifying key is code.
#[storage]
#[entrypoint]
pub struct Tidex6Verifier {}

/// Append a `U256` as a 32-byte big-endian word.
#[inline]
fn push_word(buf: &mut Vec<u8>, value: U256) {
    buf.extend_from_slice(&value.to_be_bytes::<32>());
}

/// Read a G1 point `(x, y)` out of a 64-byte precompile return.
fn read_g1(bytes: &[u8]) -> Option<[U256; 2]> {
    if bytes.len() < 64 {
        return None;
    }
    Some([
        U256::from_be_slice(&bytes[0..32]),
        U256::from_be_slice(&bytes[32..64]),
    ])
}

#[public]
impl Tidex6Verifier {
    /// Verify a Groth16 proof.
    ///
    /// `pb` is in EVM pairing order: `[[x.c1, x.c0], [y.c1, y.c0]]`.
    /// Returns `true` only when the pairing check passes and every public
    /// input is below the scalar field modulus.
    #[selector(name = "verifyProof")]
    pub fn verify_proof(
        &self,
        pa: [U256; 2],
        pb: [[U256; 2]; 2],
        pc: [U256; 2],
        pub_signals: [U256; vk::NR_PUBLIC_INPUTS],
    ) -> bool {
        if pub_signals.iter().any(|s| !is_field_element(*s)) {
            return false;
        }
        let Some(vk_x) = self.public_input_commitment(&pub_signals) else {
            return false;
        };
        self.pairing_ok(pa, pb, pc, vk_x)
    }
}

impl Tidex6Verifier {
    /// Static call to a precompile; `None` when the precompile rejects the input.
    fn precompile(&self, target: Address, input: &[u8]) -> Option<Vec<u8>> {
        // SAFETY: static call, no reentrancy into our (empty) storage.
        unsafe { RawCall::new_static(self.vm()).call(target, input).ok() }
    }

    /// `vk_x = IC[0] + sum(IC[i+1] * input[i])`, accumulated on G1.
    fn public_input_commitment(&self, inputs: &[U256; vk::NR_PUBLIC_INPUTS]) -> Option<[U256; 2]> {
        let mut acc = vk::IC[0];
        for (point, scalar) in vk::IC[1..].iter().zip(inputs.iter()) {
            let mut mul_in = Vec::with_capacity(96);
            push_word(&mut mul_in, point[0]);
            push_word(&mut mul_in, point[1]);
            push_word(&mut mul_in, *scalar);
            let product = read_g1(&self.precompile(EC_MUL, &mul_in)?)?;

            let mut add_in = Vec::with_capacity(128);
            push_word(&mut add_in, product[0]);
            push_word(&mut add_in, product[1]);
            push_word(&mut add_in, acc[0]);
            push_word(&mut add_in, acc[1]);
            acc = read_g1(&self.precompile(EC_ADD, &add_in)?)?;
        }
        Some(acc)
    }

    /// `e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1`.
    fn pairing_ok(&self, pa: [U256; 2], pb: [[U256; 2]; 2], pc: [U256; 2], vk_x: [U256; 2]) -> bool {
        let mut input = Vec::with_capacity(768);

        // -A: negate y in the base field. A y outside the field makes the
        // point invalid and the precompile fails, which is the right answer.
        push_word(&mut input, pa[0]);
        let neg_y = if pa[1].is_zero() { U256::ZERO } else { Q.wrapping_sub(pa[1]) };
        push_word(&mut input, neg_y);
        // B
        for coordinate in pb.iter().flatten() {
            push_word(&mut input, *coordinate);
        }
        // alpha1, beta2
        for w in vk::ALPHA { push_word(&mut input, w); }
        for w in vk::BETA { push_word(&mut input, w); }
        // vk_x, gamma2
        push_word(&mut input, vk_x[0]);
        push_word(&mut input, vk_x[1]);
        for w in vk::GAMMA { push_word(&mut input, w); }
        // C, delta2
        push_word(&mut input, pc[0]);
        push_word(&mut input, pc[1]);
        for w in vk::DELTA { push_word(&mut input, w); }

        match self.precompile(EC_PAIRING, &input) {
            Some(out) if out.len() >= 32 => out[31] == 1 && out[..31].iter().all(|b| *b == 0),
            _ => false,
        }
    }
}
