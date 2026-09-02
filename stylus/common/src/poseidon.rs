//! Poseidon over BN254, two inputs (width 3), circom parameter set.
//!
//! Byte-identical to `tidex6_core::poseidon::hash_pair`, to the in-circuit
//! gadget, to the `solana-poseidon` syscall and to `contracts/src/PoseidonT3.sol`.
//! The constants in `poseidon_consts.rs` are generated from `light-poseidon`
//! by `export_solidity_poseidon`; this file only replays the permutation:
//! `FULL/2` full rounds, `PARTIAL` rounds with the S-box on the first element,
//! `FULL/2` full rounds again — each round being add-constants, S-box, MDS.

use alloy_primitives::U256;

use crate::field::R;
use crate::poseidon_consts::{ARK, FULL_ROUNDS, MDS, PARTIAL_ROUNDS, WIDTH};

/// x^5 in the scalar field.
#[inline]
fn pow5(value: U256) -> U256 {
    let squared = value.mul_mod(value, R);
    let quartic = squared.mul_mod(squared, R);
    quartic.mul_mod(value, R)
}

/// Multiply the state by the MDS matrix.
#[inline]
fn mix(state: [U256; WIDTH]) -> [U256; WIDTH] {
    let mut out = [U256::ZERO; WIDTH];
    for (row, slot) in MDS.iter().zip(out.iter_mut()) {
        let mut acc = U256::ZERO;
        for (cell, value) in row.iter().zip(state.iter()) {
            acc = acc.add_mod(cell.mul_mod(*value, R), R);
        }
        *slot = acc;
    }
    out
}

/// Poseidon(left, right) — the Merkle parent hash.
///
/// Returns `None` when an input is not a field element: a silent reduction
/// would hash something other than what the caller passed, and the resulting
/// root would disagree with every other implementation.
pub fn hash_pair(left: U256, right: U256) -> Option<U256> {
    if left >= R || right >= R {
        return None;
    }
    // Domain tag first (zero for the circom set), then the inputs.
    let mut state = [U256::ZERO, left, right];
    let half = FULL_ROUNDS / 2;
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;

    for round in 0..total {
        let base = round * WIDTH;
        for (i, s) in state.iter_mut().enumerate() {
            *s = s.add_mod(ARK[base + i], R);
        }
        let full = round < half || round >= half + PARTIAL_ROUNDS;
        if full {
            for s in state.iter_mut() {
                *s = pow5(*s);
            }
        } else {
            state[0] = pow5(state[0]);
        }
        state = mix(state);
    }
    Some(state[0])
}
