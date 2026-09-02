//! Poseidon over BN254, two inputs (width 3), circom parameter set.
//!
//! Byte-identical to `tidex6_core::poseidon::hash_pair`, to the in-circuit
//! gadget, to the `solana-poseidon` syscall and to `contracts/src/PoseidonT3.sol`.
//! The constants in `poseidon_consts.rs` are generated from `light-poseidon`
//! by `export_solidity_poseidon`, stored in Montgomery form; this file replays
//! the permutation: `FULL/2` full rounds, `PARTIAL` rounds with the S-box on
//! the first element, `FULL/2` full rounds again — each round being
//! add-constants, S-box, MDS.

use alloy_primitives::U256;

use crate::field::{add_mod, from_mont, limbs_from_u256, mont_mul, to_mont, u256_from_limbs, Limbs, ZERO};
use crate::poseidon_consts::{ARK, FULL_ROUNDS, MDS, PARTIAL_ROUNDS, WIDTH};

/// x^5 in the scalar field (Montgomery form in, Montgomery form out).
#[inline]
fn pow5(x: &Limbs) -> Limbs {
    let x2 = mont_mul(x, x);
    let x4 = mont_mul(&x2, &x2);
    mont_mul(&x4, x)
}

/// Multiply the state by the MDS matrix.
#[inline]
fn mix(state: &[Limbs; WIDTH]) -> [Limbs; WIDTH] {
    let mut out = [ZERO; WIDTH];
    for (row, slot) in MDS.iter().zip(out.iter_mut()) {
        let mut acc = ZERO;
        for (cell, value) in row.iter().zip(state.iter()) {
            acc = add_mod(&acc, &mont_mul(cell, value));
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
    let left = limbs_from_u256(left)?;
    let right = limbs_from_u256(right)?;
    // Domain tag first (zero for the circom set), then the inputs.
    let mut state = [ZERO, to_mont(&left), to_mont(&right)];
    let half = FULL_ROUNDS / 2;
    let total = FULL_ROUNDS + PARTIAL_ROUNDS;

    for round in 0..total {
        let base = round * WIDTH;
        for (i, s) in state.iter_mut().enumerate() {
            *s = add_mod(s, &ARK[base + i]);
        }
        let full = round < half || round >= half + PARTIAL_ROUNDS;
        if full {
            for s in state.iter_mut() {
                *s = pow5(s);
            }
        } else {
            state[0] = pow5(&state[0]);
        }
        state = mix(&state);
    }
    Some(u256_from_limbs(from_mont(&state[0])))
}
