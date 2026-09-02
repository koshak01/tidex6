//! BN254 moduli, as the EVM precompiles and the circuit see them.

use alloy_primitives::{uint, U256};

/// Scalar field modulus `r`. Every public input, commitment, nullifier and
/// Merkle node must be below it.
pub const R: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

/// Base field modulus `q`. Coordinates of G1 points live here; negating a
/// point means `y -> q - y`.
pub const Q: U256 =
    uint!(21888242871839275222246405745257275088696311157297823662689037894645226208583_U256);

/// Is `value` a scalar-field element?
#[inline]
pub fn is_field_element(value: U256) -> bool {
    value < R
}
