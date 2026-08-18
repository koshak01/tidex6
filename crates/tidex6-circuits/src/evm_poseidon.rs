//! Render a Solidity Poseidon-T3 library from the very constants
//! `light-poseidon` uses offchain.
//!
//! The Merkle tree only works if every party computes the same parent hash.
//! On Solana that is the `solana-poseidon` syscall; in the circuit it is
//! `poseidon_gadget`; offchain it is `tidex6_core::poseidon`. All three agree
//! because all three use the circom-compatible BN254 parameter set.
//!
//! An EVM pool needs a fourth implementation, in Solidity — and a Poseidon
//! that disagrees by one round constant produces a different root, which means
//! proofs that never verify and deposits that can never be withdrawn. So this
//! module does not transcribe constants from a reference implementation: it
//! reads them out of `light-poseidon` itself and prints them. The generated
//! library is correct by construction, and regenerating it after a dependency
//! bump shows any drift as a diff.
//!
//! Permutation order follows `light_poseidon::Poseidon::hash` exactly:
//! `full/2` full rounds, then `partial` rounds with the S-box on the first
//! element only, then `full/2` full rounds again — each round being
//! add-round-constants, S-box, MDS.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::parameters::bn254_x5::get_poseidon_parameters;

/// Decimal string of a scalar-field element.
fn fr_decimal(value: &Fr) -> String {
    let bytes = value.into_bigint().to_bytes_be();
    let mut work = bytes;
    let mut digits: Vec<u8> = Vec::new();

    while work.iter().any(|byte| *byte != 0) {
        let mut remainder = 0u16;
        for byte in work.iter_mut() {
            let current = (remainder << 8) | u16::from(*byte);
            *byte = (current / 10) as u8;
            remainder = current % 10;
        }
        digits.push(remainder as u8);
    }

    if digits.is_empty() {
        return "0".to_string();
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}

/// Render `PoseidonT3.sol` — a two-input Poseidon over BN254, matching
/// `tidex6_core::poseidon::hash_pair` byte for byte.
///
/// # Возвращает
/// * `String` — complete Solidity source for the library.
///
/// # Паникует
/// Если `light-poseidon` не отдаёт параметры для ширины 3 — это означало бы,
/// что зависимость сменила набор констант, и молча продолжать нельзя.
pub fn render_poseidon_t3() -> String {
    let params = get_poseidon_parameters::<Fr>(3).expect("bn254_x5 width-3 parameters");

    assert_eq!(params.width, 3, "PoseidonT3 requires width 3");
    assert_eq!(params.alpha, 5, "circom Poseidon uses the x^5 S-box");

    let full_rounds = params.full_rounds;
    let partial_rounds = params.partial_rounds;


    // Round constants, flattened as light-poseidon stores them: round-major,
    // `width` entries per round.
    let ark: Vec<String> = params.ark.iter().map(fr_decimal).collect();
    let expected_ark = (full_rounds + partial_rounds) * params.width;
    assert_eq!(
        ark.len(),
        expected_ark,
        "unexpected round-constant count: dependency changed its parameter set"
    );

    // Each round is its own `[a, b, c]` triple: the Solidity type is
    // `uint256[3][rounds]`, and a flat list of `width * rounds` values does
    // not implicitly convert to it.
    let ark_literal = ark
        .chunks(params.width)
        .map(|round| format!("            [{}]", round.join(", ")))
        .collect::<Vec<_>>()
        .join(",\n");

    let mds_literal = params
        .mds
        .iter()
        .map(|row| {
            let cells: Vec<String> = row.iter().map(fr_decimal).collect();
            format!("            [{}]", cells.join(", "))
        })
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Poseidon hash over BN254, two inputs (width 3)
/// @notice Generated from the exact constants `light-poseidon` uses offchain,
///         which are the circom-compatible BN254 parameters. Byte-identical to
///         `tidex6_core::poseidon::hash_pair`, to the in-circuit gadget, and to
///         the `solana-poseidon` syscall the Solana pool calls.
///
///         DO NOT EDIT BY HAND. Regenerate with:
///           cargo run --bin export_solidity_poseidon --release
///
/// @dev {full_rounds} full rounds, {partial_rounds} partial rounds, S-box x^5.
library PoseidonT3 {{
    /// BN254 scalar field modulus.
    uint256 internal constant F =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 internal constant FULL_ROUNDS = {full_rounds};
    uint256 internal constant PARTIAL_ROUNDS = {partial_rounds};

    /// Round constants, {rounds} rounds x 3 state elements.
    function roundConstants() internal pure returns (uint256[3][{rounds}] memory ark) {{
        ark = [
{ark_literal}
        ];
    }}

    /// MDS matrix.
    function mds() internal pure returns (uint256[3][3] memory matrix) {{
        matrix = [
{mds_literal}
        ];
    }}

    /// @notice Poseidon(left, right) — the Merkle parent hash.
    /// @dev Reverts when an input is not a field element: a silent reduction
    ///      would hash something other than what the caller passed, and the
    ///      resulting root would disagree with every other implementation.
    function hash(uint256 left, uint256 right) internal pure returns (uint256) {{
        require(left < F, "PoseidonT3: left not a field element");
        require(right < F, "PoseidonT3: right not a field element");

        uint256[3][{rounds}] memory ark = roundConstants();
        uint256[3][3] memory m = mds();

        // State starts with the domain tag (zero for the circom parameter set),
        // then the inputs.
        uint256[3] memory state;
        state[0] = 0;
        state[1] = left;
        state[2] = right;

        uint256 halfFull = FULL_ROUNDS / 2;

        for (uint256 round = 0; round < halfFull; round++) {{
            state = _addRoundConstants(state, ark[round]);
            state = _sboxFull(state);
            state = _mix(state, m);
        }}

        for (uint256 round = halfFull; round < halfFull + PARTIAL_ROUNDS; round++) {{
            state = _addRoundConstants(state, ark[round]);
            state[0] = _pow5(state[0]);
            state = _mix(state, m);
        }}

        for (uint256 round = halfFull + PARTIAL_ROUNDS; round < FULL_ROUNDS + PARTIAL_ROUNDS; round++) {{
            state = _addRoundConstants(state, ark[round]);
            state = _sboxFull(state);
            state = _mix(state, m);
        }}

        return state[0];
    }}

    function _addRoundConstants(uint256[3] memory state, uint256[3] memory ark)
        private
        pure
        returns (uint256[3] memory)
    {{
        state[0] = addmod(state[0], ark[0], F);
        state[1] = addmod(state[1], ark[1], F);
        state[2] = addmod(state[2], ark[2], F);
        return state;
    }}

    function _sboxFull(uint256[3] memory state) private pure returns (uint256[3] memory) {{
        state[0] = _pow5(state[0]);
        state[1] = _pow5(state[1]);
        state[2] = _pow5(state[2]);
        return state;
    }}

    function _pow5(uint256 value) private pure returns (uint256) {{
        uint256 squared = mulmod(value, value, F);
        uint256 quartic = mulmod(squared, squared, F);
        return mulmod(quartic, value, F);
    }}

    function _mix(uint256[3] memory state, uint256[3][3] memory m)
        private
        pure
        returns (uint256[3] memory)
    {{
        uint256[3] memory mixed;
        for (uint256 i = 0; i < 3; i++) {{
            uint256 accumulator = 0;
            for (uint256 j = 0; j < 3; j++) {{
                accumulator = addmod(accumulator, mulmod(m[i][j], state[j], F), F);
            }}
            mixed[i] = accumulator;
        }}
        return mixed;
    }}
}}
"#,
        rounds = full_rounds + partial_rounds,
    )
}
