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
use ark_ff::{BigInteger, Field, PrimeField};
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

    // Rounds are emitted unrolled, with the constants as literals in the
    // code rather than an array built in memory on every call. Building a
    // 65x3 array cost ~250k gas per hash; a leaf insertion is twenty hashes,
    // and five million gas per deposit is not a product.
    let half = full_rounds / 2;
    let mut rounds_body = String::new();
    for round in 0..(full_rounds + partial_rounds) {
        let base = round * params.width;
        let (c0, c1, c2) = (&ark[base], &ark[base + 1], &ark[base + 2]);
        let full_sbox = round < half || round >= half + partial_rounds;

        rounds_body.push_str(&format!("\n        // round {round}\n"));
        rounds_body.push_str(&format!("        s0 = addmod(s0, {c0}, F);\n"));
        rounds_body.push_str(&format!("        s1 = addmod(s1, {c1}, F);\n"));
        rounds_body.push_str(&format!("        s2 = addmod(s2, {c2}, F);\n"));
        if full_sbox {
            rounds_body.push_str("        s0 = _pow5(s0);\n");
            rounds_body.push_str("        s1 = _pow5(s1);\n");
            rounds_body.push_str("        s2 = _pow5(s2);\n");
        } else {
            rounds_body.push_str("        s0 = _pow5(s0);\n");
        }
        rounds_body.push_str("        (s0, s1, s2) = _mix(s0, s1, s2);\n");
    }

    let mds_constants = {
        let mut out = String::new();
        for (i, row) in params.mds.iter().enumerate() {
            for (j, cell) in row.iter().enumerate() {
                out.push_str(&format!(
                    "    uint256 private constant M{i}{j} = {};\n",
                    fr_decimal(cell)
                ));
            }
        }
        out
    };

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
///      Rounds are unrolled and the constants live in the bytecode: building
///      them in memory on every call cost roughly 250k gas per hash, and a
///      leaf insertion needs twenty of them.
library PoseidonT3 {{
    /// BN254 scalar field modulus.
    uint256 internal constant F =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // MDS matrix.
{mds_constants}
    /// @notice Poseidon(left, right) — the Merkle parent hash.
    /// @dev Reverts when an input is not a field element: a silent reduction
    ///      would hash something other than what the caller passed, and the
    ///      resulting root would disagree with every other implementation.
    function hash(uint256 left, uint256 right) internal pure returns (uint256) {{
        require(left < F, "PoseidonT3: left not a field element");
        require(right < F, "PoseidonT3: right not a field element");

        // State starts with the domain tag (zero for the circom parameter
        // set), then the inputs.
        uint256 s0 = 0;
        uint256 s1 = left;
        uint256 s2 = right;
{rounds_body}
        return s0;
    }}

    /// x^5 in the scalar field.
    function _pow5(uint256 value) private pure returns (uint256) {{
        uint256 squared = mulmod(value, value, F);
        uint256 quartic = mulmod(squared, squared, F);
        return mulmod(quartic, value, F);
    }}

    /// Multiply the state by the MDS matrix.
    function _mix(uint256 s0, uint256 s1, uint256 s2)
        private
        pure
        returns (uint256, uint256, uint256)
    {{
        return (
            addmod(
                addmod(mulmod(M00, s0, F), mulmod(M01, s1, F), F),
                mulmod(M02, s2, F),
                F
            ),
            addmod(
                addmod(mulmod(M10, s0, F), mulmod(M11, s1, F), F),
                mulmod(M12, s2, F),
                F
            ),
            addmod(
                addmod(mulmod(M20, s0, F), mulmod(M21, s1, F), F),
                mulmod(M22, s2, F),
                F
            )
        );
    }}
}}
"#,
    )
}

/// Render the Poseidon-T3 constants as a Rust module for the Stylus contracts
/// (`stylus/common/src/poseidon_consts.rs`).
///
/// Same `light-poseidon` parameters as [`render_poseidon_t3`]; the Stylus side
/// replays the permutation in `stylus/common/src/poseidon.rs` on its own
/// Montgomery arithmetic, so the constants are emitted already in Montgomery
/// form (`c·2^256 mod p`) as little-endian 64-bit limbs, and the contract never
/// converts them at run time.
///
/// # Возвращает
/// * `String` — complete Rust source of the module.
pub fn render_stylus_poseidon_consts() -> String {
    let params = get_poseidon_parameters::<Fr>(3).expect("bn254_x5 width-3 parameters");
    assert_eq!(params.width, 3, "PoseidonT3 requires width 3");
    assert_eq!(params.alpha, 5, "circom Poseidon uses the x^5 S-box");

    // Montgomery form: multiply by R = 2^256 mod p. `Fr::from(2).pow(256)` is
    // exactly R mod p as a field element, so `c * r` is `c·R mod p`.
    let r_mod_p = Fr::from(2u64).pow([256u64]);
    let limbs = |c: &Fr| -> String {
        let bytes = (*c * r_mod_p).into_bigint().to_bytes_le();
        let mut out = [0u8; 32];
        out[..bytes.len()].copy_from_slice(&bytes);
        (0..4)
            .map(|i| {
                let mut w = [0u8; 8];
                w.copy_from_slice(&out[8 * i..8 * i + 8]);
                format!("0x{:016x}", u64::from_le_bytes(w))
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    let ark_rows: String = params
        .ark
        .iter()
        .map(|c| format!("    [{}],\n", limbs(c)))
        .collect();
    let mds_rows: String = params
        .mds
        .iter()
        .map(|row| {
            let cells: String = row
                .iter()
                .map(|c| format!("        [{}],\n", limbs(c)))
                .collect();
            format!("    [\n{cells}    ],\n")
        })
        .collect();

    format!(
        "//! Poseidon-T3 constants (circom BN254 set), width 3, S-box x^5.\n\
         //!\n\
         //! GENERATED — DO NOT EDIT BY HAND. Regenerate with\n\
         //! `cargo run --bin export_solidity_poseidon --release` (writes this file\n\
         //! next to `contracts/src/PoseidonT3.sol`, from the same `light-poseidon`\n\
         //! parameters, so the two can never drift apart).\n\
         //!\n\
         //! Constants are stored in Montgomery form (`c·2^256 mod p`) as little-endian\n\
         //! 64-bit limbs — the representation `field::mont_mul` works in — so the\n\
         //! permutation never converts them at run time.\n\n\
         use crate::field::Limbs;\n\n\
         pub const WIDTH: usize = 3;\n\
         pub const FULL_ROUNDS: usize = {full};\n\
         pub const PARTIAL_ROUNDS: usize = {partial};\n\n\
         /// Round constants, round-major, `WIDTH` entries per round.\n\
         pub const ARK: [Limbs; {ark_len}] = [\n{ark_rows}];\n\n\
         /// MDS matrix.\n\
         pub const MDS: [[Limbs; 3]; 3] = [\n{mds_rows}];\n",
        full = params.full_rounds,
        partial = params.partial_rounds,
        ark_len = params.ark.len(),
    )
}
