//! Render a Solidity Groth16 verifier from an arkworks `VerifyingKey<Bn254>`.
//!
//! The EVM counterpart of [`crate::solana_bytes`]. Where the Solana path
//! converts the verifying key into the byte layout `groth16-solana` consumes,
//! this module emits a self-contained `.sol` contract that verifies the same
//! proofs through the BN254 precompiles every EVM since Byzantium ships:
//!
//! - `0x06` — G1 addition (`ecAdd`)
//! - `0x07` — G1 scalar multiplication (`ecMul`)
//! - `0x08` — pairing check (`ecPairing`)
//!
//! Whitechain runs the Cancun EVM on the OP Stack, so all three are available
//! there unchanged. Nothing in the proving system moves: the same circuits,
//! the same ceremony output and the same browser prover feed this contract.
//!
//! # Coordinate order
//!
//! BN254 G2 coordinates are `Fq2` elements `c0 + c1*u`. Arkworks serializes
//! them as `[c0, c1]`; both `groth16-solana` and the EVM pairing precompile
//! expect `[c1, c0]`. The swap performed here is the same one
//! [`crate::solana_bytes::groth16_to_solana_bytes`] performs, which is why the
//! two backends verify byte-identical proofs.
//!
//! # Reproducibility
//!
//! The emitted contract carries the verifying key as decimal constants in the
//! order snarkjs uses for its own Solidity export, so the output can be
//! diffed against `snarkjs zkey export solidityverifier` run on the same
//! ceremony artifact. Anyone can regenerate it and compare.

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::VerifyingKey;

/// Decimal representation of a base-field element, as Solidity wants it.
fn fq_to_decimal(value: &Fq) -> String {
    let be_bytes = value.into_bigint().to_bytes_be();
    let mut decimal = String::new();
    let mut digits: Vec<u8> = Vec::new();

    // Convert big-endian bytes to a decimal string without pulling in a
    // bignum dependency: repeated division by 10 over the byte array.
    let mut work = be_bytes;
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

    for digit in digits.iter().rev() {
        decimal.push((b'0' + digit) as char);
    }
    decimal
}

/// `(x, y)` of a G1 point as decimal strings.
fn g1_decimal(point: &G1Affine) -> (String, String) {
    (fq_to_decimal(&point.x), fq_to_decimal(&point.y))
}

/// A G2 point as four decimal strings in EVM precompile order:
/// `x.c1, x.c0, y.c1, y.c0`.
fn g2_decimal(point: &G2Affine) -> (String, String, String, String) {
    let extract = |coordinate: &Fq2| (fq_to_decimal(&coordinate.c1), fq_to_decimal(&coordinate.c0));
    let (x1, x0) = extract(&point.x);
    let (y1, y0) = extract(&point.y);
    (x1, x0, y1, y0)
}

/// Render a standalone Solidity verifier for `vk`.
///
/// `header` is prepended verbatim — use it to record which ceremony state the
/// key came from, so a deployed contract can be traced back to its setup.
///
/// # Параметры
/// * `vk` — verifying key produced by the ceremony (or by the development
///   setup, in which case say so in `header`).
/// * `header` — comment block placed above the pragma.
///
/// # Возвращает
/// * `String` — the complete contract source, ready to write to a `.sol` file.
pub fn render_solidity_verifier(vk: &VerifyingKey<Bn254>, header: &str) -> String {
    render_solidity_verifier_named(vk, header, "Tidex6Verifier", "withdraw circuit")
}

/// Render the verifier under a chosen contract name.
///
/// One verifying key is one contract, and a pool that checks two circuits (the
/// hidden-amount pool: withdraw and join-split) needs two verifiers side by
/// side in the same Solidity project — so they cannot both be called
/// `Tidex6Verifier`. The assembly is identical whatever the name; only the
/// header, the contract identifier and the circuit named in the docs change.
///
/// # Параметры
/// * `vk` — the verifying key to embed.
/// * `header` — comment block placed above the pragma.
/// * `contract_name` — Solidity identifier of the emitted contract.
/// * `circuit_label` — human-readable circuit name for the `@title` line.
///
/// # Возвращает
/// * `String` — the complete contract source.
pub fn render_solidity_verifier_named(
    vk: &VerifyingKey<Bn254>,
    header: &str,
    contract_name: &str,
    circuit_label: &str,
) -> String {
    let public_inputs = vk.gamma_abc_g1.len() - 1;

    let (alpha_x, alpha_y) = g1_decimal(&vk.alpha_g1);
    let (beta_x1, beta_x0, beta_y1, beta_y0) = g2_decimal(&vk.beta_g2);
    let (gamma_x1, gamma_x0, gamma_y1, gamma_y0) = g2_decimal(&vk.gamma_g2);
    let (delta_x1, delta_x0, delta_y1, delta_y0) = g2_decimal(&vk.delta_g2);

    let mut ic_constants = String::new();
    for (index, point) in vk.gamma_abc_g1.iter().enumerate() {
        let (x, y) = g1_decimal(point);
        ic_constants.push_str(&format!(
            "    uint256 constant IC{index}x = {x};\n    uint256 constant IC{index}y = {y};\n\n"
        ));
    }

    let mut ic_accumulation = String::new();
    for index in 1..=public_inputs {
        // `_pVk` is the accumulator's address in memory, and `g1MulAccC`
        // reads both coordinates from it (`pR` and `pR + 32`). Passing an
        // offset instead of the address makes the precompile add whatever
        // happens to sit at that address — which is how this first failed.
        ic_accumulation.push_str(&format!(
            "                g1MulAccC(_pVk, IC{index}x, IC{index}y, calldataload(add(pubSignals, {offset})))\n",
            offset = (index - 1) * 32
        ));
    }

    format!(
        r#"{header}// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Groth16 verifier for the tidex6 {circuit_label}
/// @notice Verifies BN254 Groth16 proofs produced by the tidex6 browser
///         prover. Generated from the verifying key — do not edit by hand;
///         regenerate with the exporter named in the header.
/// @dev Public inputs: {public_inputs}
contract {contract_name} {{
    // Base field modulus.
    uint256 constant q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    // Scalar field modulus.
    uint256 constant r =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // Verifying key.
    uint256 constant alphax = {alpha_x};
    uint256 constant alphay = {alpha_y};

    uint256 constant betax1 = {beta_x1};
    uint256 constant betax2 = {beta_x0};
    uint256 constant betay1 = {beta_y1};
    uint256 constant betay2 = {beta_y0};

    uint256 constant gammax1 = {gamma_x1};
    uint256 constant gammax2 = {gamma_x0};
    uint256 constant gammay1 = {gamma_y1};
    uint256 constant gammay2 = {gamma_y0};

    uint256 constant deltax1 = {delta_x1};
    uint256 constant deltax2 = {delta_x0};
    uint256 constant deltay1 = {delta_y1};
    uint256 constant deltay2 = {delta_y0};

{ic_constants}    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant lastMem = 896;

    /// @notice Verify a Groth16 proof.
    /// @param _pA Proof element A.
    /// @param _pB Proof element B, in EVM pairing order.
    /// @param _pC Proof element C.
    /// @param _pubSignals The {public_inputs} public inputs.
    /// @return True when the proof is valid for these inputs.
    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[{public_inputs}] calldata _pubSignals
    ) public view returns (bool) {{
        assembly {{
            function checkField(v) {{
                if iszero(lt(v, r)) {{
                    mstore(0, 0)
                    return(0, 0x20)
                }}
            }}

            // G1 scalar multiply-accumulate into the memory at `pR`.
            function g1MulAccC(pR, x, y, s) {{
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)
                if iszero(success) {{
                    mstore(0, 0)
                    return(0, 0x20)
                }}

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)
                if iszero(success) {{
                    mstore(0, 0)
                    return(0, 0x20)
                }}
            }}

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {{
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Accumulate the public-input commitment.
{ic_accumulation}
                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(
                    add(_pPairing, 32),
                    mod(sub(q, calldataload(add(pA, 32))), q)
                )

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(_pVk))
                mstore(add(_pPairing, 416), mload(add(_pVk, 32)))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(
                    sub(gas(), 2000),
                    8,
                    _pPairing,
                    768,
                    _pPairing,
                    0x20
                )

                isOk := and(success, mload(_pPairing))
            }}

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, lastMem))

            // Reject public inputs outside the scalar field.
{field_checks}
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }}
    }}
}}
"#,
        field_checks = (0..public_inputs)
            .map(|index| format!(
                "            checkField(calldataload(add(_pubSignals, {})))\n",
                index * 32
            ))
            .collect::<String>(),
    )
}

/// Render the verifying key as a Rust module for the Stylus verifier
/// (`stylus/verifier/src/vk.rs`).
///
/// Same numbers, same order as [`render_solidity_verifier`]: G1 points as
/// `(x, y)`, G2 points in EVM pairing order `(x.c1, x.c0, y.c1, y.c0)`, and
/// `IC[0]` followed by one point per public input. Emitted as `uint!` literals
/// so the constants are checked at compile time and cost nothing at run time.
///
/// # Параметры
/// * `vk` — verifying key produced by the ceremony (or the development setup).
/// * `header` — comment block placed at the top; use it to say where the key
///   came from. `//` comments are rewritten to `//!` doc comments.
///
/// # Возвращает
/// * `String` — complete Rust source of the module.
pub fn render_stylus_vk(vk: &VerifyingKey<Bn254>, header: &str) -> String {
    let public_inputs = vk.gamma_abc_g1.len() - 1;
    let doc_header: String = header
        .lines()
        .map(|line| {
            if let Some(rest) = line.strip_prefix("//") {
                format!("//!{rest}\n")
            } else {
                format!("{line}\n")
            }
        })
        .collect();

    let (alpha_x, alpha_y) = g1_decimal(&vk.alpha_g1);
    let g2_block = |name: &str, point: &G2Affine| {
        let (x1, x0, y1, y0) = g2_decimal(point);
        format!(
            "/// {name}2 — G2 in EVM pairing order `(x.c1, x.c0, y.c1, y.c0)`.\n\
             pub const {upper}: [U256; 4] = [\n    uint!({x1}_U256),\n    uint!({x0}_U256),\n    uint!({y1}_U256),\n    uint!({y0}_U256),\n];\n",
            upper = name.to_uppercase()
        )
    };
    let ic_rows: String = vk
        .gamma_abc_g1
        .iter()
        .map(|point| {
            let (x, y) = g1_decimal(point);
            format!("    [uint!({x}_U256), uint!({y}_U256)],\n")
        })
        .collect();

    format!(
        "{doc_header}\n\
         use alloy_primitives::{{uint, U256}};\n\n\
         pub const NR_PUBLIC_INPUTS: usize = {public_inputs};\n\n\
         /// alpha1 — G1 `(x, y)`.\n\
         pub const ALPHA: [U256; 2] = [uint!({alpha_x}_U256), uint!({alpha_y}_U256)];\n\n\
         {beta}\n{gamma}\n{delta}\n\
         /// IC[0] and the per-input points: `vk_x = IC[0] + sum(IC[i+1] * input[i])`.\n\
         pub const IC: [[U256; 2]; {ic_len}] = [\n{ic_rows}];\n",
        beta = g2_block("beta", &vk.beta_g2),
        gamma = g2_block("gamma", &vk.gamma_g2),
        delta = g2_block("delta", &vk.delta_g2),
        ic_len = public_inputs + 1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_conversion_matches_known_values() {
        assert_eq!(fq_to_decimal(&Fq::from(0u64)), "0");
        assert_eq!(fq_to_decimal(&Fq::from(1u64)), "1");
        assert_eq!(fq_to_decimal(&Fq::from(1234567890u64)), "1234567890");
    }
}

/// Байты доказательства в том виде, в каком их принимает контракт на Solidity.
///
/// Отдельно от `solana_bytes`, и это не дублирование. Там точки проходят через
/// `CanonicalSerialize`, а arkworks укладывает в старшие биты последнего байта
/// свои признаки сериализации. Координата BN254 меньше модуля, старший байт у
/// неё не больше `0x30`, и эти биты в ней всегда свободны — поэтому признаки
/// туда и кладут. Solana такие байты принимает; прекомпайлы EVM — нет: слово со
/// взведённым битом для них не точка кривой, спаривание отказывает, и контракт
/// отвечает `InvalidProof`, ничего не объясняя.
///
/// Замер 25.08.2026: одиннадцать доказательств из двенадцати несут хотя бы одно
/// такое слово. То есть при отправке байтов Solana-раскладки в EVM отказывает
/// почти каждый платёж, и выглядит это как неверное доказательство, а не как
/// разница форматов.
///
/// Здесь координаты берутся числами — `into_bigint().to_bytes_be()`, — и места
/// для признаков в них нет вовсе. Тем же путём собирается фикстура, которую
/// принимает и `forge test`, и контракт в живой сети.
///
/// Точка `A` **не отрицается**: Solidity отрицает её сам, внутри спаривания.
/// В Solana-раскладке она приходит уже отрицённой, и отдать её как есть значит
/// отрицать дважды.
///
/// # Возвращает
/// * `[u8; 256]` — `a.x‖a.y‖b.x.c1‖b.x.c0‖b.y.c1‖b.y.c0‖c.x‖c.y`, big-endian.
pub fn groth16_proof_to_evm_bytes(proof: &ark_groth16::Proof<Bn254>) -> [u8; 256] {
    fn fq_be(value: &Fq) -> [u8; 32] {
        let bytes = value.into_bigint().to_bytes_be();
        let mut out = [0u8; 32];
        // `to_bytes_be` отдаёт ровно ширину числа; выравниваем справа, чтобы
        // короткое значение не уехало в старшие байты слова.
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    let mut out = [0u8; 256];
    out[0..32].copy_from_slice(&fq_be(&proof.a.x));
    out[32..64].copy_from_slice(&fq_be(&proof.a.y));
    out[64..96].copy_from_slice(&fq_be(&proof.b.x.c1));
    out[96..128].copy_from_slice(&fq_be(&proof.b.x.c0));
    out[128..160].copy_from_slice(&fq_be(&proof.b.y.c1));
    out[160..192].copy_from_slice(&fq_be(&proof.b.y.c0));
    out[192..224].copy_from_slice(&fq_be(&proof.c.x));
    out[224..256].copy_from_slice(&fq_be(&proof.c.y));
    out
}
