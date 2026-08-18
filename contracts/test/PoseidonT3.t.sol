// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PoseidonT3} from "../src/PoseidonT3.sol";

/// @title Does the Solidity Poseidon agree with the Rust one?
/// @notice The Merkle tree only works if every implementation computes the
///         same parent hash. This asserts the generated Solidity library
///         reproduces a vector taken from `tidex6_core::poseidon::hash_pair`,
///         which is itself byte-identical to the in-circuit gadget and to the
///         `solana-poseidon` syscall the Solana pool calls.
///
///         Regenerate the library and the vector with:
///           cargo run --bin export_solidity_poseidon --release
contract PoseidonT3Test is Test {
    /// Poseidon(0, 1), as computed by the Rust implementation.
    uint256 internal constant HASH_0_1 =
        12583541437132735734108669866114103169564651237895298778035846191048104863326;

    uint256 internal constant F =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// The one test that matters: agree with Rust, or the pools cannot
    /// interoperate at all.
    function test_matchesRustVector() public pure {
        assertEq(
            PoseidonT3.hash(0, 1),
            HASH_0_1,
            "Solidity Poseidon disagrees with the Rust implementation"
        );
    }

    /// Order matters — a hash that ignored argument order would break the
    /// Merkle path, where left and right siblings are distinct positions.
    function test_isOrderSensitive() public pure {
        assertTrue(
            PoseidonT3.hash(0, 1) != PoseidonT3.hash(1, 0),
            "hash must not be symmetric in its arguments"
        );
    }

    /// Deterministic across calls.
    function test_isDeterministic() public pure {
        assertEq(PoseidonT3.hash(7, 9), PoseidonT3.hash(7, 9));
    }

    /// Non-field-elements are rejected rather than silently reduced: a silent
    /// reduction would hash something other than what the caller passed.
    function test_rejectsNonFieldElement() public {
        vm.expectRevert("PoseidonT3: left not a field element");
        this.hashExternal(F, 1);

        vm.expectRevert("PoseidonT3: right not a field element");
        this.hashExternal(1, F);
    }

    /// Wrapper so `vm.expectRevert` can catch a revert from a library call.
    function hashExternal(uint256 left, uint256 right) external pure returns (uint256) {
        return PoseidonT3.hash(left, right);
    }
}
