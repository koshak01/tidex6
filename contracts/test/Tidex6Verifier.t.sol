// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Tidex6Verifier} from "../src/Tidex6Verifier.sol";

/// @title Does a real tidex6 proof verify on the EVM?
/// @notice The proof below was produced by the tidex6 arkworks prover for a
///         depth-20 withdraw circuit and is accepted by the arkworks verifier
///         offchain. This test asserts the Solidity verifier agrees — and that
///         it rejects the same proof once a public input is tampered with.
///
///         Regenerate both the contract and this vector with:
///           cargo run --bin export_solidity_verifier --release
///           cargo run --bin export_solidity_fixture  --release
contract Tidex6VerifierTest is Test {
    Tidex6Verifier internal verifier;

    uint256[2] internal pA = [
        15287433880459027552261932827020979231094889212359852054477654433641785078650,
        18235396623827226785610927084245921060504276583383911690541529076702371124548
    ];

    uint256[2][2] internal pB = [
        [
            10237973405797135824753935662185894344879425805841819230673210280204254625094,
            17698154475394060160448217351619742824382869650519963572133423514609379446791
        ],
        [
            21433430501573817527301864424126101301470292125552409831140779465938734409591,
            18209675138861534787102268961865402943212177091377578442379733636156485067025
        ]
    ];

    uint256[2] internal pC = [
        6069125796756155929347489569901620148941956298937894915196723443748306662767,
        20574723224923398393727685973119277803891024063555431190279180730205066440123
    ];

    uint256[5] internal publicInputs = [
        3532976981344519423482578911752138451329232525103423799578242888779035313020,
        14183151523391397544502662298281553877624780464072146348117366941878960199891,
        7719472615821079694904732333912527190217998977709370935963838933860875309329,
        8081474342524916534442555080520771649945043395396817525337876380178177999425,
        0
    ];

    function setUp() public {
        verifier = new Tidex6Verifier();
    }

    /// The whole point: a proof generated off-chain in Rust verifies on-chain
    /// through the BN254 precompiles, with no change to the proving system.
    function test_acceptsRealProof() public view {
        assertTrue(
            verifier.verifyProof(pA, pB, pC, publicInputs),
            "verifier rejected a valid tidex6 withdraw proof"
        );
    }

    /// A verifier that accepts everything is not a verifier. Flip the Merkle
    /// root and the proof must stop verifying.
    function test_rejectsTamperedRoot() public view {
        uint256[5] memory tampered = publicInputs;
        tampered[0] = tampered[0] + 1;
        assertFalse(
            verifier.verifyProof(pA, pB, pC, tampered),
            "verifier accepted a proof with a tampered merkle root"
        );
    }

    /// Same for the nullifier hash — the field that stops double spends.
    function test_rejectsTamperedNullifier() public view {
        uint256[5] memory tampered = publicInputs;
        tampered[1] = tampered[1] + 1;
        assertFalse(
            verifier.verifyProof(pA, pB, pC, tampered),
            "verifier accepted a proof with a tampered nullifier hash"
        );
    }

    /// And for the recipient — swapping it must invalidate the proof, which is
    /// what makes an unchecked recipient account safe in the first place.
    function test_rejectsTamperedRecipient() public view {
        uint256[5] memory tampered = publicInputs;
        tampered[2] = tampered[2] + 1;
        assertFalse(
            verifier.verifyProof(pA, pB, pC, tampered),
            "verifier accepted a proof with a tampered recipient"
        );
    }

    /// A garbage proof must not pass either.
    function test_rejectsGarbageProof() public view {
        uint256[2] memory badA = [uint256(1), uint256(2)];
        assertFalse(
            verifier.verifyProof(badA, pB, pC, publicInputs),
            "verifier accepted a garbage proof element"
        );
    }
}
