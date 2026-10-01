// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import {TestUSDC} from "../src/TestUSDC.sol";
import {Tidex6TokenPubkeyVerifier} from "../src/Tidex6TokenPubkeyVerifier.sol";
import {Tidex6TokenTransferVerifier} from "../src/Tidex6TokenTransferVerifier.sol";
import {Tidex6TokenUnwrapVerifier} from "../src/Tidex6TokenUnwrapVerifier.sol";
import {Tidex6TokenDepositVerifier} from "../src/Tidex6TokenDepositVerifier.sol";
import {Tidex6TokenExitVerifier} from "../src/Tidex6TokenExitVerifier.sol";
import {Tidex6HiddenWithdrawVerifierV2} from "../src/Tidex6HiddenWithdrawVerifierV2.sol";
import {Tidex6HiddenTransferVerifierV2} from "../src/Tidex6HiddenTransferVerifierV2.sol";
import {IERC20, Tidex6ConfidentialToken} from "../src/Tidex6ConfidentialToken.sol";
import {
    IConfidentialTokenCustody,
    ITokenExitVerifier,
    Tidex6TokenPoolV2
} from "../src/Tidex6TokenPoolV2.sol";
import {IWithdrawVerifierV2, ITransferVerifierV2} from "../src/Tidex6HiddenPoolV2.sol";

/// @notice One full confidential-token round on a local chain (ADR-023):
///         deploy, register two keys, wrap, transfer, deposit into the pool,
///         take the note back onto a balance, unwrap — with the proofs that
///         `export_token_circle` built offline against the state each call
///         leaves behind. Every step's effect is checked before the next.
///
///         forge script script/TokenCircle.s.sol --rpc-url http://127.0.0.1:8547 --broadcast
///
/// @dev Alice is the devnode's prefunded key; Bob is derived here and funded
///      by Alice. Development verifying keys only.
contract TokenCircle is Script {
    uint256 internal constant ALICE_PK = 0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9a8e98c;

    string internal json;

    function run() external {
        json = vm.readFile("script/token_circle.json");
        uint256 bobPk = uint256(keccak256("tidex6 token circle: bob"));
        address alice = vm.addr(ALICE_PK);
        address bob = vm.addr(bobPk);
        uint64 wrapped = uint64(vm.parseJsonUint(json, ".wrapped"));

        // ── deploy ───────────────────────────────────────────────────
        vm.startBroadcast(ALICE_PK);
        TestUSDC usdc = new TestUSDC();
        Tidex6ConfidentialToken token = new Tidex6ConfidentialToken(
            IERC20(address(usdc)),
            new Tidex6TokenPubkeyVerifier(),
            new Tidex6TokenTransferVerifier(),
            new Tidex6TokenUnwrapVerifier(),
            new Tidex6TokenDepositVerifier()
        );
        Tidex6TokenPoolV2 pool = new Tidex6TokenPoolV2(
            IConfidentialTokenCustody(address(token)),
            IWithdrawVerifierV2(address(new Tidex6HiddenWithdrawVerifierV2())),
            ITransferVerifierV2(address(new Tidex6HiddenTransferVerifierV2())),
            ITokenExitVerifier(address(new Tidex6TokenExitVerifier())),
            vm.parseJsonUint(json, ".treasuryPk"),
            vm.parseJsonUint(json, ".feeFloor")
        );
        token.setPool(address(pool));
        (bool sent,) = bob.call{value: 1 ether}("");
        require(sent, "fund bob");
        usdc.mint(alice, wrapped);
        usdc.approve(address(token), wrapped);
        console.log("token", address(token));
        console.log("pool", address(pool));

        // ── 1. registration, 2. wrap ─────────────────────────────────
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _proof(".registerAlice");
        token.register(_key(".aliceKey"), a, b, c);
        token.wrap(wrapped);
        token.applyPending();
        vm.stopBroadcast();

        vm.startBroadcast(bobPk);
        (a, b, c) = _proof(".registerBob");
        token.register(_key(".bobKey"), a, b, c);
        vm.stopBroadcast();

        // ── 3. Alice pays Bob; 4. Alice funds Bob's pool note ────────
        vm.startBroadcast(ALICE_PK);
        (a, b, c) = _proof(".transfer");
        token.transfer(a, b, c, _input18(".transfer"), hex"");
        (a, b, c) = _proof(".deposit");
        token.depositToPool(a, b, c, _input14(".deposit"), hex"", hex"");
        vm.stopBroadcast();
        require(pool.currentRoot() == vm.parseJsonUint(json, ".poolRootAfterDeposit"), "pool root");
        require(pool.nextLeafIndex() == 2, "two leaves");

        // ── 5. Bob takes the note onto his balance, 6. both unwrap ───
        vm.startBroadcast(bobPk);
        token.applyPending();
        _exit(pool);
        token.applyPending();
        (a, b, c) = _proof(".unwrapBob");
        token.unwrap(a, b, c, _input7(".unwrapBob"));
        vm.stopBroadcast();

        vm.startBroadcast(ALICE_PK);
        (a, b, c) = _proof(".unwrapAlice");
        token.unwrap(a, b, c, _input7(".unwrapAlice"));
        vm.stopBroadcast();

        // ── what the chain shows at the end ──────────────────────────
        uint256 bobOut = vm.parseJsonUint(json, ".bobUnwraps");
        uint256 aliceOut = vm.parseJsonUint(json, ".aliceUnwraps");
        require(usdc.balanceOf(bob) == bobOut, "bob paid out");
        require(usdc.balanceOf(alice) == aliceOut, "alice paid out");
        require(usdc.balanceOf(address(token)) == wrapped - bobOut - aliceOut, "custody holds the fee note");
        console.log("bob", bobOut, "alice", aliceOut);
        console.log("custody", usdc.balanceOf(address(token)));
        console.log("token circle: OK");
    }

    function _exit(Tidex6TokenPoolV2 pool) private {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = _proof(".exit");
        uint256[] memory i = vm.parseJsonUintArray(json, ".exit.input");
        Tidex6TokenPoolV2.TokenCredit memory credit = Tidex6TokenPoolV2.TokenCredit(
            [i[2], i[3]], [i[4], i[5]], [i[6], i[7]]
        );
        pool.withdrawToToken(a, b, c, i[0], i[1], credit);
    }

    function _proof(string memory step)
        private
        view
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c)
    {
        uint256[] memory w = vm.parseJsonUintArray(json, string.concat(step, ".proof"));
        a = [w[0], w[1]];
        b = [[w[2], w[3]], [w[4], w[5]]];
        c = [w[6], w[7]];
    }

    function _key(string memory path) private view returns (uint256[2] memory key) {
        uint256[] memory k = vm.parseJsonUintArray(json, path);
        key = [k[0], k[1]];
    }

    function _input7(string memory step) private view returns (uint256[7] memory out) {
        uint256[] memory v = vm.parseJsonUintArray(json, string.concat(step, ".input"));
        for (uint256 i = 0; i < 7; ++i) out[i] = v[i];
    }

    function _input14(string memory step) private view returns (uint256[14] memory out) {
        uint256[] memory v = vm.parseJsonUintArray(json, string.concat(step, ".input"));
        for (uint256 i = 0; i < 14; ++i) out[i] = v[i];
    }

    function _input18(string memory step) private view returns (uint256[18] memory out) {
        uint256[] memory v = vm.parseJsonUintArray(json, string.concat(step, ".input"));
        for (uint256 i = 0; i < 18; ++i) out[i] = v[i];
    }
}
