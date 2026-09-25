// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Tidex6HiddenPoolV2, IERC20V2} from "../src/Tidex6HiddenPoolV2.sol";
import {Tidex6HiddenWithdrawVerifier} from "../src/Tidex6HiddenWithdrawVerifier.sol";
import {Tidex6HiddenTransferVerifier} from "../src/Tidex6HiddenTransferVerifier.sol";
import {PoseidonT3} from "../src/PoseidonT3.sol";
import {TestToken, MockVerifier} from "./Tidex6HiddenPool.t.sol";

/// The v2 pool's own logic (ADR-022): the leaf is bound to the amount paid in,
/// the refund path belongs to the funder after the window, and both spending
/// paths share one nullifier. The circuit side — that only the owner can build
/// a withdraw proof — is checked on the Rust side against real proofs.
contract Tidex6HiddenPoolV2Test is Test {
    Tidex6HiddenPoolV2 pool;
    TestToken token;
    MockVerifier verifier;

    address alice = address(0xA11CE);
    address mallory = address(0xBAD);
    address bob = address(0xB0B);

    uint256 constant OWNER_PK = 0x1234;
    uint256 constant RHO = 0x5678;
    uint256 constant AUX = 0;
    uint256 constant WINDOW = 1 days;

    function setUp() public {
        token = new TestToken();
        verifier = new MockVerifier();
        pool = new Tidex6HiddenPoolV2(
            IERC20V2(address(token)),
            Tidex6HiddenWithdrawVerifier(address(verifier)),
            Tidex6HiddenTransferVerifier(address(verifier))
        );
        for (uint256 i = 0; i < 2; i++) {
            address who = i == 0 ? alice : mallory;
            token.mint(who, 1_000_000_000);
            vm.prank(who);
            token.approve(address(pool), type(uint256).max);
        }
    }

    function core(uint256 ownerPk, uint256 rho, uint256 aux) internal view returns (uint256) {
        return PoseidonT3.hash(PoseidonT3.hash(pool.D_CORE(), ownerPk), PoseidonT3.hash(rho, aux));
    }

    function leaf(uint256 c, uint256 amount, address funder, uint256 refundAfter) internal pure returns (uint256) {
        uint256 refundTag = refundAfter == 0 ? 0 : PoseidonT3.hash(uint256(uint160(funder)), refundAfter);
        return PoseidonT3.hash(PoseidonT3.hash(c, amount), refundTag);
    }

    function nullifierAt(uint256 rho, uint256 position) internal view returns (uint256) {
        return PoseidonT3.hash(PoseidonT3.hash(pool.D_NF(), rho), position);
    }

    function test_leafIsBoundToTheAmountPaidIn() public {
        uint256 c = core(OWNER_PK, RHO, AUX);
        vm.prank(mallory);
        pool.deposit(c, 1, 0, "");
        // The leaf a million-unit note would need is not in the tree: the pool
        // filed the one-unit leaf, and there is no call that files another.
        assertEq(pool.leafPositionPlusOne(leaf(c, 1, mallory, 0)), 1);
        assertEq(pool.leafPositionPlusOne(leaf(c, 1_000_000, mallory, 0)), 0);
    }

    function test_refundAfterTheWindowPaysTheFunder() public {
        uint256 c = core(OWNER_PK, RHO, AUX);
        vm.prank(alice);
        pool.deposit(c, 5_000, WINDOW, "");
        uint256 refundAfter = block.timestamp + WINDOW;

        vm.warp(refundAfter);
        uint256 before = token.balanceOf(alice);
        vm.prank(alice);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, refundAfter);
        assertEq(token.balanceOf(alice), before + 5_000);
        assertTrue(pool.nullifierSpent(nullifierAt(RHO, 0)));
    }

    function test_refundBeforeTheWindowIsRefused() public {
        vm.prank(alice);
        pool.deposit(core(OWNER_PK, RHO, AUX), 5_000, WINDOW, "");
        uint256 refundAfter = block.timestamp + WINDOW;
        vm.warp(refundAfter - 1);
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.RefundNotYet.selector);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, refundAfter);
    }

    function test_onlyTheFunderCanRefund() public {
        vm.prank(alice);
        pool.deposit(core(OWNER_PK, RHO, AUX), 5_000, WINDOW, "");
        uint256 refundAfter = block.timestamp + WINDOW;
        vm.warp(refundAfter);
        // Mallory knows every part of the note; the leaf still carries Alice.
        vm.prank(mallory);
        vm.expectRevert(Tidex6HiddenPoolV2.UnknownNote.selector);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, refundAfter);
    }

    function test_refundCannotClaimMoreThanWasPaid() public {
        vm.prank(alice);
        pool.deposit(core(OWNER_PK, RHO, AUX), 5_000, WINDOW, "");
        uint256 refundAfter = block.timestamp + WINDOW;
        vm.warp(refundAfter);
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.UnknownNote.selector);
        pool.refund(OWNER_PK, RHO, AUX, 5_001, refundAfter);
    }

    function test_refundTwiceIsRefused() public {
        vm.prank(alice);
        pool.deposit(core(OWNER_PK, RHO, AUX), 5_000, WINDOW, "");
        uint256 refundAfter = block.timestamp + WINDOW;
        vm.warp(refundAfter);
        vm.startPrank(alice);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, refundAfter);
        vm.expectRevert(Tidex6HiddenPoolV2.NullifierAlreadySpent.selector);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, refundAfter);
        vm.stopPrank();
    }

    function test_noRefundAfterTheOwnerWithdrew() public {
        vm.prank(alice);
        pool.deposit(core(OWNER_PK, RHO, AUX), 5_000, WINDOW, "");
        uint256 refundAfter = block.timestamp + WINDOW;
        uint256 nf = nullifierAt(RHO, 0);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        pool.withdraw(a, b, c, pool.currentRoot(), nf, bob, address(0), 0, 5_000);
        assertEq(token.balanceOf(bob), 5_000);

        vm.warp(refundAfter);
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.NullifierAlreadySpent.selector);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, refundAfter);
    }

    function test_noWithdrawAfterRefund() public {
        vm.prank(alice);
        pool.deposit(core(OWNER_PK, RHO, AUX), 5_000, WINDOW, "");
        uint256 refundAfter = block.timestamp + WINDOW;
        uint256 root = pool.currentRoot();
        vm.warp(refundAfter);
        vm.prank(alice);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, refundAfter);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.expectRevert(Tidex6HiddenPoolV2.NullifierAlreadySpent.selector);
        pool.withdraw(a, b, c, root, nullifierAt(RHO, 0), bob, address(0), 0, 5_000);
    }

    function test_aNoteWithoutRefundCannotBeRefunded() public {
        vm.prank(alice);
        pool.deposit(core(OWNER_PK, RHO, AUX), 5_000, 0, "");
        vm.warp(block.timestamp + 365 days);
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.RefundNotYet.selector);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, 0);
    }

    function test_theFeeNoteHasNoRefundAndSitsNextToThePayment() public {
        uint256 payCore = core(OWNER_PK, RHO, AUX);
        uint256 feeCore = core(0x7EA5, 0x99, AUX);
        vm.prank(alice);
        pool.depositWithFee(payCore, 5_000, WINDOW, "", feeCore, 100, "");
        uint256 refundAfter = block.timestamp + WINDOW;

        assertEq(pool.leafPositionPlusOne(leaf(payCore, 5_000, alice, refundAfter)), 1);
        // The fee leaf carries no refund tag, and its position is its own.
        assertEq(pool.leafPositionPlusOne(leaf(feeCore, 100, alice, 0)), 2);
        assertEq(token.balanceOf(address(pool)), 5_100);

        vm.warp(block.timestamp + 365 days);
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.UnknownNote.selector);
        pool.refund(0x7EA5, 0x99, AUX, 100, refundAfter);
    }

    function test_reusedRandomnessStillGivesDistinctNullifiers() public {
        // Faerie Gold: the same rho in two notes. Positions differ, so do the
        // nullifiers, and the owner can spend both.
        vm.startPrank(alice);
        pool.deposit(core(OWNER_PK, RHO, AUX), 5_000, 0, "");
        pool.deposit(core(OWNER_PK, RHO, AUX), 6_000, 0, "");
        vm.stopPrank();
        assertTrue(nullifierAt(RHO, 0) != nullifierAt(RHO, 1));
    }

    function test_anIdenticalNoteIsRefused() public {
        vm.startPrank(alice);
        pool.deposit(core(OWNER_PK, RHO, AUX), 5_000, 0, "");
        vm.expectRevert(Tidex6HiddenPoolV2.CommitmentAlreadyUsed.selector);
        pool.deposit(core(OWNER_PK, RHO, AUX), 5_000, 0, "");
        vm.stopPrank();
    }

    function test_refundWindowBounds() public {
        uint256 c = core(OWNER_PK, RHO, AUX);
        vm.startPrank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.RefundWindowOutOfRange.selector);
        pool.deposit(c, 5_000, 4 minutes, "");
        vm.expectRevert(Tidex6HiddenPoolV2.RefundWindowOutOfRange.selector);
        pool.deposit(c, 5_000, 31 days, "");
        vm.stopPrank();
    }
}
