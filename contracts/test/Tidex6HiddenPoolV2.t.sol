// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Tidex6HiddenPoolV2, IERC20V2, IWithdrawVerifierV2, ITransferVerifierV2} from "../src/Tidex6HiddenPoolV2.sol";
import {PoseidonT3} from "../src/PoseidonT3.sol";
import {TestToken} from "./Tidex6HiddenPool.t.sol";

/// Verifier stand-in for both v2 circuits; the verdict is the test's.
/// `view`, like the real verifiers (see the v1 test for why it matters).
contract MockVerifierV2 {
    bool public verdict = true;

    function setVerdict(bool value) external {
        verdict = value;
    }

    function verifyProof(uint256[2] calldata, uint256[2][2] calldata, uint256[2] calldata, uint256[8] calldata)
        external
        view
        returns (bool)
    {
        return verdict;
    }

    function verifyProof(uint256[2] calldata, uint256[2][2] calldata, uint256[2] calldata, uint256[7] calldata)
        external
        view
        returns (bool)
    {
        return verdict;
    }
}

/// The v2 pool's own logic (ADR-022): the leaf is bound to the amount paid in,
/// the refund path belongs to the funder after the window, and both spending
/// paths share one nullifier. The circuit side — that only the owner can build
/// a withdraw proof — is checked on the Rust side against real proofs.
contract Tidex6HiddenPoolV2Test is Test {
    Tidex6HiddenPoolV2 pool;
    TestToken token;
    MockVerifierV2 verifier;

    address alice = address(0xA11CE);
    address mallory = address(0xBAD);
    address bob = address(0xB0B);

    uint256 constant OWNER_PK = 0x1234;
    uint256 constant RHO = 0x5678;
    uint256 constant AUX = 0;
    uint256 constant WINDOW = 1 days;
    uint256 constant TREASURY_PK = 0x7EA5;
    uint256 constant FEE_FLOOR = 100;
    uint256 constant FEE_RHO = 0x99;

    function setUp() public {
        token = new TestToken();
        verifier = new MockVerifierV2();
        pool = new Tidex6HiddenPoolV2(
            IERC20V2(address(token)),
            IWithdrawVerifierV2(address(verifier)),
            ITransferVerifierV2(address(verifier)),
            TREASURY_PK,
            FEE_FLOOR
        );
        for (uint256 i = 0; i < 2; i++) {
            address who = i == 0 ? alice : mallory;
            token.mint(who, 1_000_000_000);
            vm.prank(who);
            token.approve(address(pool), type(uint256).max);
        }
        c0 = core(OWNER_PK, RHO, AUX);
    }

    uint256 c0;

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
        uint256 c = c0;
        vm.prank(mallory);
        pool.deposit(c, 1, 0, "", FEE_RHO, "");
        // The leaf a million-unit note would need is not in the tree: the pool
        // filed the one-unit leaf, and there is no call that files another.
        assertEq(pool.leafPositionPlusOne(leaf(c, 1, mallory, 0)), 1);
        assertEq(pool.leafPositionPlusOne(leaf(c, 1_000_000, mallory, 0)), 0);
    }

    function test_refundAfterTheWindowPaysTheFunder() public {
        uint256 c = c0;
        vm.prank(alice);
        pool.deposit(c, 5_000, WINDOW, "", FEE_RHO, "");
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
        pool.deposit(c0, 5_000, WINDOW, "", FEE_RHO, "");
        uint256 refundAfter = block.timestamp + WINDOW;
        vm.warp(refundAfter - 1);
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.RefundNotYet.selector);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, refundAfter);
    }

    function test_onlyTheFunderCanRefund() public {
        vm.prank(alice);
        pool.deposit(c0, 5_000, WINDOW, "", FEE_RHO, "");
        uint256 refundAfter = block.timestamp + WINDOW;
        vm.warp(refundAfter);
        // Mallory knows every part of the note; the leaf still carries Alice.
        vm.prank(mallory);
        vm.expectRevert(Tidex6HiddenPoolV2.UnknownNote.selector);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, refundAfter);
    }

    function test_refundCannotClaimMoreThanWasPaid() public {
        vm.prank(alice);
        pool.deposit(c0, 5_000, WINDOW, "", FEE_RHO, "");
        uint256 refundAfter = block.timestamp + WINDOW;
        vm.warp(refundAfter);
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.UnknownNote.selector);
        pool.refund(OWNER_PK, RHO, AUX, 5_001, refundAfter);
    }

    function test_refundTwiceIsRefused() public {
        vm.prank(alice);
        pool.deposit(c0, 5_000, WINDOW, "", FEE_RHO, "");
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
        pool.deposit(c0, 5_000, WINDOW, "", FEE_RHO, "");
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
        pool.deposit(c0, 5_000, WINDOW, "", FEE_RHO, "");
        uint256 refundAfter = block.timestamp + WINDOW;
        uint256 root = pool.currentRoot();
        uint256 nf = nullifierAt(RHO, 0);
        vm.warp(refundAfter);
        vm.prank(alice);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, refundAfter);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.expectRevert(Tidex6HiddenPoolV2.NullifierAlreadySpent.selector);
        pool.withdraw(a, b, c, root, nf, bob, address(0), 0, 5_000);
    }

    function test_aNoteWithoutRefundCannotBeRefunded() public {
        vm.prank(alice);
        pool.deposit(c0, 5_000, 0, "", FEE_RHO, "");
        vm.warp(block.timestamp + 365 days);
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.RefundNotYet.selector);
        pool.refund(OWNER_PK, RHO, AUX, 5_000, 0);
    }

    function test_everyDepositFilesTheFeeForTheTreasury() public {
        uint256 payCore = c0;
        uint256 feeCore = core(TREASURY_PK, FEE_RHO, 0);
        vm.prank(alice);
        pool.deposit(payCore, 5_000, WINDOW, "", FEE_RHO, "");
        uint256 refundAfter = block.timestamp + WINDOW;

        // 1% of 5 000 is 50, under the floor of 100: the floor is charged.
        assertEq(token.balanceOf(address(pool)), 5_100);
        assertEq(pool.leafPositionPlusOne(leaf(payCore, 5_000, alice, refundAfter)), 1);
        // The fee leaf is owned by the treasury key and carries no refund tag.
        assertEq(pool.leafPositionPlusOne(leaf(feeCore, 100, alice, 0)), 2);

        vm.warp(block.timestamp + 365 days);
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.UnknownNote.selector);
        pool.refund(TREASURY_PK, FEE_RHO, 0, 100, refundAfter);
    }

    function test_theFeeIsOnePercentRoundedUp() public {
        vm.prank(alice);
        pool.deposit(c0, 1_000_050, 0, "", FEE_RHO, "");
        // 1 000 050 / 100 = 10 000.5 → 10 001.
        assertEq(pool.feeFor(1_000_050), 10_001);
        assertEq(token.balanceOf(address(pool)), 1_000_050 + 10_001);
    }

    function test_thereIsNoDepositWithoutAFee() public {
        // The only way in charges the fee; a sender without funds for it is refused.
        address poor = address(0x9009);
        token.mint(poor, 5_000);
        vm.startPrank(poor);
        token.approve(address(pool), type(uint256).max);
        vm.expectRevert(bytes("balance"));
        pool.deposit(c0, 5_000, 0, "", FEE_RHO, "");
        vm.stopPrank();
    }

    function test_reusedRandomnessStillGivesDistinctNullifiers() public {
        // Faerie Gold: the same rho in two notes. Positions differ, so do the
        // nullifiers, and the owner can spend both.
        vm.startPrank(alice);
        pool.deposit(c0, 5_000, 0, "", FEE_RHO, "");
        pool.deposit(c0, 6_000, 0, "", FEE_RHO + 1, "");
        vm.stopPrank();
        // Payments sit at 0 and 2, each followed by its fee note.
        assertTrue(nullifierAt(RHO, 0) != nullifierAt(RHO, 2));
    }

    function test_anIdenticalNoteIsRefused() public {
        vm.startPrank(alice);
        pool.deposit(c0, 5_000, 0, "", FEE_RHO, "");
        vm.expectRevert(Tidex6HiddenPoolV2.CommitmentAlreadyUsed.selector);
        pool.deposit(c0, 5_000, 0, "", FEE_RHO + 1, "");
        vm.stopPrank();
    }

    function test_refundWindowBounds() public {
        uint256 c = c0;
        vm.startPrank(alice);
        vm.expectRevert(Tidex6HiddenPoolV2.RefundWindowOutOfRange.selector);
        pool.deposit(c, 5_000, 4 minutes, "", FEE_RHO, "");
        vm.expectRevert(Tidex6HiddenPoolV2.RefundWindowOutOfRange.selector);
        pool.deposit(c, 5_000, 31 days, "", FEE_RHO, "");
        vm.stopPrank();
    }
}
