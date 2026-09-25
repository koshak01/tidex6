// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Tidex6HiddenPool, IERC20} from "../src/Tidex6HiddenPool.sol";
import {Tidex6HiddenWithdrawVerifier} from "../src/Tidex6HiddenWithdrawVerifier.sol";
import {Tidex6HiddenTransferVerifier} from "../src/Tidex6HiddenTransferVerifier.sol";
import {PoseidonT3} from "../src/PoseidonT3.sol";

/// Minimal ERC-20 for the test. Not a product; just something to move.
contract TestToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external virtual returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external virtual returns (bool) {
        return _move(from, to, amount);
    }

    function _move(address from, address to, uint256 amount) internal returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// A verifier whose verdict the test sets.
///
/// It stands in for the real Groth16 verifier deliberately: these tests are
/// about the pool's own logic — who is paid, what is refused, what the
/// nullifier guards — and that logic has to hold whatever the cryptography
/// answers, including when it answers "no". The cryptography is checked
/// elsewhere: `Tidex6Verifier.t.sol` runs a real proof from the Rust prover
/// against the generated verifier, and every deployed pool is walked end to end
/// on a live chain before it carries anything.
///
/// `verifyProof` must stay `view`. The real verifiers declare it `view`, so the
/// pool reaches them with `staticcall`; a mock that recorded its arguments in
/// storage would revert on every call, and every test here would fail for a
/// reason that has nothing to do with the pool.
contract MockVerifier {
    bool public verdict = true;

    function setVerdict(bool value) external {
        verdict = value;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[8] calldata
    ) external view returns (bool) {
        return verdict;
    }

    function verifyProof(
        uint256[2] calldata,
        uint256[2][2] calldata,
        uint256[2] calldata,
        uint256[4] calldata
    ) external view returns (bool) {
        return verdict;
    }
}

/// A token that calls back into the pool while it is being paid out. Used once,
/// to show the nullifier is written before the transfer and not after it.
contract ReentrantToken is TestToken {
    Tidex6HiddenPool public pool;
    bool public armed;
    bool public reenterRefused;

    function arm(Tidex6HiddenPool pool_) external {
        pool = pool_;
        armed = true;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        if (armed) {
            armed = false;
            uint256[2] memory a;
            uint256[2][2] memory b;
            uint256[2] memory c;
            // The same nullifier as the withdrawal in flight. If the pool wrote
            // it only after paying, this second spend would go through.
            try pool.withdraw(a, b, c, pool.currentRoot(), 777, to, address(0), 0, 1) {
                reenterRefused = false;
            } catch {
                reenterRefused = true;
            }
        }
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// A token that calls back into `deposit` while the pool is pulling it — the
/// shape of an ERC-777-style token. Used to show a nested deposit cannot land
/// on the same leaf as the one in flight.
contract ReentrantDepositToken is TestToken {
    Tidex6HiddenPool public pool;
    bool public armed;
    uint256 public nestedCommitment;

    function arm(Tidex6HiddenPool pool_, uint256 commitment) external {
        pool = pool_;
        nestedCommitment = commitment;
        armed = true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        if (armed) {
            armed = false;
            // The token itself deposits; it holds a balance and allowance of its own.
            pool.deposit(1, nestedCommitment, "");
        }
        return _move(from, to, amount);
    }
}

/// @title Hidden-amount pool — the contract the product actually runs on
/// @notice Every note here carries its amount inside the commitment, so the
///         pool cannot check that the two agree and does not try: a commitment
///         that does not match its amount is a note nobody can ever withdraw.
///         What the pool must get right is everything around that — the tree
///         walk, the root history, the double-spend guard, who is paid how
///         much, and the exact public inputs handed to the verifier. Those are
///         what these tests pin down.
contract Tidex6HiddenPoolTest is Test {
    /// BN254 scalar field order. A commitment at or above this is not a field
    /// element and the pool must refuse it.
    uint256 internal constant F =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    TestToken internal token;
    MockVerifier internal verifier;
    Tidex6HiddenPool internal pool;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);
    address internal relayer = address(0xBEEF);

    /// Commitments. What they hide is the client's business; to the pool they
    /// are field elements it has not seen before.
    uint256 internal constant C1 = 0x1111111111111111111111111111111111111111111111111111111111111;
    uint256 internal constant C2 = 0x2222222222222222222222222222222222222222222222222222222222222;
    uint256 internal constant C3 = 0x3333333333333333333333333333333333333333333333333333333333333;

    event Deposit(
        uint256 indexed commitment,
        uint256 leafIndex,
        uint256 newRoot,
        address depositor,
        uint256 amount,
        bytes envelope
    );

    function setUp() public {
        token = new TestToken();
        verifier = new MockVerifier();
        pool = new Tidex6HiddenPool(
            IERC20(address(token)),
            Tidex6HiddenWithdrawVerifier(address(verifier)),
            Tidex6HiddenTransferVerifier(address(verifier))
        );

        token.mint(alice, 1_000_000);
        vm.prank(alice);
        token.approve(address(pool), type(uint256).max);
    }

    /// The root of a depth-20 tree holding one leaf at index 0, computed here
    /// from Poseidon alone rather than read back from the pool. Independent of
    /// the pool's own bookkeeping on purpose: this is the value the Rust client
    /// and the Solana program arrive at, and if the pool's walk ever diverges
    /// from it, proofs built by the client are unprovable here.
    function _rootWithFirstLeaf(uint256 leaf) internal pure returns (uint256) {
        uint256 node = leaf;
        uint256 emptyAtLevel = 0;
        for (uint256 level = 0; level < 20; level++) {
            node = PoseidonT3.hash(node, emptyAtLevel);
            emptyAtLevel = PoseidonT3.hash(emptyAtLevel, emptyAtLevel);
        }
        return node;
    }

    function _deposit(uint256 amount, uint256 commitment) internal returns (uint256 root) {
        vm.prank(alice);
        pool.deposit(amount, commitment, "");
        return pool.currentRoot();
    }

    // ── deposit ────────────────────────────────────────────────────────────

    function test_depositMovesTokensAndInsertsLeaf() public {
        uint256 expectedRoot = _rootWithFirstLeaf(C1);

        // The log is the only place the envelope and the amount are published;
        // the browser and the indexer read the payment out of exactly this.
        vm.expectEmit(true, false, false, true, address(pool));
        emit Deposit(C1, 0, expectedRoot, alice, 1_000, hex"deadbeef");

        vm.prank(alice);
        pool.deposit(1_000, C1, hex"deadbeef");

        assertEq(token.balanceOf(address(pool)), 1_000, "pool holds the deposit");
        assertEq(token.balanceOf(alice), 999_000, "sender paid it");
        assertEq(pool.nextLeafIndex(), 1, "one leaf used");
        assertEq(pool.currentRoot(), expectedRoot, "the tree walk matches the client's");
        assertTrue(pool.isKnownRoot(expectedRoot), "the new root can be proved against");
    }

    function test_depositRejectsZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPool.AmountOutOfRange.selector);
        pool.deposit(0, C1, "");
    }

    /// The circuit range-proves the amount to 64 bits. A pool that took more
    /// would accept money for a note no proof could ever spend.
    function test_depositRejectsAmountAboveCircuitRange() public {
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPool.AmountOutOfRange.selector);
        pool.deposit(uint256(type(uint64).max) + 1, C1, "");
    }

    /// The other side of that boundary: the largest note the circuit accepts
    /// has to go through, or the range check is off by one.
    function test_depositAcceptsTheLargestAllowedAmount() public {
        uint256 max = pool.MAX_AMOUNT();
        token.mint(alice, max);

        vm.prank(alice);
        pool.deposit(max, C1, "");

        assertEq(token.balanceOf(address(pool)), max, "the largest note is accepted");
    }

    function test_depositRejectsCommitmentOutsideField() public {
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPool.NotAFieldElement.selector);
        pool.deposit(1_000, F, "");
    }

    /// Two identical commitments share one nullifier: the first withdrawal
    /// would spend both notes and the second deposit would be unrecoverable.
    function test_depositRejectsDuplicateCommitment() public {
        vm.startPrank(alice);
        pool.deposit(1_000, C1, "");
        vm.expectRevert(Tidex6HiddenPool.CommitmentAlreadyUsed.selector);
        pool.deposit(1_000, C1, "");
        vm.stopPrank();
    }

    /// The empty tree must hash to the same root the client starts from. If
    /// these ever diverge, the very first withdrawal proves against a root the
    /// pool has never heard of, and nothing deposited here is spendable.
    function test_emptyTreeRootMatchesTheClient() public view {
        uint256 empty = 0;
        for (uint256 level = 0; level < pool.TREE_DEPTH(); level++) {
            empty = PoseidonT3.hash(empty, empty);
        }
        assertEq(pool.rootHistory(0), empty, "empty-tree root");
        assertEq(pool.currentRoot(), empty, "and it is the current root");
    }

    /// Zero is what an untouched slot of the root ring holds. It must never
    /// count as known, or an unused slot would authorise a spend.
    function test_zeroIsNeverAKnownRoot() public view {
        assertFalse(pool.isKnownRoot(0), "zero root");
    }

    // ── withdraw ───────────────────────────────────────────────────────────

    function test_withdrawPaysRecipientAndRelayer() public {
        uint256 root = _deposit(1_000, C1);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        pool.withdraw(a, b, c, root, 42, bob, relayer, 10, 1_000);

        assertEq(token.balanceOf(bob), 990, "recipient gets the amount minus the fee");
        assertEq(token.balanceOf(relayer), 10, "relayer gets the fee");
        assertEq(token.balanceOf(address(pool)), 0, "the note left the pool");
        assertTrue(pool.nullifierSpent(42), "nullifier recorded");
        assertEq(pool.currentRoot(), root, "a withdrawal does not touch the tree");
    }

    /// The whole point of the nullifier: one note, one withdrawal.
    function test_withdrawRejectsReusedNullifier() public {
        uint256 root = _deposit(2_000, C1);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        pool.withdraw(a, b, c, root, 42, bob, relayer, 0, 1_000);

        vm.expectRevert(Tidex6HiddenPool.NullifierAlreadySpent.selector);
        pool.withdraw(a, b, c, root, 42, bob, relayer, 0, 1_000);
    }

    function test_withdrawRejectsUnknownRoot() public {
        _deposit(1_000, C1);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.expectRevert(Tidex6HiddenPool.RootNotRecent.selector);
        pool.withdraw(a, b, c, 0xdead, 42, bob, relayer, 0, 1_000);
    }

    /// A fee above the amount would underflow the payout — refused before the
    /// proof is even looked at.
    function test_withdrawRejectsFeeAboveAmount() public {
        uint256 root = _deposit(1_000, C1);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.expectRevert(Tidex6HiddenPool.FeeExceedsAmount.selector);
        pool.withdraw(a, b, c, root, 42, bob, relayer, 1_001, 1_000);
    }

    /// The boundary right next to it: a fee equal to the amount is allowed, and
    /// must pay out zero rather than underflow.
    function test_withdrawAllowsFeeEqualToAmount() public {
        uint256 root = _deposit(1_000, C1);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        pool.withdraw(a, b, c, root, 42, bob, relayer, 1_000, 1_000);

        assertEq(token.balanceOf(bob), 0, "nothing left for the recipient");
        assertEq(token.balanceOf(relayer), 1_000, "all of it went to the fee");
    }

    function test_withdrawRejectsInvalidProof() public {
        uint256 root = _deposit(1_000, C1);
        verifier.setVerdict(false);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.expectRevert(Tidex6HiddenPool.InvalidProof.selector);
        pool.withdraw(a, b, c, root, 42, bob, relayer, 0, 1_000);

        assertFalse(pool.nullifierSpent(42), "a refused withdrawal spends nothing");
        assertEq(token.balanceOf(bob), 0, "and pays nothing");
    }

    /// The public inputs are the only thing binding a proof to this payout. The
    /// recipient and the relayer travel as two 128-bit halves each, and a pool
    /// that assembled them wrongly would let a valid proof be redirected to
    /// another address — the shape of gap our own review found in the first
    /// circuit, before there was money in any pool. This pins the order and the
    /// split against the exact calldata the pool sends.
    function test_withdrawPublicInputsBindRecipientAndRelayer() public {
        uint256 root = _deposit(1_000, C1);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        // Every element is cast: an array literal takes the common type of its
        // elements, and a bare number literal there is a rational constant.
        uint256[8] memory expected = [
            root,
            uint256(42),
            uint256(uint160(bob)) >> 128,
            uint256(uint160(bob)) & type(uint128).max,
            uint256(uint160(relayer)) >> 128,
            uint256(uint160(relayer)) & type(uint128).max,
            uint256(7),
            uint256(1_000)
        ];

        vm.expectCall(
            address(verifier),
            abi.encodeCall(Tidex6HiddenWithdrawVerifier.verifyProof, (a, b, c, expected))
        );
        pool.withdraw(a, b, c, root, 42, bob, relayer, 7, 1_000);
    }

    /// A token can call back while it is paying out. The nullifier is written
    /// before the transfer, so the re-entrant withdrawal must be refused —
    /// otherwise one note could be spent twice inside a single transaction.
    function test_nullifierIsWrittenBeforeThePayout() public {
        ReentrantToken evil = new ReentrantToken();
        MockVerifier v = new MockVerifier();
        Tidex6HiddenPool p = new Tidex6HiddenPool(
            IERC20(address(evil)),
            Tidex6HiddenWithdrawVerifier(address(v)),
            Tidex6HiddenTransferVerifier(address(v))
        );

        evil.mint(alice, 10_000);
        vm.startPrank(alice);
        evil.approve(address(p), type(uint256).max);
        p.deposit(1_000, C1, "");
        vm.stopPrank();

        evil.arm(p);
        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        p.withdraw(a, b, c, p.currentRoot(), 777, bob, address(0), 0, 1_000);

        assertTrue(evil.reenterRefused(), "the re-entrant withdrawal was refused");
        assertTrue(p.nullifierSpent(777), "and the nullifier stayed spent");
        assertEq(evil.balanceOf(bob), 1_000, "the honest payout still went through");
    }

    // ── depositWithFee ─────────────────────────────────────────────────────

    /// One call, one token pull, two leaves and two `Deposit` logs — the same
    /// logs two `deposit` calls emit, so the browser, the auditor, the relayer's
    /// index and the treasury robots read the pair without a change.
    function test_depositWithFeeAddsBothNotesInOneCall() public {
        uint256 afterFirst = _rootWithFirstLeaf(C1);

        vm.expectEmit(true, false, false, true, address(pool));
        emit Deposit(C1, 0, afterFirst, alice, 1_000, hex"aa");
        vm.expectEmit(true, false, false, false, address(pool));
        emit Deposit(C2, 1, 0, alice, 100, hex"bb");

        vm.prank(alice);
        pool.depositWithFee(1_000, C1, hex"aa", 100, C2, hex"bb");

        assertEq(token.balanceOf(address(pool)), 1_100, "pool holds payment and fee");
        assertEq(token.balanceOf(alice), 998_900, "sender paid both in one pull");
        assertEq(pool.nextLeafIndex(), 2, "two leaves");
        assertTrue(pool.commitmentKnown(C1) && pool.commitmentKnown(C2), "both notes are in");
    }

    /// The pair lands exactly where two separate deposits would: a proof built
    /// against a tree the client rebuilt from the logs has to verify here.
    function test_depositWithFeeGivesTheSameRootAsTwoDeposits() public {
        Tidex6HiddenPool twin = new Tidex6HiddenPool(
            IERC20(address(token)),
            Tidex6HiddenWithdrawVerifier(address(verifier)),
            Tidex6HiddenTransferVerifier(address(verifier))
        );
        vm.startPrank(alice);
        token.approve(address(twin), type(uint256).max);
        twin.deposit(1_000, C1, "");
        twin.deposit(100, C2, "");
        pool.depositWithFee(1_000, C1, "", 100, C2, "");
        vm.stopPrank();

        assertEq(pool.currentRoot(), twin.currentRoot(), "same tree either way");
    }

    function test_depositWithFeeRefusesEqualCommitments() public {
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPool.CommitmentAlreadyUsed.selector);
        pool.depositWithFee(1_000, C1, "", 100, C1, "");
    }

    function test_depositWithFeeRefusesAZeroFee() public {
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPool.AmountOutOfRange.selector);
        pool.depositWithFee(1_000, C1, "", 0, C2, "");
    }

    function test_depositWithFeeRefusesAnOversizedFee() public {
        vm.prank(alice);
        vm.expectRevert(Tidex6HiddenPool.AmountOutOfRange.selector);
        pool.depositWithFee(1_000, C1, "", uint256(type(uint64).max) + 1, C2, "");
    }

    /// A failed pull undoes both notes: the pair enters together or not at all.
    function test_depositWithFeeWithoutAllowanceLeavesNoNote() public {
        vm.prank(alice);
        token.approve(address(pool), 1_050);
        vm.prank(alice);
        vm.expectRevert(bytes("allowance"));
        pool.depositWithFee(1_000, C1, "", 100, C2, "");

        assertEq(pool.nextLeafIndex(), 0, "no leaf");
        assertFalse(pool.commitmentKnown(C1), "the payment note did not stay behind");
    }

    // ── re-entrancy on deposit ─────────────────────────────────────────────

    /// A token that re-enters `deposit` while being pulled. The tree is final
    /// before the pull, so the nested deposit takes the NEXT leaf and both
    /// notes survive; pulled first, the nested note would have been
    /// overwritten by the outer one.
    function test_reentrantDepositCannotOverwriteALeaf() public {
        ReentrantDepositToken evil = new ReentrantDepositToken();
        Tidex6HiddenPool p = new Tidex6HiddenPool(
            IERC20(address(evil)),
            Tidex6HiddenWithdrawVerifier(address(verifier)),
            Tidex6HiddenTransferVerifier(address(verifier))
        );
        evil.mint(alice, 10_000);
        evil.mint(address(evil), 10);
        vm.prank(alice);
        evil.approve(address(p), type(uint256).max);
        vm.prank(address(evil));
        evil.approve(address(p), type(uint256).max);

        evil.arm(p, C2);
        vm.prank(alice);
        p.deposit(1_000, C1, "");

        Tidex6HiddenPool twin = new Tidex6HiddenPool(
            IERC20(address(token)),
            Tidex6HiddenWithdrawVerifier(address(verifier)),
            Tidex6HiddenTransferVerifier(address(verifier))
        );
        vm.startPrank(alice);
        token.approve(address(twin), type(uint256).max);
        twin.deposit(1_000, C1, "");
        twin.deposit(1, C2, "");
        vm.stopPrank();

        assertEq(p.nextLeafIndex(), 2, "both deposits took a leaf");
        assertEq(p.currentRoot(), twin.currentRoot(), "and neither overwrote the other");
    }

    // ── transferNote (join-split) ──────────────────────────────────────────

    /// Spending one note into two moves no token and adds two leaves. The
    /// amounts live inside the commitments; the chain sees neither of them.
    function test_transferNoteCreatesTwoLeavesAndSpendsTheNullifier() public {
        uint256 root = _deposit(5_000, C1);
        uint256 heldBefore = token.balanceOf(address(pool));

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        pool.transferNote(a, b, c, root, 99, C2, C3, "", "");

        assertEq(token.balanceOf(address(pool)), heldBefore, "no token moved");
        assertEq(pool.nextLeafIndex(), 3, "two new leaves on top of the deposit");
        assertTrue(pool.nullifierSpent(99), "the spent note is marked");
        assertTrue(pool.isKnownRoot(pool.currentRoot()), "the new root can be proved against");
    }

    function test_transferNoteRejectsReusedNullifier() public {
        uint256 root = _deposit(5_000, C1);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        pool.transferNote(a, b, c, root, 99, C2, C3, "", "");

        vm.expectRevert(Tidex6HiddenPool.NullifierAlreadySpent.selector);
        pool.transferNote(a, b, c, root, 99, C2, C3, "", "");
    }

    /// Both outputs are reserved before either is appended, so a join-split
    /// cannot reuse a commitment that is already in the tree.
    function test_transferNoteRejectsCommitmentAlreadyInTree() public {
        uint256 root = _deposit(5_000, C1);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.expectRevert(Tidex6HiddenPool.CommitmentAlreadyUsed.selector);
        pool.transferNote(a, b, c, root, 99, C1, C2, "", "");
    }

    /// Two equal outputs would be one note the owner could not tell apart from
    /// itself. The contract claims the second reservation trips on the first;
    /// this is that claim.
    function test_transferNoteRejectsTwoEqualOutputs() public {
        uint256 root = _deposit(5_000, C1);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.expectRevert(Tidex6HiddenPool.CommitmentAlreadyUsed.selector);
        pool.transferNote(a, b, c, root, 99, C2, C2, "", "");
    }

    function test_transferNoteRejectsUnknownRoot() public {
        _deposit(5_000, C1);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.expectRevert(Tidex6HiddenPool.RootNotRecent.selector);
        pool.transferNote(a, b, c, 0xdead, 99, C2, C3, "", "");
    }

    function test_transferNoteRejectsInvalidProof() public {
        uint256 root = _deposit(5_000, C1);
        verifier.setVerdict(false);

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        vm.expectRevert(Tidex6HiddenPool.InvalidProof.selector);
        pool.transferNote(a, b, c, root, 99, C2, C3, "", "");

        assertFalse(pool.nullifierSpent(99), "a refused join-split spends nothing");
        assertEq(pool.nextLeafIndex(), 1, "and inserts nothing");
    }

    /// The root ring is what lets a proof survive other people's insertions. A
    /// root that was current when the user started must still work several
    /// deposits later, or two concurrent payments would invalidate each other.
    function test_olderRootStaysProvableWhileItIsInTheRing() public {
        uint256 oldRoot = _deposit(1_000, C1);
        _deposit(1_000, C2);
        _deposit(1_000, C3);

        assertTrue(pool.isKnownRoot(oldRoot), "still in the ring three insertions later");

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;
        pool.withdraw(a, b, c, oldRoot, 42, bob, relayer, 0, 1_000);

        assertEq(token.balanceOf(bob), 1_000, "a proof against the old root still pays");
    }
}
