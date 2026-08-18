// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Tidex6Pool, IERC20} from "../src/Tidex6Pool.sol";
import {Tidex6Verifier} from "../src/Tidex6Verifier.sol";

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

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        require(allowance[from][msg.sender] >= amount, "allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @title Does the Solidity pool agree with the Rust client?
/// @notice The proof below was generated against a depth-20 tree built by
///         `tidex6_core::merkle` for a single deposit. The pool builds its own
///         tree from the same commitment. If the two roots differ, deposits
///         made here could never be withdrawn — so `test_rootMatchesRust` is
///         the test that decides whether this contract is safe to deploy.
///
///         Regenerate with:
///           cargo run --bin export_pool_fixture --release
contract Tidex6PoolTest is Test {
    Tidex6Pool internal pool;
    TestToken internal token;
    Tidex6Verifier internal verifier;

    address internal depositor = address(0xD3);
    address internal recipient = 0xA439Ad519046CCd7056Ddf74fbaAc99d740Bdf09;
    address internal relayer = 0x8f4f72DD4421Bc39af3b3Ff145e0702F6AC95fb9;

    uint256 internal constant DENOMINATION = 100_000_000;
    uint256 internal constant FEE = 1000000;

    uint256 internal constant COMMITMENT = 21133731795125218879770237676509304824224234338153766379440246562756965142916;
    uint256 internal constant EXPECTED_ROOT = 9320035109223905669555919870974467834898477155077275771998462004481757406537;
    uint256 internal constant NULLIFIER_HASH = 3228837805036640562887160086138756906643146730490387571226220750860647184912;

    uint256[2] internal pA = [
        18355650993405829351318310845625095851488932673043829676404441586980944174085,
        20525590052761788257212279698976163398967734254757856126619486220281176099393
    ];
    uint256[2][2] internal pB = [
        [13328324735284595025494996279474245863484224807984223672536408027179946702065, 6140717143362093304772299772137796309389000459017798120432226530013257410964],
        [1518812842158753693098321154726345845535961035254281654471458899096613779406, 9059291629793683769918780764450333765704367733703733665930539396934983992259]
    ];
    uint256[2] internal pC = [
        16510715908193970019001884229889098001892185354171190596275793801905905147475,
        7976949711549427312820191277330775824544179788110363428593525979441454006206
    ];

    function setUp() public {
        token = new TestToken();
        verifier = new Tidex6Verifier();
        pool = new Tidex6Pool(IERC20(address(token)), verifier, DENOMINATION);

        token.mint(depositor, DENOMINATION * 10);
        vm.prank(depositor);
        token.approve(address(pool), type(uint256).max);
    }

    /// The test that decides everything: after one deposit, the root the
    /// contract computed must equal the root the Rust client computed for the
    /// same commitment. Disagreement means locked deposits.
    function test_rootMatchesRust() public {
        vm.prank(depositor);
        pool.deposit(COMMITMENT);

        assertEq(
            pool.currentRoot(),
            EXPECTED_ROOT,
            "Solidity tree root disagrees with the Rust client"
        );
    }

    /// End to end: deposit, then withdraw with a real proof.
    function test_depositThenWithdraw() public {
        vm.prank(depositor);
        pool.deposit(COMMITMENT);

        uint256 recipientBefore = token.balanceOf(recipient);
        uint256 relayerBefore = token.balanceOf(relayer);

        pool.withdraw(pA, pB, pC, EXPECTED_ROOT, NULLIFIER_HASH, recipient, relayer, FEE);

        assertEq(
            token.balanceOf(recipient) - recipientBefore,
            DENOMINATION - FEE,
            "recipient did not receive the denomination minus fee"
        );
        assertEq(
            token.balanceOf(relayer) - relayerBefore,
            FEE,
            "relayer did not receive the fee"
        );
        assertTrue(pool.nullifierSpent(NULLIFIER_HASH), "nullifier not marked spent");
    }

    /// The double-spend guard. Spending the same note twice must fail.
    function test_rejectsDoubleSpend() public {
        vm.prank(depositor);
        pool.deposit(COMMITMENT);

        pool.withdraw(pA, pB, pC, EXPECTED_ROOT, NULLIFIER_HASH, recipient, relayer, FEE);

        vm.expectRevert(Tidex6Pool.NullifierAlreadySpent.selector);
        pool.withdraw(pA, pB, pC, EXPECTED_ROOT, NULLIFIER_HASH, recipient, relayer, FEE);
    }

    /// A relayer must not be able to redirect the payment to itself: the
    /// recipient is a public input, so changing it invalidates the proof.
    function test_rejectsRedirectedRecipient() public {
        vm.prank(depositor);
        pool.deposit(COMMITMENT);

        address thief = address(0xBAD);
        vm.expectRevert(Tidex6Pool.InvalidProof.selector);
        pool.withdraw(pA, pB, pC, EXPECTED_ROOT, NULLIFIER_HASH, thief, relayer, FEE);
    }

    /// Nor raise its own fee, for the same reason.
    function test_rejectsRaisedFee() public {
        vm.prank(depositor);
        pool.deposit(COMMITMENT);

        vm.expectRevert(Tidex6Pool.InvalidProof.selector);
        pool.withdraw(pA, pB, pC, EXPECTED_ROOT, NULLIFIER_HASH, recipient, relayer, FEE + 1);
    }

    /// A root the pool never produced must not authorise anything.
    function test_rejectsUnknownRoot() public {
        vm.prank(depositor);
        pool.deposit(COMMITMENT);

        vm.expectRevert(Tidex6Pool.RootNotRecent.selector);
        pool.withdraw(pA, pB, pC, EXPECTED_ROOT + 1, NULLIFIER_HASH, recipient, relayer, FEE);
    }

    /// Zero is what an empty ring slot holds; it must never count as a root.
    function test_rejectsZeroRoot() public {
        assertFalse(pool.isKnownRoot(0), "zero must not be a known root");
    }

    /// The same commitment twice would give the depositor two notes they
    /// cannot tell apart.
    function test_rejectsRepeatedCommitment() public {
        vm.startPrank(depositor);
        pool.deposit(COMMITMENT);
        vm.expectRevert(Tidex6Pool.CommitmentAlreadyUsed.selector);
        pool.deposit(COMMITMENT);
        vm.stopPrank();
    }
}
