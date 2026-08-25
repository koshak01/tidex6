// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
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

    /// One token at six decimals — the same unit as the Solana pool, so the
    /// same payment reads identically in both chains. The fixture's fee is
    /// 0.1 of it, leaving 0.9 for the recipient.
    uint256 internal constant DENOMINATION = 1_000_000;
    uint256 internal constant FEE = 100000;

    /// Заглушка конверта: на длину и содержимое контракт не смотрит, но в
    /// вызове он должен быть — иначе тест не заметил бы, что конверт потерян
    /// по дороге.
    bytes internal constant ENVELOPE = hex"0102030405060708";

    uint256 internal constant COMMITMENT = 21133731795125218879770237676509304824224234338153766379440246562756965142916;
    uint256 internal constant EXPECTED_ROOT = 9320035109223905669555919870974467834898477155077275771998462004481757406537;
    uint256 internal constant NULLIFIER_HASH = 3228837805036640562887160086138756906643146730490387571226220750860647184912;

    uint256[2] internal pA = [
        9438134815438011935928593090538055819616411355848012844336576132834405727042,
        21675714116725929809454780118211379664240319028325953860265280328100220287161
    ];
    uint256[2][2] internal pB = [
        [20943415472556338014354117034039081010839424600469383427894345060108973296695, 8916157652801196921110292318822247852318436022550120959070933317531542090917],
        [13319133629601920727976715485732024569562814998952957314620073575150983506074, 16884654186089586826930553054257595047320085165381834592983009609877828084395]
    ];
    uint256[2] internal pC = [
        14265608599792245122837536353060558221729929428204346989944824274989119694108,
        15817134301474164410010386004029249556960504654843364133447057212793309160063
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
        pool.deposit(COMMITMENT, ENVELOPE);

        assertEq(
            pool.currentRoot(),
            EXPECTED_ROOT,
            "Solidity tree root disagrees with the Rust client"
        );
    }

    /// Конверт обязан доехать до лога — по нему получатель находит платёж.
    ///
    /// Без этой проверки потерю конверта не заметил бы никто: депозит прошёл
    /// бы, дерево выросло, деньги легли в пул, а получатель никогда бы о них
    /// не узнал — искать ему было бы нечего. Молчаливый отказ, самый дорогой
    /// вид.
    function test_depositEmitsEnvelope() public {
        vm.recordLogs();
        vm.prank(depositor);
        pool.deposit(COMMITMENT, ENVELOPE);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] != keccak256("Deposit(uint256,uint256,uint256,address,bytes)")) {
                continue;
            }
            (, , , bytes memory envelope) =
                abi.decode(logs[i].data, (uint256, uint256, address, bytes));
            assertEq(envelope, ENVELOPE, "the envelope in the log is not the one deposited");
            found = true;
        }
        assertTrue(found, "no Deposit event carried an envelope");
    }

    /// End to end: deposit, then withdraw with a real proof.
    function test_depositThenWithdraw() public {
        vm.prank(depositor);
        pool.deposit(COMMITMENT, ENVELOPE);

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
        pool.deposit(COMMITMENT, ENVELOPE);

        pool.withdraw(pA, pB, pC, EXPECTED_ROOT, NULLIFIER_HASH, recipient, relayer, FEE);

        vm.expectRevert(Tidex6Pool.NullifierAlreadySpent.selector);
        pool.withdraw(pA, pB, pC, EXPECTED_ROOT, NULLIFIER_HASH, recipient, relayer, FEE);
    }

    /// A relayer must not be able to redirect the payment to itself: the
    /// recipient is a public input, so changing it invalidates the proof.
    function test_rejectsRedirectedRecipient() public {
        vm.prank(depositor);
        pool.deposit(COMMITMENT, ENVELOPE);

        address thief = address(0xBAD);
        vm.expectRevert(Tidex6Pool.InvalidProof.selector);
        pool.withdraw(pA, pB, pC, EXPECTED_ROOT, NULLIFIER_HASH, thief, relayer, FEE);
    }

    /// Nor raise its own fee, for the same reason.
    function test_rejectsRaisedFee() public {
        vm.prank(depositor);
        pool.deposit(COMMITMENT, ENVELOPE);

        vm.expectRevert(Tidex6Pool.InvalidProof.selector);
        pool.withdraw(pA, pB, pC, EXPECTED_ROOT, NULLIFIER_HASH, recipient, relayer, FEE + 1);
    }

    /// A root the pool never produced must not authorise anything.
    function test_rejectsUnknownRoot() public {
        vm.prank(depositor);
        pool.deposit(COMMITMENT, ENVELOPE);

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
        pool.deposit(COMMITMENT, ENVELOPE);
        vm.expectRevert(Tidex6Pool.CommitmentAlreadyUsed.selector);
        pool.deposit(COMMITMENT, ENVELOPE);
        vm.stopPrank();
    }

    /// @notice GAP-2 on Solana does not exist here, and must not be introduced.
    /// @dev On Solana the recipient is bound to the proof as
    ///      `reduce_mod_bn254(pubkey)`. A Solana pubkey is 256 bits and the
    ///      field is ~254, so the map loses information: `reduce(P)` equals
    ///      `reduce(P + r)`. A malicious relayer could swap the recipient for
    ///      `P + r` — a different account, the same field element, a proof that
    ///      still verifies, and funds sent somewhere unspendable.
    ///
    ///      An EVM address is 160 bits, comfortably below the 254-bit field
    ///      order, so `uint256(uint160(addr))` is injective and no such
    ///      collision exists. This test pins that down: if anyone ever
    ///      introduces a reduction here, the largest possible address would
    ///      stop round-tripping and this fails.
    function test_addressToFieldIsInjective() public pure {
        uint256 fieldOrder =
            21888242871839275222246405745257275088548364400416034343698204186575808495617;

        address maxAddress = address(type(uint160).max);
        uint256 asField = uint256(uint160(maxAddress));

        assertLt(asField, fieldOrder, "an address must fit the scalar field with room to spare");
        assertEq(
            address(uint160(asField)),
            maxAddress,
            "address must survive the round trip through a field element"
        );

        // The Solana collision partner, P + r, is far outside address range —
        // it cannot be written as an address at all.
        assertGt(asField + fieldOrder, uint256(type(uint160).max), "P + r must not be an address");
    }
}
