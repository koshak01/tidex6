// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PoseidonT3} from "./PoseidonT3.sol";
import {IWithdrawVerifierV2, ITransferVerifierV2} from "./Tidex6HiddenPoolV2.sol";

/// @notice Groth16 verifier of the withdraw-to-token circuit (eight public inputs).
interface ITokenExitVerifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[8] calldata publicInputs
    ) external view returns (bool);
}

/// @notice What the pool needs from the confidential token that holds its
///         custody.
interface IConfidentialTokenCustody {
    /// Pay `amount` of the underlying ERC-20 to `to`.
    function payOut(address to, uint256 amount) external;

    /// Add a ciphertext to the pending balance registered under `recipientKey`.
    function creditPending(
        uint256[2] calldata recipientKey,
        uint256[2] calldata commitment,
        uint256[2] calldata handle
    ) external;
}

/// @title Shielded pool v2 for a confidential token (ADR-023)
/// @notice The note format, tree, nullifiers, fee policy and in-pool transfer
///         are those of `Tidex6HiddenPoolV2` (ADR-022). What differs is where
///         the money lives and how it gets in and out.
///
///         **Custody is the token's.** This pool holds no ERC-20. Every unit of
///         the underlying token sits in the confidential token contract and
///         backs, at once, the encrypted balances there and the notes here.
///         That is what lets value cross between the two without a number: a
///         deposit from an encrypted balance moves no ERC-20, so there is no
///         transfer amount for anyone to read.
///
///         Ways in and out:
///
///         - `depositFromToken` — called by the token after it verified a
///           `DepositFromToken` proof and debited the sender's ciphertext. The
///           proof already fixed both leaves (payment and fee, ADR-022 layout)
///           and the fee policy against this pool's treasury key and floor.
///         - `withdrawToToken` — a note's owner proves `WithdrawToToken`; the
///           note is spent and its amount lands as a ciphertext on the
///           recipient's pending balance. No number.
///         - `withdraw` — the owner proves `withdraw_v2`; the token pays the
///           public amount in the open ERC-20, as the plain v2 pool does.
///         - `transferNote` — the v2 forward inside the pool, unchanged.
///
///         There is no `refund`: a refund rebuilds the leaf from a public
///         amount, and notes here never had one. A note's owner can still
///         spend it any time.
///
/// @dev Amounts are in the token's own units, the same `uint64` the
///      confidential balances use; the token wraps 6-decimal ERC-20s.
contract Tidex6TokenPoolV2 {
    uint256 public constant TREE_DEPTH = 20;
    uint256 public constant ROOT_RING_SIZE = 30;
    uint256 public constant MAX_AMOUNT = type(uint64).max;

    uint256 internal constant F =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IConfidentialTokenCustody public immutable token;
    IWithdrawVerifierV2 public immutable withdrawVerifier;
    ITransferVerifierV2 public immutable transferVerifier;
    ITokenExitVerifier public immutable exitVerifier;
    /// Owner key of the treasury: every fee note is filed for it.
    uint256 public immutable treasuryOwnerPk;
    /// Smallest fee, in token units.
    uint256 public immutable feeFloor;

    uint256 public nextLeafIndex;
    uint256 public rootRingHead;
    uint256[TREE_DEPTH] public filledSubtrees;
    uint256[TREE_DEPTH] public zeroSubtrees;
    uint256[ROOT_RING_SIZE] public rootHistory;

    /// Spent nullifiers — one guard for all three spending paths.
    mapping(uint256 => bool) public nullifierSpent;

    /// Leaf position plus one, by leaf value; zero — not in the tree.
    mapping(uint256 => uint256) public leafPositionPlusOne;

    /// @notice A note was funded from an encrypted balance. No amount.
    event DepositFromToken(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, bytes envelope);

    /// @notice A note was created by a join-split.
    event NoteCreated(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, bytes envelope);

    /// @notice A note left the pool to `recipient` in the open ERC-20.
    event Withdrawal(
        uint256 indexed nullifier, address indexed recipient, address relayer, uint256 fee, uint256 amount
    );

    /// @notice A note left the pool as a ciphertext; the token keeps the
    ///         recipient's key, so nothing here names them.
    event WithdrawalToToken(uint256 indexed nullifier);

    error NotAFieldElement();
    error CommitmentAlreadyUsed();
    error TreeFull();
    error RootNotRecent();
    error NullifierAlreadySpent();
    error InvalidProof();
    error FeeExceedsAmount();
    error OnlyToken();

    /// @notice The three notes an in-pool transfer creates, with their envelopes.
    struct TransferOutputs {
        uint256 pay;
        uint256 change;
        uint256 fee;
        bytes payEnvelope;
        bytes changeEnvelope;
        bytes feeEnvelope;
    }

    /// @notice A withdraw-to-token request: the circuit's public inputs past
    ///         root and nullifier, as `(x, y)` pairs.
    struct TokenCredit {
        uint256[2] recipientKey;
        uint256[2] commitment;
        uint256[2] handle;
    }

    constructor(
        IConfidentialTokenCustody token_,
        IWithdrawVerifierV2 withdrawVerifier_,
        ITransferVerifierV2 transferVerifier_,
        ITokenExitVerifier exitVerifier_,
        uint256 treasuryOwnerPk_,
        uint256 feeFloor_
    ) {
        if (treasuryOwnerPk_ >= F) revert NotAFieldElement();
        token = token_;
        withdrawVerifier = withdrawVerifier_;
        transferVerifier = transferVerifier_;
        exitVerifier = exitVerifier_;
        treasuryOwnerPk = treasuryOwnerPk_;
        feeFloor = feeFloor_;

        uint256 zeroHash = 0;
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            zeroSubtrees[level] = zeroHash;
            filledSubtrees[level] = zeroHash;
            zeroHash = PoseidonT3.hash(zeroHash, zeroHash);
        }
        rootHistory[0] = zeroHash;
    }

    /// @notice File the payment and fee notes of a deposit from an encrypted
    ///         balance. Token only: the token verified the proof that binds both
    ///         leaves to the debited ciphertext and the fee to this pool's
    ///         treasury key and floor, which it read from here.
    function depositFromToken(
        uint256 commitmentPay,
        uint256 commitmentFee,
        bytes calldata payEnvelope,
        bytes calldata feeEnvelope
    ) external {
        if (msg.sender != address(token)) revert OnlyToken();
        uint256 firstLeaf = _reserveLeaves(2);
        _markLeaf(commitmentPay, firstLeaf);
        _markLeaf(commitmentFee, firstLeaf + 1);
        emit DepositFromToken(commitmentPay, firstLeaf, _appendLeaf(firstLeaf, commitmentPay), payEnvelope);
        emit DepositFromToken(commitmentFee, firstLeaf + 1, _appendLeaf(firstLeaf + 1, commitmentFee), feeEnvelope);
    }

    /// @notice Forward a note inside the pool (`transfer_v2`), exactly as in
    ///         `Tidex6HiddenPoolV2.transferNote`. No token moves.
    function transferNote(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256 merkleRoot,
        uint256 nullifier,
        TransferOutputs calldata out
    ) external {
        if (nullifierSpent[nullifier]) revert NullifierAlreadySpent();
        if (!_isKnownRoot(merkleRoot)) revert RootNotRecent();
        uint256 firstLeaf = _reserveLeaves(3);
        _markLeaf(out.pay, firstLeaf);
        _markLeaf(out.change, firstLeaf + 1);
        _markLeaf(out.fee, firstLeaf + 2);

        uint256[7] memory publicInputs =
            [merkleRoot, nullifier, out.pay, out.change, out.fee, treasuryOwnerPk, feeFloor];
        if (!transferVerifier.verifyProof(proofA, proofB, proofC, publicInputs)) revert InvalidProof();

        nullifierSpent[nullifier] = true;

        emit NoteCreated(out.pay, firstLeaf, _appendLeaf(firstLeaf, out.pay), out.payEnvelope);
        emit NoteCreated(out.change, firstLeaf + 1, _appendLeaf(firstLeaf + 1, out.change), out.changeEnvelope);
        emit NoteCreated(out.fee, firstLeaf + 2, _appendLeaf(firstLeaf + 2, out.fee), out.feeEnvelope);
    }

    /// @notice Spend a note onto an encrypted balance. Only the note's owner
    ///         can build the proof; the ciphertext is bound to the recipient's
    ///         key by it, so a relayer may submit without being able to
    ///         redirect.
    function withdrawToToken(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256 merkleRoot,
        uint256 nullifier,
        TokenCredit calldata credit
    ) external {
        if (nullifierSpent[nullifier]) revert NullifierAlreadySpent();
        if (!_isKnownRoot(merkleRoot)) revert RootNotRecent();

        uint256[8] memory publicInputs = [
            merkleRoot,
            nullifier,
            credit.recipientKey[0],
            credit.recipientKey[1],
            credit.commitment[0],
            credit.commitment[1],
            credit.handle[0],
            credit.handle[1]
        ];
        if (!exitVerifier.verifyProof(proofA, proofB, proofC, publicInputs)) revert InvalidProof();

        nullifierSpent[nullifier] = true;
        token.creditPending(credit.recipientKey, credit.commitment, credit.handle);
        emit WithdrawalToToken(nullifier);
    }

    /// @notice Withdraw a note to `recipient` in the open ERC-20 (`withdraw_v2`).
    ///         The token pays from the custody it holds for the pool.
    function withdraw(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256 merkleRoot,
        uint256 nullifier,
        address recipient,
        address relayer,
        uint256 fee,
        uint256 amount
    ) external {
        if (nullifierSpent[nullifier]) revert NullifierAlreadySpent();
        if (fee > amount) revert FeeExceedsAmount();
        if (!_isKnownRoot(merkleRoot)) revert RootNotRecent();

        (uint256 recipientHi, uint256 recipientLo) = _splitAddress(recipient);
        (uint256 relayerHi, uint256 relayerLo) = _splitAddress(relayer);
        uint256[8] memory publicInputs =
            [merkleRoot, nullifier, recipientHi, recipientLo, relayerHi, relayerLo, fee, amount];
        if (!withdrawVerifier.verifyProof(proofA, proofB, proofC, publicInputs)) revert InvalidProof();

        nullifierSpent[nullifier] = true;

        token.payOut(recipient, amount - fee);
        if (fee > 0) token.payOut(relayer, fee);
        emit Withdrawal(nullifier, recipient, relayer, fee, amount);
    }

    function currentRoot() external view returns (uint256) {
        return rootHistory[rootRingHead];
    }

    function isKnownRoot(uint256 root) external view returns (bool) {
        return _isKnownRoot(root);
    }

    function _splitAddress(address value) private pure returns (uint256 hi, uint256 lo) {
        uint256 word = uint256(uint160(value));
        hi = word >> 128;
        lo = word & type(uint128).max;
    }

    /// First of `count` free positions. `_appendLeaf` advances the index.
    function _reserveLeaves(uint256 count) private view returns (uint256 leafIndex) {
        leafIndex = nextLeafIndex;
        if (leafIndex + count > (1 << TREE_DEPTH)) revert TreeFull();
    }

    /// Record that `leaf` sits at `position`. A leaf already in the tree is
    /// refused — two equal outputs of one call included.
    function _markLeaf(uint256 leaf, uint256 position) private {
        if (leaf >= F) revert NotAFieldElement();
        if (leafPositionPlusOne[leaf] != 0) revert CommitmentAlreadyUsed();
        leafPositionPlusOne[leaf] = position + 1;
    }

    function _appendLeaf(uint256 leafIndex, uint256 leaf) private returns (uint256) {
        uint256 currentIndex = leafIndex;
        uint256 currentHash = leaf;
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            uint256 left;
            uint256 right;
            if (currentIndex & 1 == 0) {
                filledSubtrees[level] = currentHash;
                left = currentHash;
                right = zeroSubtrees[level];
            } else {
                left = filledSubtrees[level];
                right = currentHash;
            }
            currentHash = PoseidonT3.hash(left, right);
            currentIndex >>= 1;
        }
        nextLeafIndex = leafIndex + 1;
        rootRingHead = (rootRingHead + 1) % ROOT_RING_SIZE;
        rootHistory[rootRingHead] = currentHash;
        return currentHash;
    }

    function _isKnownRoot(uint256 root) private view returns (bool) {
        if (root == 0) return false;
        for (uint256 i = 0; i < ROOT_RING_SIZE; i++) {
            if (rootHistory[i] == root) return true;
        }
        return false;
    }
}
