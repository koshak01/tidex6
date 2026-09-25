// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PoseidonT3} from "./PoseidonT3.sol";

/// @notice Groth16 verifier of the v2 withdraw circuit (eight public inputs).
interface IWithdrawVerifierV2 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[8] calldata publicInputs
    ) external view returns (bool);
}

/// @notice Groth16 verifier of the v2 in-pool transfer (seven public inputs).
interface ITransferVerifierV2 {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[7] calldata publicInputs
    ) external view returns (bool);
}

/// @notice Minimal ERC-20 surface the pool needs.
interface IERC20V2 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Hidden-amount shielded pool, note format v2 (ADR-022)
/// @notice Two properties the v1 pool lacked, both by construction:
///
///         - **The pool computes the leaf.** A depositor hands in the note's
///           `core` (whose it is, and its randomness) together with the tokens;
///           the pool binds `core` to the amount it actually received. A note
///           cannot claim more than was paid into it.
///         - **Only the owner spends.** The withdraw circuit proves knowledge
///           of the owner's spending key. Whoever funded the note can take it
///           back only through `refund`, only after the window they chose, and
///           only if the owner has not spent it first — one note, one
///           nullifier, whichever path comes first. Fee notes have no refund.
///         - **The fee cannot be skipped.** Every way value enters or moves
///           pays 1% (rounded up, at least `feeFloor`) as a note the pool
///           itself files for the treasury key it was deployed with: a
///           deposit here, a forward inside the pool through the circuit.
///
///         Leaf layout, two-input Poseidon throughout:
///
///           core   = H(H(D_CORE, ownerPk), H(rho, aux))     (client)
///           body   = H(core, amount)                        (pool)
///           refund = H(funder, refundAfter)  or 0           (pool)
///           leaf   = H(body, refund)
///           nf     = H(H(D_NF, rho), position)
///
/// @dev Multichain, not cross-chain: deposits made here are withdrawn here.
contract Tidex6HiddenPoolV2 {
    uint256 public constant TREE_DEPTH = 20;
    uint256 public constant ROOT_RING_SIZE = 30;
    uint256 public constant MAX_AMOUNT = type(uint64).max;

    /// Refund windows a depositor may choose: five minutes to thirty days,
    /// the same range the Solana program accepts. Zero means no refund.
    uint256 public constant MIN_REFUND_WINDOW = 5 minutes;
    uint256 public constant MAX_REFUND_WINDOW = 30 days;

    /// Hash domains — the same constants as `tidex6-confidential::note_v2`.
    uint256 public constant D_CORE = 0x746964783602;
    uint256 public constant D_NF = 0x746964783603;

    uint256 internal constant F =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// The fee: 1% of the payment, rounded up, never below `feeFloor`.
    uint256 public constant FEE_PERCENT_DIVISOR = 100;

    IERC20V2 public immutable token;
    IWithdrawVerifierV2 public immutable withdrawVerifier;
    ITransferVerifierV2 public immutable transferVerifier;
    /// Owner key of the treasury: every fee note is filed for it.
    uint256 public immutable treasuryOwnerPk;
    /// Smallest fee in base units — 0.1 token at the token's decimals.
    uint256 public immutable feeFloor;

    uint256 public nextLeafIndex;
    uint256 public rootRingHead;
    uint256[TREE_DEPTH] public filledSubtrees;
    uint256[TREE_DEPTH] public zeroSubtrees;
    uint256[ROOT_RING_SIZE] public rootHistory;

    /// Spent nullifiers — the double-spend guard for both spending paths.
    mapping(uint256 => bool) public nullifierSpent;

    /// Leaf position plus one, by leaf value; zero means "not in the tree".
    /// Replaces v1's `commitmentKnown`: a refund has to find the position its
    /// nullifier is derived from.
    mapping(uint256 => uint256) public leafPositionPlusOne;

    /// @notice A note was funded from outside the pool.
    /// @param refundAfter When the funder may take it back; 0 — never.
    event Deposit(
        uint256 indexed commitment,
        uint256 leafIndex,
        uint256 newRoot,
        address depositor,
        uint256 amount,
        uint256 refundAfter,
        bytes envelope
    );

    /// @notice A note was created by a join-split.
    event NoteCreated(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, bytes envelope);

    /// @notice A note left the pool to `recipient`.
    event Withdrawal(
        uint256 indexed nullifier, address indexed recipient, address relayer, uint256 fee, uint256 amount
    );

    /// @notice A note went back to the address that funded it.
    event Refunded(uint256 indexed nullifier, address indexed funder, uint256 amount);

    error NotAFieldElement();
    error CommitmentAlreadyUsed();
    error TreeFull();
    error RootNotRecent();
    error NullifierAlreadySpent();
    error InvalidProof();
    error AmountOutOfRange();
    error FeeExceedsAmount();
    error TransferFailed();
    error RefundWindowOutOfRange();
    error UnknownNote();
    error RefundNotYet();

    /// @notice The three notes an in-pool transfer creates, with their envelopes.
    struct TransferOutputs {
        uint256 pay;
        uint256 change;
        uint256 fee;
        bytes payEnvelope;
        bytes changeEnvelope;
        bytes feeEnvelope;
    }

    constructor(
        IERC20V2 token_,
        IWithdrawVerifierV2 withdrawVerifier_,
        ITransferVerifierV2 transferVerifier_,
        uint256 treasuryOwnerPk_,
        uint256 feeFloor_
    ) {
        if (treasuryOwnerPk_ >= F) revert NotAFieldElement();
        token = token_;
        withdrawVerifier = withdrawVerifier_;
        transferVerifier = transferVerifier_;
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

    /// @notice Fund a note of `amount` base units for the owner of `core`, and
    ///         the fee on it for the treasury. The sender is charged
    ///         `amount + feeFor(amount)`.
    /// @param core H(H(D_CORE, ownerPk), H(rho, aux)), computed by the sender.
    /// @param amount Base units the recipient gets; the leaf is bound to it.
    /// @param refundWindow Seconds after which the sender may take the payment
    ///        back if the owner has not; 0 — no refund.
    /// @param envelope Sealed for the recipient.
    /// @param feeRho Randomness of the fee note; the pool builds its core
    ///        from the treasury key, so it can belong to nobody else.
    /// @param feeEnvelope Sealed for the treasury's reader key.
    function deposit(
        uint256 core,
        uint256 amount,
        uint256 refundWindow,
        bytes calldata envelope,
        uint256 feeRho,
        bytes calldata feeEnvelope
    ) external {
        if (feeRho >= F) revert NotAFieldElement();
        uint256 fee = feeFor(amount);
        uint256 firstLeaf = _reserveLeaves(2);
        _fileNote(core, amount, _refundAfter(refundWindow), envelope, firstLeaf);
        _fileNote(_treasuryCore(feeRho), fee, 0, feeEnvelope, firstLeaf + 1);
        // Pulled last, after the tree is final: a token that calls back on
        // transfer cannot re-enter and overwrite a reserved leaf.
        if (!token.transferFrom(msg.sender, address(this), amount + fee)) revert TransferFailed();
    }

    /// @notice The fee on a payment of `amount`: 1% rounded up, at least `feeFloor`.
    function feeFor(uint256 amount) public view returns (uint256) {
        uint256 percent = (amount + FEE_PERCENT_DIVISOR - 1) / FEE_PERCENT_DIVISOR;
        return percent > feeFloor ? percent : feeFloor;
    }

    /// @notice Forward a note inside the pool: a payment, change back to the
    ///         spender, and the fee to the treasury (`transfer_v2`). The
    ///         circuit checks the fee against the pool's own treasury key and
    ///         floor, which the pool supplies as public inputs. No token moves.
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

    /// @notice Withdraw a note to `recipient`. Only the owner can build the
    ///         proof; recipient, relayer, fee and amount are bound by it.
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

        if (!token.transfer(recipient, amount - fee)) revert TransferFailed();
        if (fee > 0) {
            if (!token.transfer(relayer, fee)) revert TransferFailed();
        }
        emit Withdrawal(nullifier, recipient, relayer, fee, amount);
    }

    /// @notice Take a note back after its refund window, if its owner has not
    ///         spent it. No proof: the funder knows the note's parts, and the
    ///         pool checks them against the leaf it computed at deposit, with
    ///         `msg.sender` in the funder's place — nobody else can match it.
    function refund(uint256 ownerPk, uint256 rho, uint256 aux, uint256 amount, uint256 refundAfter)
        external
    {
        if (refundAfter == 0 || block.timestamp < refundAfter) revert RefundNotYet();
        uint256 core = PoseidonT3.hash(PoseidonT3.hash(D_CORE, ownerPk), PoseidonT3.hash(rho, aux));
        uint256 leaf = _leaf(core, amount, refundAfter);
        uint256 positionPlusOne = leafPositionPlusOne[leaf];
        if (positionPlusOne == 0) revert UnknownNote();

        uint256 nullifier = PoseidonT3.hash(PoseidonT3.hash(D_NF, rho), positionPlusOne - 1);
        if (nullifierSpent[nullifier]) revert NullifierAlreadySpent();
        nullifierSpent[nullifier] = true;

        if (!token.transfer(msg.sender, amount)) revert TransferFailed();
        emit Refunded(nullifier, msg.sender, amount);
    }

    function currentRoot() external view returns (uint256) {
        return rootHistory[rootRingHead];
    }

    function isKnownRoot(uint256 root) external view returns (bool) {
        return _isKnownRoot(root);
    }

    /// File one funded note at `position`: compute its leaf from the amount,
    /// record the position, insert it and log the deposit.
    function _fileNote(
        uint256 core,
        uint256 amount,
        uint256 refundAfter,
        bytes calldata envelope,
        uint256 position
    ) private {
        uint256 leaf = _leaf(core, amount, refundAfter);
        _markLeaf(leaf, position);
        uint256 newRoot = _appendLeaf(position, leaf);
        emit Deposit(leaf, position, newRoot, msg.sender, amount, refundAfter, envelope);
    }

    /// The leaf the pool files for `core` funded with `amount` by `msg.sender`.
    function _leaf(uint256 core, uint256 amount, uint256 refundAfter) private view returns (uint256) {
        if (core >= F) revert NotAFieldElement();
        if (amount == 0 || amount > MAX_AMOUNT) revert AmountOutOfRange();
        uint256 body = PoseidonT3.hash(core, amount);
        uint256 refundTag = refundAfter == 0 ? 0 : PoseidonT3.hash(uint256(uint160(msg.sender)), refundAfter);
        return PoseidonT3.hash(body, refundTag);
    }

    /// Core of a fee note: owned by the treasury, randomness from the sender.
    function _treasuryCore(uint256 feeRho) private view returns (uint256) {
        return PoseidonT3.hash(PoseidonT3.hash(D_CORE, treasuryOwnerPk), PoseidonT3.hash(feeRho, 0));
    }

    function _refundAfter(uint256 refundWindow) private view returns (uint256) {
        if (refundWindow == 0) return 0;
        if (refundWindow < MIN_REFUND_WINDOW || refundWindow > MAX_REFUND_WINDOW) {
            revert RefundWindowOutOfRange();
        }
        return block.timestamp + refundWindow;
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
