// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PoseidonT3} from "./PoseidonT3.sol";
import {Tidex6HiddenWithdrawVerifier} from "./Tidex6HiddenWithdrawVerifier.sol";
import {Tidex6HiddenTransferVerifier} from "./Tidex6HiddenTransferVerifier.sol";

/// @notice Minimal ERC-20 surface the pool needs.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Hidden-amount shielded pool for a single ERC-20
/// @notice Notes of any size. The amount lives inside the commitment,
///         `Poseidon(secret, nullifier, amount)`, and the circuits prove it is
///         in range — so the chain never learns how much a note is worth, only
///         that a note exists. Three operations:
///
///         - `deposit`: fund a note. The amount is visible here, because an
///           ERC-20 transfer is; this is the pool's only public number on the
///           way in.
///         - `transferNote`: spend one note into two new ones (join-split). No
///           token moves, no amount appears — a payment inside the pool is two
///           opaque commitments and one nullifier.
///         - `withdraw`: leave the pool. The amount is public here, because
///           the pool has to know how much to pay out.
///
///         This mirrors the Solana program (`programs/tidex6-confidential-pool`)
///         deliberately: same tree depth, same root ring, same Poseidon, same
///         public inputs in the same order. The circuits are
///         `tidex6-confidential::withdraw` (eight inputs) and
///         `tidex6-confidential::transfer` (four).
///
/// @dev Multichain, not cross-chain. This pool knows nothing about any other
///      chain's state and must never be taught to: deposits made here are
///      withdrawn here.
///
/// @dev Recipient and relayer are bound as two 128-bit halves of the 32-byte
///      word the circuit takes — the same split the Solana program uses for a
///      32-byte pubkey, so one circuit serves both chains. An address is 160
///      bits: the high half carries its top 32 bits, the low half the other
///      128. Both halves are far below the field order, so the binding is
///      injective. Never introduce a reduction on this path.
contract Tidex6HiddenPool {
    /// Depth of the incremental tree. Fixed at compile time in the circuits.
    uint256 public constant TREE_DEPTH = 20;

    /// How many past roots stay acceptable. A proof built against a root that
    /// was current when the user started is still valid a few insertions
    /// later — without this, every concurrent insertion would invalidate
    /// in-flight spends.
    uint256 public constant ROOT_RING_SIZE = 30;

    /// Largest note the circuits accept: the range proof covers 64 bits.
    uint256 public constant MAX_AMOUNT = type(uint64).max;

    /// BN254 scalar field modulus. Every field element must be below it.
    uint256 internal constant F =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// The token this pool holds.
    IERC20 public immutable token;

    /// Groth16 verifier for the hidden-amount withdraw circuit (8 inputs).
    Tidex6HiddenWithdrawVerifier public immutable withdrawVerifier;

    /// Groth16 verifier for the join-split circuit (4 inputs).
    Tidex6HiddenTransferVerifier public immutable transferVerifier;

    /// Next free leaf.
    uint256 public nextLeafIndex;

    /// Head of the root ring.
    uint256 public rootRingHead;

    /// Right-most filled node per level, for incremental insertion.
    uint256[TREE_DEPTH] public filledSubtrees;

    /// Hash of an empty subtree per level.
    uint256[TREE_DEPTH] public zeroSubtrees;

    /// Recent roots, oldest overwritten.
    uint256[ROOT_RING_SIZE] public rootHistory;

    /// Spent nullifiers. The double-spend guard.
    mapping(uint256 => bool) public nullifierSpent;

    /// Commitments already in the tree, so an accidental repeat is rejected
    /// rather than creating a note the owner cannot distinguish.
    mapping(uint256 => bool) public commitmentKnown;

    /// @notice A note was funded from outside the pool.
    /// @param amount Base units moved into the pool — public because the
    ///        ERC-20 transfer that carried them is.
    /// @param envelope The sealed envelope for the recipient — opaque to the
    ///        chain, meaningful only to whoever holds the key it was sealed
    ///        for. Carried in the log rather than storage: a log byte costs 8
    ///        gas against 20 000 for a storage slot, and nothing on chain ever
    ///        needs to read this back.
    event Deposit(
        uint256 indexed commitment,
        uint256 leafIndex,
        uint256 newRoot,
        address depositor,
        uint256 amount,
        bytes envelope
    );

    /// @notice A note was created by a join-split. No amount, no depositor:
    ///         there is nothing public about it except its place in the tree.
    event NoteCreated(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, bytes envelope);

    /// @notice A note was spent by a join-split.
    event NoteSpent(uint256 indexed nullifierHash);

    /// @notice A note left the pool.
    event Withdrawal(
        uint256 indexed nullifierHash,
        address indexed recipient,
        address relayer,
        uint256 fee,
        uint256 amount
    );

    error NotAFieldElement();
    error CommitmentAlreadyUsed();
    error SameCommitment();
    error TreeFull();
    error RootNotRecent();
    error NullifierAlreadySpent();
    error InvalidProof();
    error AmountOutOfRange();
    error FeeExceedsAmount();
    error TransferFailed();

    /// @param token_ ERC-20 held by this pool.
    /// @param withdrawVerifier_ Groth16 verifier for the withdraw circuit.
    /// @param transferVerifier_ Groth16 verifier for the join-split circuit.
    constructor(
        IERC20 token_,
        Tidex6HiddenWithdrawVerifier withdrawVerifier_,
        Tidex6HiddenTransferVerifier transferVerifier_
    ) {
        token = token_;
        withdrawVerifier = withdrawVerifier_;
        transferVerifier = transferVerifier_;

        // Empty-subtree hashes, level by level, exactly as the Solana program
        // computes them at initialisation.
        uint256 zeroHash = 0;
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            zeroSubtrees[level] = zeroHash;
            filledSubtrees[level] = zeroHash;
            zeroHash = PoseidonT3.hash(zeroHash, zeroHash);
        }
        rootHistory[0] = zeroHash;
    }

    /// @notice Fund a note of `amount` base units.
    /// @param amount Base units moved into the pool; must fit the circuit's
    ///        64-bit range.
    /// @param commitment Poseidon(secret, nullifier, amount), computed by the
    ///        client. The pool cannot check it and does not need to — a
    ///        commitment that does not match its amount is a note nobody can
    ///        ever withdraw.
    /// @param envelope The sealed envelope for the recipient, produced in the
    ///        sender's browser before anything left it.
    function deposit(uint256 amount, uint256 commitment, bytes calldata envelope) external {
        if (amount == 0 || amount > MAX_AMOUNT) revert AmountOutOfRange();
        uint256 leafIndex = _reserveLeaf(commitment, 1);

        if (!token.transferFrom(msg.sender, address(this), amount)) {
            revert TransferFailed();
        }

        uint256 newRoot = _appendLeaf(leafIndex, commitment);

        emit Deposit(commitment, leafIndex, newRoot, msg.sender, amount, envelope);
    }

    /// @notice Spend one note into two. The proof shows the spent note is in
    ///         the tree, its nullifier is this one, and the two new
    ///         commitments carry amounts that sum to it — all amounts hidden.
    ///         No token moves.
    /// @param merkleRoot Root the proof was built against.
    /// @param nullifierHash Nullifier of the note being spent.
    /// @param commitmentOut1 First new note.
    /// @param commitmentOut2 Second new note (the change, typically).
    /// @param envelope1 Sealed envelope for the owner of the first note.
    /// @param envelope2 Sealed envelope for the owner of the second note.
    function transferNote(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256 merkleRoot,
        uint256 nullifierHash,
        uint256 commitmentOut1,
        uint256 commitmentOut2,
        bytes calldata envelope1,
        bytes calldata envelope2
    ) external {
        if (nullifierSpent[nullifierHash]) revert NullifierAlreadySpent();
        if (!_isKnownRoot(merkleRoot)) revert RootNotRecent();
        if (commitmentOut1 == commitmentOut2) revert SameCommitment();
        uint256 firstLeaf = _reserveLeaf(commitmentOut1, 2);
        _reserveLeaf(commitmentOut2, 1);

        uint256[4] memory publicInputs = [merkleRoot, nullifierHash, commitmentOut1, commitmentOut2];
        if (!transferVerifier.verifyProof(proofA, proofB, proofC, publicInputs)) {
            revert InvalidProof();
        }

        // Spend before inserting: the nullifier is the double-spend guard.
        nullifierSpent[nullifierHash] = true;
        emit NoteSpent(nullifierHash);

        uint256 root1 = _appendLeaf(firstLeaf, commitmentOut1);
        emit NoteCreated(commitmentOut1, firstLeaf, root1, envelope1);
        uint256 root2 = _appendLeaf(firstLeaf + 1, commitmentOut2);
        emit NoteCreated(commitmentOut2, firstLeaf + 1, root2, envelope2);
    }

    /// @notice Withdraw a note of `amount` to `recipient`, paying `relayer` a
    ///         `fee` out of it.
    /// @dev Recipient, relayer, fee and amount are public inputs to the proof,
    ///      so a relayer cannot redirect the payment, raise its own fee or
    ///      change the amount: any change invalidates the proof.
    function withdraw(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256 merkleRoot,
        uint256 nullifierHash,
        address recipient,
        address relayer,
        uint256 fee,
        uint256 amount
    ) external {
        if (nullifierSpent[nullifierHash]) revert NullifierAlreadySpent();
        if (amount == 0 || amount > MAX_AMOUNT) revert AmountOutOfRange();
        if (fee > amount) revert FeeExceedsAmount();
        if (!_isKnownRoot(merkleRoot)) revert RootNotRecent();

        (uint256 recipientHi, uint256 recipientLo) = _splitAddress(recipient);
        (uint256 relayerHi, uint256 relayerLo) = _splitAddress(relayer);
        uint256[8] memory publicInputs = [
            merkleRoot,
            nullifierHash,
            recipientHi,
            recipientLo,
            relayerHi,
            relayerLo,
            fee,
            amount
        ];

        if (!withdrawVerifier.verifyProof(proofA, proofB, proofC, publicInputs)) {
            revert InvalidProof();
        }

        // Spend before paying: the nullifier is the double-spend guard, and it
        // must be set before any external call.
        nullifierSpent[nullifierHash] = true;

        uint256 payout = amount - fee;
        if (!token.transfer(recipient, payout)) revert TransferFailed();
        if (fee > 0) {
            if (!token.transfer(relayer, fee)) revert TransferFailed();
        }

        emit Withdrawal(nullifierHash, recipient, relayer, fee, amount);
    }

    /// @notice Current tree root.
    function currentRoot() external view returns (uint256) {
        return rootHistory[rootRingHead];
    }

    /// @notice Is this root recent enough to prove against?
    function isKnownRoot(uint256 root) external view returns (bool) {
        return _isKnownRoot(root);
    }

    /// The two 128-bit halves of an address as a left-padded 32-byte word —
    /// `(hi, lo)`, the circuit's `recipient_hi / recipient_lo`.
    function _splitAddress(address value) private pure returns (uint256 hi, uint256 lo) {
        uint256 word = uint256(uint160(value));
        hi = word >> 128;
        lo = word & type(uint128).max;
    }

    /// Check a commitment can enter the tree and that `count` leaves are free;
    /// mark it known and return the index of the first of them. The index is
    /// not advanced here — `_appendLeaf` does that as it inserts.
    function _reserveLeaf(uint256 commitment, uint256 count) private returns (uint256 leafIndex) {
        if (commitment >= F) revert NotAFieldElement();
        if (commitmentKnown[commitment]) revert CommitmentAlreadyUsed();
        leafIndex = nextLeafIndex;
        if (leafIndex + count > (1 << TREE_DEPTH)) revert TreeFull();
        commitmentKnown[commitment] = true;
    }

    /// Append a leaf and return the new root. Same walk the Solana program does.
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

    /// A root counts as known while it is still in the ring. Zero never does —
    /// an uninitialised slot must not authorise a spend.
    function _isKnownRoot(uint256 root) private view returns (bool) {
        if (root == 0) return false;
        for (uint256 i = 0; i < ROOT_RING_SIZE; i++) {
            if (rootHistory[i] == root) return true;
        }
        return false;
    }
}
