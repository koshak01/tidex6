// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PoseidonT3} from "./PoseidonT3.sol";
import {Tidex6Verifier} from "./Tidex6Verifier.sol";

/// @notice Minimal ERC-20 surface the pool needs.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @title Shielded pool for a single ERC-20
/// @notice Deposits append a commitment to an incremental Merkle tree;
///         withdrawals prove membership in zero knowledge and spend a
///         nullifier. The link between the two is what stays private.
///
///         This mirrors the Solana pool (`programs/tidex6-wusdc-pool`)
///         deliberately: same tree depth, same root ring, same Poseidon, same
///         five public inputs. The proving system is shared, so the mechanics
///         must be too — a divergence here would mean proofs that verify on
///         one chain and not the other.
///
/// @dev Multichain, not cross-chain. This pool knows nothing about any other
///      chain's state and must never be taught to: deposits made here are
///      withdrawn here.
///
/// @dev On recipient binding — the Solana pool has a known weakness here
///      (GAP-2). There the recipient is bound as `reduce_mod_bn254(pubkey)`,
///      and since a pubkey is 256 bits against a ~254-bit field, the map
///      collides: `reduce(P) == reduce(P + r)`. A relayer could swap the
///      recipient for a different, unspendable account and the proof would
///      still verify.
///
///      That does not happen here. An EVM address is 160 bits, far below the
///      field order, so `uint256(uint160(addr))` is injective — there is no
///      second address with the same field element. Never introduce a
///      reduction on this path; `test_addressToFieldIsInjective` guards it.
contract Tidex6Pool {
    /// Depth of the incremental tree. Fixed at compile time in the circuit.
    uint256 public constant TREE_DEPTH = 20;

    /// How many past roots stay acceptable. A withdrawal proved against a root
    /// that was current when the user started is still valid a few deposits
    /// later — without this, every concurrent deposit would invalidate
    /// in-flight withdrawals.
    uint256 public constant ROOT_RING_SIZE = 30;

    /// BN254 scalar field modulus. Every field element must be below it.
    uint256 internal constant F =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// The token this pool holds.
    IERC20 public immutable token;

    /// Groth16 verifier for the withdraw circuit.
    Tidex6Verifier public immutable verifier;

    /// Fixed deposit size. A pool with arbitrary amounts leaks the link
    /// through the amount itself, so every note is worth the same.
    uint256 public immutable denomination;

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

    /// Commitments already deposited, so an accidental repeat is rejected
    /// rather than creating a note the depositor cannot distinguish.
    mapping(uint256 => bool) public commitmentKnown;

    /// @notice A note was funded.
    /// @param envelope The sealed envelope for the recipient — opaque to the
    ///        chain, meaningful only to whoever holds the key it was sealed
    ///        for. Carried in the log rather than storage: a log byte costs 8
    ///        gas against 20 000 for a storage slot, and nothing on chain ever
    ///        needs to read this back. The recipient scans logs, the same way
    ///        they scan the pool's memo accounts on Solana.
    event Deposit(
        uint256 indexed commitment,
        uint256 leafIndex,
        uint256 newRoot,
        address depositor,
        bytes envelope
    );
    event Withdrawal(uint256 indexed nullifierHash, address indexed recipient, address relayer, uint256 fee);

    error NotAFieldElement();
    error CommitmentAlreadyUsed();
    error TreeFull();
    error RootNotRecent();
    error NullifierAlreadySpent();
    error InvalidProof();
    error FeeExceedsDenomination();
    error TransferFailed();

    /// @param token_ ERC-20 held by this pool.
    /// @param verifier_ Groth16 verifier for the withdraw circuit.
    /// @param denomination_ Fixed note size, in the token's smallest unit.
    constructor(IERC20 token_, Tidex6Verifier verifier_, uint256 denomination_) {
        token = token_;
        verifier = verifier_;
        denomination = denomination_;

        // Empty-subtree hashes, level by level, exactly as the Solana pool
        // computes them at initialisation.
        uint256 zeroHash = 0;
        for (uint256 level = 0; level < TREE_DEPTH; level++) {
            zeroSubtrees[level] = zeroHash;
            filledSubtrees[level] = zeroHash;
            zeroHash = PoseidonT3.hash(zeroHash, zeroHash);
        }
        rootHistory[0] = zeroHash;
    }

    /// @notice Deposit one note.
    /// @param commitment Poseidon(secret, nullifier), computed by the client.
    /// @param envelope The sealed envelope for the recipient, produced in the
    ///        sender's browser before anything left it. The pool does not read
    ///        it and could not: it is encrypted to a key only the recipient
    ///        can derive.
    /// @dev The pool never sees the secret. It only learns that some
    ///      commitment was funded — which is the entire point.
    ///
    ///      The envelope travels with the deposit rather than in a separate
    ///      call because the two must not come apart: a commitment without an
    ///      envelope is money nobody can find, and an envelope without a
    ///      commitment points at nothing. On Solana the same pairing is held
    ///      by writing both in one flow; here one transaction does it.
    function deposit(uint256 commitment, bytes calldata envelope) external {
        if (commitment >= F) revert NotAFieldElement();
        if (commitmentKnown[commitment]) revert CommitmentAlreadyUsed();
        if (nextLeafIndex >= (1 << TREE_DEPTH)) revert TreeFull();

        commitmentKnown[commitment] = true;

        if (!token.transferFrom(msg.sender, address(this), denomination)) {
            revert TransferFailed();
        }

        uint256 leafIndex = nextLeafIndex;
        uint256 newRoot = _appendLeaf(leafIndex, commitment);

        emit Deposit(commitment, leafIndex, newRoot, msg.sender, envelope);
    }

    /// @notice Withdraw a note to `recipient`, optionally paying a relayer.
    /// @param proofA Groth16 proof element A.
    /// @param proofB Groth16 proof element B.
    /// @param proofC Groth16 proof element C.
    /// @param merkleRoot Root the proof was built against.
    /// @param nullifierHash Nullifier being spent.
    /// @param recipient Who receives the funds.
    /// @param relayer Who is paid the fee — typically the sender of this
    ///        transaction, so the recipient never needs gas of their own.
    /// @param fee Paid to `relayer` out of the denomination.
    ///
    /// @dev Recipient, relayer and fee are public inputs to the proof, so a
    ///      relayer cannot redirect the payment or raise its own fee: any
    ///      change invalidates the proof.
    function withdraw(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256 merkleRoot,
        uint256 nullifierHash,
        address recipient,
        address relayer,
        uint256 fee
    ) external {
        if (nullifierSpent[nullifierHash]) revert NullifierAlreadySpent();
        if (fee > denomination) revert FeeExceedsDenomination();
        if (!_isKnownRoot(merkleRoot)) revert RootNotRecent();

        uint256[5] memory publicInputs = [
            merkleRoot,
            nullifierHash,
            uint256(uint160(recipient)),
            uint256(uint160(relayer)),
            fee
        ];

        if (!verifier.verifyProof(proofA, proofB, proofC, publicInputs)) {
            revert InvalidProof();
        }

        // Spend before paying: the nullifier is the double-spend guard, and it
        // must be set before any external call.
        nullifierSpent[nullifierHash] = true;

        uint256 payout = denomination - fee;
        if (!token.transfer(recipient, payout)) revert TransferFailed();
        if (fee > 0) {
            if (!token.transfer(relayer, fee)) revert TransferFailed();
        }

        emit Withdrawal(nullifierHash, recipient, relayer, fee);
    }

    /// @notice Current tree root.
    function currentRoot() external view returns (uint256) {
        return rootHistory[rootRingHead];
    }

    /// @notice Is this root recent enough to withdraw against?
    function isKnownRoot(uint256 root) external view returns (bool) {
        return _isKnownRoot(root);
    }

    /// Append a leaf and return the new root. Same walk the Solana pool does.
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
    /// an uninitialised slot must not authorise a withdrawal.
    function _isKnownRoot(uint256 root) private view returns (bool) {
        if (root == 0) return false;
        for (uint256 i = 0; i < ROOT_RING_SIZE; i++) {
            if (rootHistory[i] == root) return true;
        }
        return false;
    }
}
