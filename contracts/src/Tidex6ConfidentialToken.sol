// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {BabyJubjub as BJJ} from "./BabyJubjub.sol";
import {Tidex6TokenPubkeyVerifier} from "./Tidex6TokenPubkeyVerifier.sol";
import {Tidex6TokenTransferVerifier} from "./Tidex6TokenTransferVerifier.sol";
import {Tidex6TokenUnwrapVerifier} from "./Tidex6TokenUnwrapVerifier.sol";
import {Tidex6TokenDepositVerifier} from "./Tidex6TokenDepositVerifier.sol";

/// @notice Minimal ERC-20 surface the wrapper needs.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

/// @notice What the shielded pool must offer for a balance to become a note.
///         Implemented by Pool v3; until it is deployed, `pool` stays unset
///         and `depositToPool` reverts instead of pretending to work.
interface IConfidentialPoolBridge {
    function depositFromToken(uint256 commitment, bytes calldata envelope) external;
}

/// @title Confidential wrapper over an ERC-20: balances as ciphertexts
/// @notice Wraps one ERC-20 into balances nobody can read. A balance is a
///         twisted ElGamal ciphertext on Baby Jubjub: commitment
///         `C = m*G + r*H` and handle `D = r*P`, where `P = s^-1 * H` is the
///         owner's public key. The owner recovers `m*G` as `C - s*D`; the
///         chain, holding only `C` and `D`, recovers nothing.
///
///         Amounts appear in exactly two places, both of them chosen by the
///         user: `wrap`, where an ERC-20 transfer comes in, and `unwrap`,
///         where one goes out. Everything between them is ciphertext:
///
///         - `transfer` moves value between two confidential balances. The
///           chain sees which keys were involved and nothing else — no amount,
///           not even a range.
///         - `depositToPool` turns a balance into a shielded-pool note, and
///           there not even the keys are visible. This is the path that has no
///           public number anywhere.
///         - `creditPending` is the way back from the pool, callable only by
///           the pool itself.
///
/// @dev Ordering. Incoming value lands in `pending`, not in `available`, and
///      the owner moves it across with `applyPending`. Without that split,
///      every incoming payment would invalidate the proof its owner was in the
///      middle of building: a transfer proof is made against one exact
///      `available` ciphertext. Token-2022 splits them for the same reason.
///
/// @dev Replay. A proof commits to the sender's `available` ciphertext, and
///      the contract checks that it still equals what it stores; after the
///      spend it does not, so the same proof cannot be used twice. Because a
///      ciphertext could in principle return to an earlier value, the hash of
///      each accepted proof is also recorded — so replaying the exact bytes
///      fails on the cheap check, and producing different bytes needs the
///      secret key.
///
/// @dev Keys, not addresses. A transfer names its recipient by public key,
///      because that is what the ciphertext is encrypted to; the contract maps
///      a key to the address that registered it. An address that never
///      registered cannot receive: there would be no key to encrypt to.
contract Tidex6ConfidentialToken {
    using BJJ for BJJ.Point;

    /// BN254 scalar field modulus — every coordinate must be below it.
    uint256 internal constant F =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// Largest amount the circuits' range proofs cover.
    uint64 public constant MAX_AMOUNT = type(uint64).max;

    /// A ciphertext: shared commitment and one reader's handle.
    struct Cipher {
        BJJ.Point commitment;
        BJJ.Point handle;
    }

    /// One confidential account.
    struct Account {
        /// Public key `P = s^-1 * H`, proved valid at registration.
        BJJ.Point key;
        /// Spendable balance.
        Cipher available;
        /// Incoming balance, waiting for the owner to apply it.
        Cipher pending;
        /// How many credits are sitting in `pending`. Informational: it tells
        /// a wallet whether calling `applyPending` would change anything.
        uint64 pendingCount;
        bool registered;
    }

    /// The wrapped token.
    IERC20 public immutable token;

    /// Verifier per circuit. Separate contracts because each verifying key
    /// hard-codes its own number of public inputs.
    Tidex6TokenPubkeyVerifier public immutable pubkeyVerifier;
    Tidex6TokenTransferVerifier public immutable transferVerifier;
    Tidex6TokenUnwrapVerifier public immutable unwrapVerifier;
    Tidex6TokenDepositVerifier public immutable depositVerifier;

    /// Who may call `creditPending`. Set once, by the deployer.
    address public pool;

    /// The deployer, kept only to set `pool` once.
    address public immutable deployer;

    /// Accounts by owner address.
    mapping(address => Account) internal accounts;

    /// Owner address by key hash — a transfer names its recipient by key.
    mapping(bytes32 => address) public keyOwner;

    /// Proofs already accepted, by hash. See the replay note above.
    mapping(bytes32 => bool) public proofUsed;

    event Registered(address indexed owner, uint256 keyX, uint256 keyY);
    event Wrapped(address indexed owner, uint64 amount);
    event PendingApplied(address indexed owner, uint64 credits);
    /// @notice Recipients scan this by `recipientKeyHash`. The envelope is the
    ///         sealed opening `(m, r)` plus the memo, readable by the
    ///         recipient and by an auditor the sender named — and by nobody
    ///         else, including this contract.
    /// @dev `points` carries four `(x, y)` pairs in this order: amount
    ///      commitment, recipient handle, auditor key, auditor handle. One
    ///      static array instead of eight scalars keeps `transfer` under the
    ///      legacy code generator's stack limit — the build profile stays the
    ///      one every deployed contract was verified with.
    event ConfidentialTransfer(
        bytes32 indexed recipientKeyHash,
        bytes32 indexed senderKeyHash,
        uint256[8] points,
        bytes envelope
    );
    event Unwrapped(address indexed owner, uint64 amount);
    event DepositedToPool(bytes32 indexed senderKeyHash, uint256 commitment);
    event CreditedFromPool(bytes32 indexed recipientKeyHash, uint256 commitmentX, uint256 commitmentY);

    error AlreadyRegistered();
    error KeyTaken();
    error NotRegistered();
    error InvalidProof();
    error ProofReplay();
    error StaleBalance();
    error FieldOverflow();
    error AmountTooLarge();
    error ZeroAmount();
    error TransferFailed();
    error PoolNotSet();
    error PoolAlreadySet();
    error OnlyPool();
    error OnlyDeployer();

    constructor(
        IERC20 token_,
        Tidex6TokenPubkeyVerifier pubkeyVerifier_,
        Tidex6TokenTransferVerifier transferVerifier_,
        Tidex6TokenUnwrapVerifier unwrapVerifier_,
        Tidex6TokenDepositVerifier depositVerifier_
    ) {
        token = token_;
        pubkeyVerifier = pubkeyVerifier_;
        transferVerifier = transferVerifier_;
        unwrapVerifier = unwrapVerifier_;
        depositVerifier = depositVerifier_;
        deployer = msg.sender;
    }

    /// @notice Name the pool allowed to credit balances on the way out of it.
    ///         Once only: the pool can move value into any account, so it is
    ///         not something a deployer should be able to re-point later.
    function setPool(address pool_) external {
        if (msg.sender != deployer) revert OnlyDeployer();
        if (pool != address(0)) revert PoolAlreadySet();
        pool = pool_;
    }

    /// @notice Open a confidential account for `msg.sender` under `key`.
    /// @param key the public key `P = s^-1 * H`
    /// @dev The proof is what makes this safe: it shows `s*P == H` for a
    ///      secret the caller knows, so `P` is on the curve, in the
    ///      prime-order subgroup, and actually owned. A point registered
    ///      without it could be unspendable, or someone else's.
    function register(
        uint256[2] calldata key,
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC
    ) external {
        Account storage account = accounts[msg.sender];
        if (account.registered) revert AlreadyRegistered();
        _requireField(key[0]);
        _requireField(key[1]);

        bytes32 keyHash = keccak256(abi.encodePacked(key[0], key[1]));
        if (keyOwner[keyHash] != address(0)) revert KeyTaken();

        if (!pubkeyVerifier.verifyProof(proofA, proofB, proofC, key)) revert InvalidProof();

        account.key = BJJ.Point(key[0], key[1]);
        account.available = _emptyCipher();
        account.pending = _emptyCipher();
        account.registered = true;
        keyOwner[keyHash] = msg.sender;
        emit Registered(msg.sender, key[0], key[1]);
    }

    /// @notice Move `amount` of the plain token into your confidential pending
    ///         balance.
    /// @dev The amount is public here and only here on the way in — an ERC-20
    ///      transfer cannot be otherwise. The ciphertext the contract credits
    ///      carries no blinding (`r = 0`, handle = identity): blinding would
    ///      hide nothing that the ERC-20 transfer has not already shown, and
    ///      the owner decrypts `C - s*O = m*G` just the same.
    function wrap(uint64 amount) external {
        if (amount == 0) revert ZeroAmount();
        Account storage account = accounts[msg.sender];
        if (!account.registered) revert NotRegistered();

        if (!token.transferFrom(msg.sender, address(this), amount)) revert TransferFailed();

        Cipher memory credit = Cipher(BJJ.mulG(amount), BJJ.identity());
        _credit(account, credit);
        emit Wrapped(msg.sender, amount);
    }

    /// @notice Move everything from `pending` into `available`.
    /// @dev Owner only, and that is not a formality. A spend proof is built
    ///      against one exact `available` ciphertext; if anyone could fold
    ///      pending in at any moment, any in-flight proof could be invalidated
    ///      by a stranger.
    function applyPending() external {
        Account storage account = accounts[msg.sender];
        if (!account.registered) revert NotRegistered();

        uint64 credits = account.pendingCount;
        account.available.commitment = BJJ.add(account.available.commitment, account.pending.commitment);
        account.available.handle = BJJ.add(account.available.handle, account.pending.handle);
        account.pending = _emptyCipher();
        account.pendingCount = 0;
        emit PendingApplied(msg.sender, credits);
    }

    /// @notice Pay from one confidential balance to another. No amount is
    ///         written, emitted or stored.
    /// @param input the circuit's eighteen public inputs, in circuit order:
    ///        sender key, sender available `(C, D)`, amount commitment,
    ///        sender handle, recipient key, recipient handle, auditor key,
    ///        auditor handle — each as `(x, y)`
    /// @param envelope sealed opening and memo for the recipient and the
    ///        auditor; opaque to the chain
    /// @dev Anyone may submit: the proof carries knowledge of the sender's
    ///      secret key, so a relayer paying the gas cannot change where the
    ///      value goes. What the contract adds is freshness — the proof must
    ///      be against the balance as it stands now.
    function transfer(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256[18] calldata input,
        bytes calldata envelope
    ) external {
        for (uint256 i = 0; i < 18; ++i) {
            _requireField(input[i]);
        }

        Account storage sender = _accountByKey(input[0], input[1]);
        _requireAvailable(sender, input[2], input[3], input[4], input[5]);

        Account storage recipient = _accountByKey(input[10], input[11]);

        _consumeProof(keccak256(abi.encodePacked(proofA, proofB, proofC, input)));
        if (!transferVerifier.verifyProof(proofA, proofB, proofC, input)) revert InvalidProof();

        Cipher memory spent = Cipher(BJJ.Point(input[6], input[7]), BJJ.Point(input[8], input[9]));
        _debit(sender, spent);

        Cipher memory credit = Cipher(BJJ.Point(input[6], input[7]), BJJ.Point(input[12], input[13]));
        _credit(recipient, credit);

        _emitTransfer(input, envelope);
    }

    /// @notice Leave for the plain token: burn `amount` from your confidential
    ///         balance and receive it as ERC-20.
    /// @param input the circuit's seven public inputs: sender key, sender
    ///        available `(C, D)`, and the amount
    /// @dev Caller must be the key's owner, and the payout goes to the caller.
    ///      The circuit has no recipient field — an amount leaving for a public
    ///      token is public anyway — so the destination is bound here, by
    ///      `msg.sender`. Without that binding a proof sitting in the mempool
    ///      could be re-submitted by anyone with their own address as the
    ///      destination. A future revision of the circuit can take the
    ///      recipient as a public input and make unwrap relayable, the way the
    ///      pool's withdraw already is.
    function unwrap(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256[7] calldata input
    ) external {
        for (uint256 i = 0; i < 7; ++i) {
            _requireField(input[i]);
        }
        if (input[6] > MAX_AMOUNT) revert AmountTooLarge();
        uint64 amount = uint64(input[6]);
        if (amount == 0) revert ZeroAmount();

        Account storage account = accounts[msg.sender];
        if (!account.registered) revert NotRegistered();
        if (account.key.x != input[0] || account.key.y != input[1]) revert NotRegistered();
        _requireAvailable(account, input[2], input[3], input[4], input[5]);

        _consumeProof(keccak256(abi.encodePacked(proofA, proofB, proofC, input)));
        if (!unwrapVerifier.verifyProof(proofA, proofB, proofC, input)) revert InvalidProof();

        // The amount is public, so its ciphertext is the unblinded one the
        // contract can build itself — the mirror image of `wrap`.
        _debit(account, Cipher(BJJ.mulG(amount), BJJ.identity()));

        if (!token.transfer(msg.sender, amount)) revert TransferFailed();
        emit Unwrapped(msg.sender, amount);
    }

    /// @notice Turn part of a confidential balance into a shielded-pool note.
    ///         The only operation here with no public number and no public
    ///         recipient.
    /// @param input the circuit's eleven public inputs: sender key, sender
    ///        available `(C, D)`, the spent ciphertext `(C_m, D_s)`, and the
    ///        note commitment
    /// @param envelope sealed note material for whoever the sender named
    /// @dev The circuit is what ties the two worlds together: it proves that
    ///      the amount inside the ElGamal ciphertext being debited is the same
    ///      amount inside the Poseidon note commitment. Neither number is
    ///      written down anywhere.
    function depositToPool(
        uint256[2] calldata proofA,
        uint256[2][2] calldata proofB,
        uint256[2] calldata proofC,
        uint256[11] calldata input,
        bytes calldata envelope
    ) external {
        address poolAddress = pool;
        if (poolAddress == address(0)) revert PoolNotSet();
        for (uint256 i = 0; i < 11; ++i) {
            _requireField(input[i]);
        }

        Account storage sender = _accountByKey(input[0], input[1]);
        _requireAvailable(sender, input[2], input[3], input[4], input[5]);

        _consumeProof(keccak256(abi.encodePacked(proofA, proofB, proofC, input)));
        if (!depositVerifier.verifyProof(proofA, proofB, proofC, input)) revert InvalidProof();

        _debit(sender, Cipher(BJJ.Point(input[6], input[7]), BJJ.Point(input[8], input[9])));

        emit DepositedToPool(keccak256(abi.encodePacked(input[0], input[1])), input[10]);
        IConfidentialPoolBridge(poolAddress).depositFromToken(input[10], envelope);
    }

    /// @notice Credit a confidential balance on the way out of the pool.
    /// @dev Pool only. The pool has already verified the exit proof — note
    ///      membership, nullifier, and that this ciphertext carries the note's
    ///      amount encrypted to this recipient — so this side does the
    ///      arithmetic and nothing else. It is the one entry point that can
    ///      create value here without a proof of its own, which is why it is
    ///      restricted to a single address set once.
    function creditPending(
        uint256[2] calldata recipientKey,
        uint256[2] calldata commitment,
        uint256[2] calldata handle
    ) external {
        if (msg.sender != pool) revert OnlyPool();
        _requireField(commitment[0]);
        _requireField(commitment[1]);
        _requireField(handle[0]);
        _requireField(handle[1]);

        Account storage recipient = _accountByKey(recipientKey[0], recipientKey[1]);
        _credit(recipient, Cipher(BJJ.Point(commitment[0], commitment[1]), BJJ.Point(handle[0], handle[1])));
        emit CreditedFromPool(
            keccak256(abi.encodePacked(recipientKey[0], recipientKey[1])),
            commitment[0],
            commitment[1]
        );
    }

    /// @notice Everything a wallet needs to build its next proof: the key, both
    ///         ciphertexts and how many credits are waiting.
    function accountOf(address owner)
        external
        view
        returns (
            uint256 keyX,
            uint256 keyY,
            uint256 availableCommitmentX,
            uint256 availableCommitmentY,
            uint256 availableHandleX,
            uint256 availableHandleY,
            uint256 pendingCommitmentX,
            uint256 pendingCommitmentY,
            uint256 pendingHandleX,
            uint256 pendingHandleY,
            uint64 pendingCount,
            bool registered
        )
    {
        Account storage account = accounts[owner];
        return (
            account.key.x,
            account.key.y,
            account.available.commitment.x,
            account.available.commitment.y,
            account.available.handle.x,
            account.available.handle.y,
            account.pending.commitment.x,
            account.pending.commitment.y,
            account.pending.handle.x,
            account.pending.handle.y,
            account.pendingCount,
            account.registered
        );
    }

    /// Emit `ConfidentialTransfer` from the circuit's public inputs.
    ///
    /// A separate function so its locals live in their own stack frame; inlined
    /// into `transfer`, the event alone pushed that function past the limit.
    function _emitTransfer(uint256[18] calldata input, bytes calldata envelope) private {
        uint256[8] memory points = [
            input[6],
            input[7],
            input[12],
            input[13],
            input[14],
            input[15],
            input[16],
            input[17]
        ];
        emit ConfidentialTransfer(
            keccak256(abi.encodePacked(input[10], input[11])),
            keccak256(abi.encodePacked(input[0], input[1])),
            points,
            envelope
        );
    }

    /// A ciphertext of zero: both points are the neutral element.
    function _emptyCipher() private pure returns (Cipher memory) {
        return Cipher(BJJ.identity(), BJJ.identity());
    }

    /// Resolve a key to its registered account, or revert.
    function _accountByKey(uint256 x, uint256 y) private view returns (Account storage) {
        address owner = keyOwner[keccak256(abi.encodePacked(x, y))];
        if (owner == address(0)) revert NotRegistered();
        return accounts[owner];
    }

    /// The proof must be against the balance as it stands now.
    function _requireAvailable(
        Account storage account,
        uint256 commitmentX,
        uint256 commitmentY,
        uint256 handleX,
        uint256 handleY
    ) private view {
        if (
            account.available.commitment.x != commitmentX ||
            account.available.commitment.y != commitmentY ||
            account.available.handle.x != handleX ||
            account.available.handle.y != handleY
        ) {
            revert StaleBalance();
        }
    }

    /// Record a proof as used, rejecting the exact same bytes twice.
    function _consumeProof(bytes32 digest) private {
        if (proofUsed[digest]) revert ProofReplay();
        proofUsed[digest] = true;
    }

    /// Subtract a ciphertext from `available`.
    function _debit(Account storage account, Cipher memory amount) private {
        account.available.commitment = BJJ.sub(account.available.commitment, amount.commitment);
        account.available.handle = BJJ.sub(account.available.handle, amount.handle);
    }

    /// Add a ciphertext to `pending`.
    function _credit(Account storage account, Cipher memory amount) private {
        account.pending.commitment = BJJ.add(account.pending.commitment, amount.commitment);
        account.pending.handle = BJJ.add(account.pending.handle, amount.handle);
        account.pendingCount += 1;
    }

    /// Coordinates and amounts are field elements; anything above the modulus
    /// would be reduced somewhere down the line, and a silent reduction on a
    /// path that binds value is how proofs stop meaning what they say.
    function _requireField(uint256 value) private pure {
        if (value >= F) revert FieldOverflow();
    }
}
