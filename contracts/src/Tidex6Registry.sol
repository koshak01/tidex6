// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title tidex6 reader registry
/// @notice Where a wallet publishes the key people seal payments to.
///
/// Without this contract the second chain is one-way: money can enter it, but
/// only for recipients who already live on Solana, because the registry existed
/// only there. Someone with MetaMask and no Solana wallet had nowhere to
/// publish a key — and a sender has nothing to seal an envelope with.
///
/// The key itself lives in the log, not in storage, and that is the whole
/// design decision here. It is 1216 bytes: thirty-eight storage slots, twenty
/// thousand gas each, three quarters of a million gas to register once. In a
/// log the same bytes cost eight gas apiece. Nothing on chain ever needs to
/// read this key back — only people do, and people can read logs.
///
/// Storage keeps what a contract genuinely needs: a hash of the key and its
/// version. The hash is not decoration. A reader who fetched the key from a log
/// has no way to know the node told the truth; comparing it against a hash the
/// contract stores turns "some bytes an RPC handed me" into "the bytes this
/// wallet published".
contract Tidex6Registry {
    /// @notice Key length of the ML-KEM reader address, in bytes.
    /// @dev Fixed on purpose. A key of the wrong size is not a key, and letting
    ///      one in would mean senders failing later, at sealing time, with an
    ///      error that points at the wrong person.
    uint256 public constant READER_LEN = 1216;

    struct Entry {
        /// keccak of the published key. Zero means "never registered".
        bytes32 keyHash;
        /// Identity version from the signed phrase, so a sender can notice a
        /// rotation instead of sealing to a lock the recipient no longer opens.
        uint8 version;
        /// Block in which the key was published — where to start reading logs.
        uint64 publishedAt;
    }

    mapping(address => Entry) private entries;

    /// @notice A wallet published (or replaced) its reader key.
    /// @param wallet Whose key it is. Indexed: this is what people filter by.
    /// @param version Identity version from the signed phrase.
    /// @param reader The key itself, 1216 bytes.
    event ReaderPublished(address indexed wallet, uint8 version, bytes reader);

    /// @notice A wallet withdrew its key: it can no longer be paid privately.
    event ReaderRevoked(address indexed wallet);

    error WrongKeyLength(uint256 got, uint256 expected);
    error NothingToRevoke();

    /// @notice Publish the key people will seal payments to.
    /// @dev Republishing is allowed and is how rotation works: the new key
    ///      replaces the old one, the version says which is which, and old
    ///      envelopes stay openable by whoever kept the old secret. Forbidding
    ///      it would mean a wallet whose key leaked could never be fixed.
    function publishReader(uint8 version, bytes calldata reader) external {
        if (reader.length != READER_LEN) {
            revert WrongKeyLength(reader.length, READER_LEN);
        }
        entries[msg.sender] = Entry({
            keyHash: keccak256(reader),
            version: version,
            publishedAt: uint64(block.number)
        });
        emit ReaderPublished(msg.sender, version, reader);
    }

    /// @notice Withdraw the key, so senders are told this wallet cannot be paid.
    /// @dev This exists for one case: a wallet whose secret half leaked. Until
    ///      the key is withdrawn the registry keeps telling senders the address
    ///      can receive, and a payment sealed to a compromised key is worse than
    ///      one that fails outright — it is quietly unspendable by its owner and
    ///      readable by whoever holds the leak.
    ///
    ///      Rotation (publishing again) covers the ordinary case. Revocation
    ///      covers the case where there is no new key to publish yet, or where
    ///      the wallet itself is no longer trusted: it must be possible to say
    ///      "stop paying me here" without first deciding where to be paid next.
    ///
    ///      Reverting on an empty entry rather than passing silently: a wallet
    ///      that never published has nothing to withdraw, and answering "done"
    ///      to that would let someone believe they had closed an exposure they
    ///      never had — or that they closed the wrong wallet's.
    function revokeReader() external {
        if (entries[msg.sender].keyHash == bytes32(0)) revert NothingToRevoke();
        delete entries[msg.sender];
        emit ReaderRevoked(msg.sender);
    }

    /// @notice What is known on chain about a wallet's key.
    /// @return keyHash Hash of the published key, zero if never published.
    /// @return version Identity version.
    /// @return publishedAt Block of publication — where to start reading logs.
    function readerOf(address wallet)
        external
        view
        returns (bytes32 keyHash, uint8 version, uint64 publishedAt)
    {
        Entry storage e = entries[wallet];
        return (e.keyHash, e.version, e.publishedAt);
    }

    /// @notice Has this wallet published a key at all.
    /// @dev A sender must check this before sealing. Sealing to a wallet that
    ///      never registered produces an envelope nobody can open — money sent
    ///      into silence.
    function isRegistered(address wallet) external view returns (bool) {
        return entries[wallet].keyHash != bytes32(0);
    }

    /// @notice Check that a key read from a log is the one this wallet published.
    /// @dev The reason the hash is stored at all. Logs come from a node, and a
    ///      node can be wrong or lying; this makes the answer verifiable
    ///      without trusting it.
    function matchesPublished(address wallet, bytes calldata reader)
        external
        view
        returns (bool)
    {
        return entries[wallet].keyHash == keccak256(reader);
    }
}
