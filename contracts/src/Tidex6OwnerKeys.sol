// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Owner keys of the v2 pools (ADR-022)
/// @notice A v2 note is bound to its recipient's owner key,
///         `ownerPk = H(D_OWNER, spendingKey)`. A sender knows only a wallet
///         address, so the wallet publishes its owner key here — once per
///         chain, next to the reader key it already published in
///         `Tidex6Registry` (which keeps a fixed 1216-byte record and is left
///         as it is).
/// @dev Only the wallet itself can set its entry. Publishing a new key does
///      not strand old notes: they stay spendable with the old spending key,
///      which the wallet derives from the same signature as before.
contract Tidex6OwnerKeys {
    uint256 internal constant F =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// Owner key by wallet; zero — none published.
    mapping(address => uint256) public ownerKeyOf;

    event OwnerKeyPublished(address indexed wallet, uint256 ownerPk);

    error NotAFieldElement();

    /// @notice Publish (or replace) the caller's owner key.
    function publishOwnerKey(uint256 ownerPk) external {
        if (ownerPk == 0 || ownerPk >= F) revert NotAFieldElement();
        ownerKeyOf[msg.sender] = ownerPk;
        emit OwnerKeyPublished(msg.sender, ownerPk);
    }
}
