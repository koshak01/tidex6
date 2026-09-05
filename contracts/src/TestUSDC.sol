// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.28;

/// @title TestUSDC — a 6-decimal test stablecoin for networks without one.
/// @notice Anyone can mint up to 100 tokens per call; there is no owner and no
///         admin. Deployed only on test networks so the pool has something to
///         hold; never meant to carry value.
contract TestUSDC {
    string public constant name = "Test USDC";
    string public constant symbol = "tUSDC";
    uint8 public constant decimals = 6;
    uint256 public constant MINT_CAP = 100_000_000; // 100 tUSDC per call

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    error MintCapExceeded(uint256 requested, uint256 cap);
    error InsufficientBalance(uint256 have, uint256 need);
    error InsufficientAllowance(uint256 have, uint256 need);

    /// @notice Faucet: mint `amount` raw units (6 decimals) to `to`.
    function mint(address to, uint256 amount) external {
        if (amount > MINT_CAP) revert MintCapExceeded(amount, MINT_CAP);
        totalSupply += amount;
        balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _move(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 allowed = allowance[from][msg.sender];
        if (allowed != type(uint256).max) {
            if (allowed < value) revert InsufficientAllowance(allowed, value);
            allowance[from][msg.sender] = allowed - value;
        }
        _move(from, to, value);
        return true;
    }

    function _move(address from, address to, uint256 value) internal {
        uint256 have = balanceOf[from];
        if (have < value) revert InsufficientBalance(have, value);
        balanceOf[from] = have - value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
    }
}
