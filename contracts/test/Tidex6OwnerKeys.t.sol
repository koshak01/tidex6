// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Tidex6OwnerKeys} from "../src/Tidex6OwnerKeys.sol";

contract Tidex6OwnerKeysTest is Test {
    Tidex6OwnerKeys keys;
    address alice = address(0xA11CE);

    function setUp() public {
        keys = new Tidex6OwnerKeys();
    }

    function test_aWalletPublishesItsOwnKey() public {
        vm.prank(alice);
        keys.publishOwnerKey(0x1234);
        assertEq(keys.ownerKeyOf(alice), 0x1234);
        assertEq(keys.ownerKeyOf(address(this)), 0);
    }

    function test_aKeyCanBeReplaced() public {
        vm.startPrank(alice);
        keys.publishOwnerKey(0x1234);
        keys.publishOwnerKey(0x5678);
        vm.stopPrank();
        assertEq(keys.ownerKeyOf(alice), 0x5678);
    }

    function test_zeroAndOutOfFieldAreRefused() public {
        vm.expectRevert(Tidex6OwnerKeys.NotAFieldElement.selector);
        keys.publishOwnerKey(0);
        vm.expectRevert(Tidex6OwnerKeys.NotAFieldElement.selector);
        keys.publishOwnerKey(type(uint256).max);
    }
}
