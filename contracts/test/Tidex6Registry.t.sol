// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, Vm} from "forge-std/Test.sol";
import {Tidex6Registry} from "../src/Tidex6Registry.sol";

contract Tidex6RegistryTest is Test {
    Tidex6Registry internal registry;

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    function setUp() public {
        registry = new Tidex6Registry();
    }

    /// Ключ нужной длины, заполненный узнаваемо: одинаковые байты поймали бы
    /// не всякую перестановку.
    function _key(uint8 salt) internal pure returns (bytes memory out) {
        out = new bytes(1216);
        for (uint256 i = 0; i < out.length; i++) {
            out[i] = bytes1(uint8((i + salt) % 251));
        }
    }

    /// Незарегистрированный кошелёк должен читаться как незарегистрированный.
    ///
    /// Это первое, что спрашивает отправитель. Ответь здесь неправильно — и он
    /// запечатает конверт в пустоту: деньги уйдут, открыть их будет некому.
    function test_unknownWalletIsNotRegistered() public view {
        assertFalse(registry.isRegistered(alice), "a wallet that never published looks registered");
        (bytes32 hash, uint8 version, uint64 at) = registry.readerOf(alice);
        assertEq(hash, bytes32(0));
        assertEq(version, 0);
        assertEq(at, 0);
    }

    /// Ключ уезжает в лог целиком и совпадает с опубликованным.
    function test_publishEmitsTheKey() public {
        bytes memory key = _key(1);

        vm.recordLogs();
        vm.prank(alice);
        registry.publishReader(2, key);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1, "publishing should emit exactly one event");
        assertEq(
            logs[0].topics[0],
            keccak256("ReaderPublished(address,uint8,bytes)"),
            "wrong event"
        );
        assertEq(address(uint160(uint256(logs[0].topics[1]))), alice, "wrong wallet in the topic");

        (uint8 version, bytes memory published) = abi.decode(logs[0].data, (uint8, bytes));
        assertEq(version, 2);
        assertEq(published, key, "the key in the log is not the key published");
    }

    /// Хеш в хранилище позволяет проверить прочитанное из лога.
    ///
    /// Логи отдаёт узел, а узел может ошибиться или солгать. Без этой проверки
    /// отправитель шифрует тем, что ему прислали, и надеется.
    function test_hashProvesWhatWasPublished() public {
        bytes memory key = _key(7);
        vm.prank(alice);
        registry.publishReader(2, key);

        assertTrue(registry.isRegistered(alice));
        assertTrue(registry.matchesPublished(alice, key), "the real key did not match its hash");

        bytes memory tampered = _key(7);
        tampered[500] = bytes1(uint8(tampered[500]) ^ 0x01);
        assertFalse(
            registry.matchesPublished(alice, tampered),
            "a key with one flipped bit passed as genuine"
        );
    }

    /// Ключ чужой длины отвергается на входе, а не при запечатывании.
    function test_rejectsWrongLength() public {
        bytes memory short = new bytes(1215);
        vm.prank(alice);
        vm.expectRevert(
            abi.encodeWithSelector(Tidex6Registry.WrongKeyLength.selector, 1215, 1216)
        );
        registry.publishReader(2, short);
    }

    /// Смена ключа разрешена — иначе утёкший ключ нельзя было бы заменить.
    function test_rotationReplacesTheKey() public {
        bytes memory first = _key(1);
        bytes memory second = _key(2);

        vm.prank(alice);
        registry.publishReader(2, first);
        vm.prank(alice);
        registry.publishReader(3, second);

        (, uint8 version,) = registry.readerOf(alice);
        assertEq(version, 3, "version did not follow the rotation");
        assertTrue(registry.matchesPublished(alice, second), "new key not stored");
        assertFalse(registry.matchesPublished(alice, first), "old key still passes");
    }

    /// Один кошелёк не может опубликовать ключ за другого.
    ///
    /// Запись идёт по `msg.sender` и никак иначе: если бы адрес приходил
    /// аргументом, кто угодно подменил бы чужой ключ своим и стал получать
    /// чужие платежи.
    function test_cannotPublishForSomeoneElse() public {
        vm.prank(alice);
        registry.publishReader(2, _key(1));

        assertTrue(registry.isRegistered(alice));
        assertFalse(registry.isRegistered(bob), "publishing for one wallet registered another");
    }
    /// Отзыв убирает ключ: отправителю говорят, что платить сюда нельзя.
    ///
    /// Это случай утёкшего секрета. Пока запись жива, реестр отвечает «можно», а
    /// платёж, запечатанный скомпрометированным ключом, хуже неудачного — он
    /// молча неизвлекаем владельцем и читается тем, у кого утечка.
    function test_revokeRemovesTheKey() public {
        bytes memory key = _key(3);
        vm.prank(alice);
        registry.publishReader(2, key);
        assertTrue(registry.isRegistered(alice));

        vm.prank(alice);
        registry.revokeReader();

        assertFalse(registry.isRegistered(alice), "the key survived revocation");
        assertFalse(registry.matchesPublished(alice, key), "the revoked key still matches");
        (bytes32 hash, uint8 version, uint64 at) = registry.readerOf(alice);
        assertEq(hash, bytes32(0));
        assertEq(version, 0);
        assertEq(at, 0);
    }

    /// Отзывать нечего — это отказ, а не тихое «готово».
    ///
    /// Иначе человек поверит, что закрыл утечку, которой у него не было, — или
    /// что закрыл её не на том кошельке.
    function test_revokeWithoutEntryReverts() public {
        vm.prank(bob);
        vm.expectRevert(Tidex6Registry.NothingToRevoke.selector);
        registry.revokeReader();
    }

    /// После отзыва можно опубликовать снова — отзыв не приговор кошельку.
    function test_canPublishAgainAfterRevoke() public {
        vm.prank(alice);
        registry.publishReader(2, _key(1));
        vm.prank(alice);
        registry.revokeReader();

        bytes memory fresh = _key(9);
        vm.prank(alice);
        registry.publishReader(3, fresh);

        assertTrue(registry.isRegistered(alice));
        assertTrue(registry.matchesPublished(alice, fresh));
    }
}
