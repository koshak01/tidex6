//! tidex6 reader registry on Stylus.
//!
//! Where a wallet publishes the key people seal payments to. The key itself
//! (1216 bytes: ML-KEM-768 with an x25519 view key) lives in the log, not in
//! storage — a log byte costs 8 gas, a storage slot 20 000, and nothing on
//! chain ever reads the key back. Storage keeps what a contract genuinely
//! needs: the keccak of the key and its version, so a reader who fetched the
//! key from a node can check it is the one this wallet published.
//!
//! ABI, events and errors are identical to `contracts/src/Tidex6Registry.sol`.

#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
extern crate alloc;

// The stylus-proc macros (`#[storage]`, `#[public]`, `sol_interface!`) expand
// to `Vec` and `vec!`; under `no_std` nobody imports those for us.
#[allow(unused_imports)]
use alloc::vec;
#[allow(unused_imports)]
use alloc::vec::Vec;

use alloy_primitives::{Address, FixedBytes, U256, B256};
use alloy_sol_types::sol;
use stylus_sdk::abi::Bytes;
use stylus_sdk::crypto::keccak;
use stylus_sdk::prelude::*;
use stylus_sdk::storage::{StorageB256, StorageMap, StorageU64, StorageU8};

/// Key length of the ML-KEM reader address, in bytes. Fixed on purpose: a key
/// of the wrong size is not a key, and letting one in would make senders fail
/// later, at sealing time, with an error that points at the wrong person.
pub const READER_LEN: usize = 1216;

sol! {
    /// A wallet published (or replaced) its reader key.
    event ReaderPublished(address indexed wallet, uint8 version, bytes reader);
    /// A wallet withdrew its key: it can no longer be paid privately.
    event ReaderRevoked(address indexed wallet);

    error WrongKeyLength(uint256 got, uint256 expected);
    error NothingToRevoke();
}

#[derive(SolidityError)]
pub enum RegistryError {
    WrongKeyLength(WrongKeyLength),
    NothingToRevoke(NothingToRevoke),
}

/// What is stored per wallet. Zero `key_hash` means "never registered".
#[storage]
pub struct Entry {
    key_hash: StorageB256,
    version: StorageU8,
    published_at: StorageU64,
}

#[storage]
#[entrypoint]
pub struct Tidex6Registry {
    entries: StorageMap<Address, Entry>,
}

#[public]
impl Tidex6Registry {
    /// Key length of the ML-KEM reader address, in bytes.
    #[selector(name = "READER_LEN")]
    pub fn reader_len(&self) -> U256 {
        U256::from(READER_LEN)
    }

    /// Publish the key people will seal payments to. Republishing is how
    /// rotation works: the new key replaces the old one, the version says
    /// which is which.
    #[selector(name = "publishReader")]
    pub fn publish_reader(&mut self, version: u8, reader: Bytes) -> Result<(), RegistryError> {
        if reader.len() != READER_LEN {
            return Err(RegistryError::WrongKeyLength(WrongKeyLength {
                got: U256::from(reader.len()),
                expected: U256::from(READER_LEN),
            }));
        }
        let wallet = self.vm().msg_sender();
        let key_hash: B256 = keccak(&reader);
        let block = self.vm().block_number();

        let mut entry = self.entries.setter(wallet);
        entry.key_hash.set(key_hash);
        entry.version.set(alloy_primitives::aliases::U8::from(version));
        entry.published_at.set(alloy_primitives::aliases::U64::from(block));

        self.vm().log(ReaderPublished { wallet, version, reader: reader.0.into() });
        Ok(())
    }

    /// Withdraw the key, so senders are told this wallet cannot be paid.
    /// Reverts on an empty entry: answering "done" to a wallet that never
    /// published would let someone believe they closed an exposure they never
    /// had.
    #[selector(name = "revokeReader")]
    pub fn revoke_reader(&mut self) -> Result<(), RegistryError> {
        let wallet = self.vm().msg_sender();
        if self.entries.get(wallet).key_hash.get().is_zero() {
            return Err(RegistryError::NothingToRevoke(NothingToRevoke {}));
        }
        let mut entry = self.entries.setter(wallet);
        entry.key_hash.set(B256::ZERO);
        entry.version.set(alloy_primitives::aliases::U8::ZERO);
        entry.published_at.set(alloy_primitives::aliases::U64::ZERO);

        self.vm().log(ReaderRevoked { wallet });
        Ok(())
    }

    /// What is known on chain about a wallet's key:
    /// `(keyHash, version, publishedAt)`; hash is zero if never published.
    #[selector(name = "readerOf")]
    pub fn reader_of(&self, wallet: Address) -> (FixedBytes<32>, u8, u64) {
        let entry = self.entries.get(wallet);
        (
            entry.key_hash.get(),
            entry.version.get().to::<u8>(),
            entry.published_at.get().to::<u64>(),
        )
    }

    /// Has this wallet published a key at all. A sender must check this
    /// before sealing: an envelope to an unregistered wallet is money sent
    /// into silence.
    #[selector(name = "isRegistered")]
    pub fn is_registered(&self, wallet: Address) -> bool {
        !self.entries.get(wallet).key_hash.get().is_zero()
    }

    /// Check that a key read from a log is the one this wallet published.
    #[selector(name = "matchesPublished")]
    pub fn matches_published(&self, wallet: Address, reader: Bytes) -> bool {
        self.entries.get(wallet).key_hash.get() == keccak(&reader)
    }
}
