//! Owner keys of the v2 pools, on Stylus (ADR-022).
//!
//! Mirrors `contracts/src/Tidex6OwnerKeys.sol`: a v2 note is bound to its
//! recipient's owner key, a sender knows only a wallet address, so the
//! wallet publishes its owner key here once per chain. Only the wallet sets
//! its own entry; a replaced key does not strand old notes.

#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
extern crate alloc;

#[allow(unused_imports)]
use alloc::vec;
#[allow(unused_imports)]
use alloc::vec::Vec;

use alloy_primitives::{Address, U256};
use alloy_sol_types::sol;
use stylus_sdk::prelude::*;
use stylus_sdk::storage::{StorageMap, StorageU256};

use tidex6_stylus_common::field::is_field_element;

sol! {
    event OwnerKeyPublished(address indexed wallet, uint256 ownerPk);
    error NotAFieldElement();
}

#[derive(SolidityError)]
pub enum OwnerKeysError {
    NotAFieldElement(NotAFieldElement),
}

#[storage]
#[entrypoint]
pub struct Tidex6OwnerKeys {
    owner_key_of: StorageMap<Address, StorageU256>,
}

#[public]
impl Tidex6OwnerKeys {
    /// Publish (or replace) the caller's owner key.
    #[selector(name = "publishOwnerKey")]
    pub fn publish_owner_key(&mut self, owner_pk: U256) -> Result<(), OwnerKeysError> {
        if owner_pk.is_zero() || !is_field_element(owner_pk) {
            return Err(OwnerKeysError::NotAFieldElement(NotAFieldElement {}));
        }
        let wallet = self.vm().msg_sender();
        self.owner_key_of.insert(wallet, owner_pk);
        self.vm().log(OwnerKeyPublished { wallet, ownerPk: owner_pk });
        Ok(())
    }

    /// Owner key of `wallet`; zero — none published.
    #[selector(name = "ownerKeyOf")]
    pub fn owner_key_of(&self, wallet: Address) -> U256 {
        self.owner_key_of.get(wallet)
    }
}
