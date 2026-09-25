//! Hidden-amount shielded pool v2 for a single ERC-20, on Stylus (ADR-022).
//!
//! Mirrors `contracts/src/Tidex6HiddenPoolV2.sol`. Two properties the v1 pool
//! lacked, both by construction:
//!
//! - **The pool files the leaf.** A depositor hands in the note's `core`
//!   together with the tokens; the pool computes
//!   `leaf = H(H(core, amount), refund)` from the amount it received. A note
//!   cannot claim more than was paid into it.
//! - **Only the owner spends.** The withdraw circuit proves the owner's
//!   spending key. The funder may take a note back through `refund` — no proof,
//!   only after its window, checked against a leaf rebuilt with the caller in
//!   the funder's place. Both paths share the position-bound nullifier
//!   `H(H(D_NF, rho), position)`. Fee notes carry no refund.
//!
//! Multichain, not cross-chain. Deposit here, withdraw here.

#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
extern crate alloc;

#[allow(unused_imports)]
use alloc::vec;
#[allow(unused_imports)]
use alloc::vec::Vec;

use alloy_primitives::{Address, U256};
use alloy_sol_types::sol;
use stylus_sdk::abi::Bytes;
use stylus_sdk::call::{call, static_call};
use stylus_sdk::prelude::*;
use stylus_sdk::storage::{StorageAddress, StorageArray, StorageBool, StorageMap, StorageU256};

use tidex6_stylus_common::field::is_field_element;

pub const TREE_DEPTH: usize = 20;
pub const ROOT_RING_SIZE: usize = 30;
pub const MAX_AMOUNT: u64 = u64::MAX;
/// Refund windows a depositor may choose; zero means no refund.
pub const MIN_REFUND_WINDOW: u64 = 5 * 60;
pub const MAX_REFUND_WINDOW: u64 = 30 * 24 * 60 * 60;
/// The fee: 1% of the payment, rounded up, never below `fee_floor`.
pub const FEE_PERCENT_DIVISOR: u64 = 100;
/// Hash domains — the same constants as `tidex6-confidential::note_v2`.
pub const D_CORE: u64 = 0x7469_6478_3602;
pub const D_NF: u64 = 0x7469_6478_3603;

sol! {
    event Deposit(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, address depositor, uint256 amount, uint256 refundAfter, bytes envelope);
    event NoteCreated(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, bytes envelope);
    event Withdrawal(uint256 indexed nullifier, address indexed recipient, address relayer, uint256 fee, uint256 amount);
    event Refunded(uint256 indexed nullifier, address indexed funder, uint256 amount);

    error NotAFieldElement();
    error CommitmentAlreadyUsed();
    error TreeFull();
    error RootNotRecent();
    error NullifierAlreadySpent();
    error InvalidProof();
    error AmountOutOfRange();
    error FeeExceedsAmount();
    error TransferFailed();
    error RefundWindowOutOfRange();
    error UnknownNote();
    error RefundNotYet();
}

#[derive(SolidityError)]
pub enum PoolError {
    NotAFieldElement(NotAFieldElement),
    CommitmentAlreadyUsed(CommitmentAlreadyUsed),
    TreeFull(TreeFull),
    RootNotRecent(RootNotRecent),
    NullifierAlreadySpent(NullifierAlreadySpent),
    InvalidProof(InvalidProof),
    AmountOutOfRange(AmountOutOfRange),
    FeeExceedsAmount(FeeExceedsAmount),
    TransferFailed(TransferFailed),
    RefundWindowOutOfRange(RefundWindowOutOfRange),
    UnknownNote(UnknownNote),
    RefundNotYet(RefundNotYet),
}

#[storage]
#[entrypoint]
pub struct Tidex6HiddenPoolV2 {
    token: StorageAddress,
    withdraw_verifier: StorageAddress,
    transfer_verifier: StorageAddress,
    /// Poseidon-T3 contract, kept out of this one for the 24 KB limit.
    poseidon: StorageAddress,
    /// Owner key of the treasury: every fee note is filed for it.
    treasury_owner_pk: StorageU256,
    /// Smallest fee in base units.
    fee_floor: StorageU256,
    next_leaf_index: StorageU256,
    root_ring_head: StorageU256,
    filled_subtrees: StorageArray<StorageU256, TREE_DEPTH>,
    zero_subtrees: StorageArray<StorageU256, TREE_DEPTH>,
    root_history: StorageArray<StorageU256, ROOT_RING_SIZE>,
    /// Spent nullifiers — the guard for both spending paths.
    nullifier_spent: StorageMap<U256, StorageBool>,
    /// Leaf position plus one; zero — not in the tree. A refund needs the
    /// position its nullifier is derived from.
    leaf_position_plus_one: StorageMap<U256, StorageU256>,
}

#[public]
impl Tidex6HiddenPoolV2 {
    #[constructor]
    pub fn constructor(
        &mut self,
        token: Address,
        withdraw_verifier: Address,
        transfer_verifier: Address,
        poseidon: Address,
        treasury_owner_pk: U256,
        fee_floor: U256,
    ) {
        self.token.set(token);
        self.withdraw_verifier.set(withdraw_verifier);
        self.transfer_verifier.set(transfer_verifier);
        self.poseidon.set(poseidon);
        self.treasury_owner_pk.set(treasury_owner_pk);
        self.fee_floor.set(fee_floor);

        let mut zero_hash = U256::ZERO;
        for level in 0..TREE_DEPTH {
            self.zero_subtrees.setter(level).unwrap().set(zero_hash);
            self.filled_subtrees.setter(level).unwrap().set(zero_hash);
            zero_hash = self.hash_pair(zero_hash, zero_hash).unwrap_or(U256::ZERO);
        }
        self.root_history.setter(0).unwrap().set(zero_hash);
    }

    /// Fund a note of `amount` for the owner of `core` and the fee on it for
    /// the treasury; the sender is charged `amount + fee_for(amount)`. The fee
    /// note's core is built here from the treasury key, with no refund.
    #[allow(clippy::too_many_arguments)]
    pub fn deposit(
        &mut self,
        core: U256,
        amount: U256,
        refund_window: U256,
        envelope: Bytes,
        fee_rho: U256,
        fee_envelope: Bytes,
    ) -> Result<(), PoolError> {
        if !is_field_element(fee_rho) {
            return Err(PoolError::NotAFieldElement(NotAFieldElement {}));
        }
        let fee = self.fee_for(amount);
        let refund_after = self.refund_after(refund_window)?;
        let first_leaf = self.reserve_leaves(2)?;
        self.file_note(core, amount, refund_after, envelope, first_leaf)?;
        let fee_core = self.treasury_core(fee_rho)?;
        self.file_note(
            fee_core,
            fee,
            U256::ZERO,
            fee_envelope,
            first_leaf + U256::from(1),
        )?;
        let depositor = self.vm().msg_sender();
        let pool = self.vm().contract_address();
        if !self.token_transfer_from(depositor, pool, amount + fee) {
            return Err(PoolError::TransferFailed(TransferFailed {}));
        }
        Ok(())
    }

    /// The fee on a payment of `amount`: 1% rounded up, at least the floor.
    #[selector(name = "feeFor")]
    pub fn fee_for(&self, amount: U256) -> U256 {
        let divisor = U256::from(FEE_PERCENT_DIVISOR);
        let percent = (amount + divisor - U256::from(1)) / divisor;
        percent.max(self.fee_floor.get())
    }

    /// Forward a note inside the pool: a payment, change back to the spender,
    /// the fee to the treasury (`transfer_v2`). The pool supplies its own
    /// treasury key and floor as public inputs. No token moves.
    #[selector(name = "transferNote")]
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_note(
        &mut self,
        proof_a: [U256; 2],
        proof_b: [[U256; 2]; 2],
        proof_c: [U256; 2],
        merkle_root: U256,
        nullifier: U256,
        out: (U256, U256, U256, Bytes, Bytes, Bytes),
    ) -> Result<(), PoolError> {
        let (pay, change, fee, pay_envelope, change_envelope, fee_envelope) = out;
        if self.nullifier_spent.get(nullifier) {
            return Err(PoolError::NullifierAlreadySpent(NullifierAlreadySpent {}));
        }
        if !self.is_known_root_inner(merkle_root) {
            return Err(PoolError::RootNotRecent(RootNotRecent {}));
        }
        let first_leaf = self.reserve_leaves(3)?;
        let one = U256::from(1);
        self.mark_leaf(pay, first_leaf)?;
        self.mark_leaf(change, first_leaf + one)?;
        self.mark_leaf(fee, first_leaf + one + one)?;

        let public_inputs = [
            merkle_root,
            nullifier,
            pay,
            change,
            fee,
            self.treasury_owner_pk.get(),
            self.fee_floor.get(),
        ];
        let verifier = self.transfer_verifier.get();
        if !self.verify_proof(
            verifier,
            SEL_VERIFY_PROOF_7,
            &proof_a,
            &proof_b,
            &proof_c,
            &public_inputs,
        ) {
            return Err(PoolError::InvalidProof(InvalidProof {}));
        }
        self.nullifier_spent.insert(nullifier, true);

        for (offset, leaf, envelope) in [
            (0u64, pay, pay_envelope),
            (1, change, change_envelope),
            (2, fee, fee_envelope),
        ] {
            let index = first_leaf + U256::from(offset);
            let root = self.append_leaf(index, leaf)?;
            self.vm().log(NoteCreated {
                commitment: leaf,
                leafIndex: index,
                newRoot: root,
                envelope: envelope.0.into(),
            });
        }
        Ok(())
    }

    /// Withdraw a note to `recipient`; only the owner can build the proof.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        &mut self,
        proof_a: [U256; 2],
        proof_b: [[U256; 2]; 2],
        proof_c: [U256; 2],
        merkle_root: U256,
        nullifier: U256,
        recipient: Address,
        relayer: Address,
        fee: U256,
        amount: U256,
    ) -> Result<(), PoolError> {
        if self.nullifier_spent.get(nullifier) {
            return Err(PoolError::NullifierAlreadySpent(NullifierAlreadySpent {}));
        }
        if fee > amount {
            return Err(PoolError::FeeExceedsAmount(FeeExceedsAmount {}));
        }
        if !self.is_known_root_inner(merkle_root) {
            return Err(PoolError::RootNotRecent(RootNotRecent {}));
        }
        let (recipient_hi, recipient_lo) = split_address(recipient);
        let (relayer_hi, relayer_lo) = split_address(relayer);
        let public_inputs = [
            merkle_root,
            nullifier,
            recipient_hi,
            recipient_lo,
            relayer_hi,
            relayer_lo,
            fee,
            amount,
        ];
        let verifier = self.withdraw_verifier.get();
        if !self.verify_proof(
            verifier,
            SEL_VERIFY_PROOF_8,
            &proof_a,
            &proof_b,
            &proof_c,
            &public_inputs,
        ) {
            return Err(PoolError::InvalidProof(InvalidProof {}));
        }
        self.nullifier_spent.insert(nullifier, true);

        if !self.token_transfer(recipient, amount - fee) {
            return Err(PoolError::TransferFailed(TransferFailed {}));
        }
        if !fee.is_zero() && !self.token_transfer(relayer, fee) {
            return Err(PoolError::TransferFailed(TransferFailed {}));
        }
        self.vm().log(Withdrawal {
            nullifier,
            recipient,
            relayer,
            fee,
            amount,
        });
        Ok(())
    }

    /// Take a note back after its window, if the owner has not spent it.
    pub fn refund(
        &mut self,
        owner_pk: U256,
        rho: U256,
        aux: U256,
        amount: U256,
        refund_after: U256,
    ) -> Result<(), PoolError> {
        if refund_after.is_zero() || U256::from(self.vm().block_timestamp()) < refund_after {
            return Err(PoolError::RefundNotYet(RefundNotYet {}));
        }
        let left = self.h(U256::from(D_CORE), owner_pk)?;
        let right = self.h(rho, aux)?;
        let core = self.h(left, right)?;
        let leaf = self.leaf(core, amount, refund_after)?;
        let position_plus_one = self.leaf_position_plus_one.get(leaf);
        if position_plus_one.is_zero() {
            return Err(PoolError::UnknownNote(UnknownNote {}));
        }
        let tagged = self.h(U256::from(D_NF), rho)?;
        let nullifier = self.h(tagged, position_plus_one - U256::from(1))?;
        if self.nullifier_spent.get(nullifier) {
            return Err(PoolError::NullifierAlreadySpent(NullifierAlreadySpent {}));
        }
        self.nullifier_spent.insert(nullifier, true);

        let funder = self.vm().msg_sender();
        if !self.token_transfer(funder, amount) {
            return Err(PoolError::TransferFailed(TransferFailed {}));
        }
        self.vm().log(Refunded {
            nullifier,
            funder,
            amount,
        });
        Ok(())
    }

    #[selector(name = "currentRoot")]
    pub fn current_root(&self) -> U256 {
        let head = self.root_ring_head.get().to::<usize>();
        self.root_history.get(head).unwrap_or(U256::ZERO)
    }

    #[selector(name = "isKnownRoot")]
    pub fn is_known_root(&self, root: U256) -> bool {
        self.is_known_root_inner(root)
    }

    #[selector(name = "nullifierSpent")]
    pub fn nullifier_spent(&self, nullifier: U256) -> bool {
        self.nullifier_spent.get(nullifier)
    }

    #[selector(name = "leafPositionPlusOne")]
    pub fn leaf_position_plus_one(&self, leaf: U256) -> U256 {
        self.leaf_position_plus_one.get(leaf)
    }
}

/// `transferFrom(address,address,uint256)`.
const SEL_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
/// `transfer(address,uint256)`.
const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
/// `hash(uint256,uint256)` on the Poseidon contract.
const SEL_POSEIDON_HASH: [u8; 4] = [0xa7, 0x8d, 0xac, 0x0d];
/// `verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[8])`.
const SEL_VERIFY_PROOF_8: [u8; 4] = [0xc9, 0x21, 0x9a, 0x7a];
/// `verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[7])`.
const SEL_VERIFY_PROOF_7: [u8; 4] = [0xc8, 0x94, 0xe7, 0x57];

/// Append a `U256` as a 32-byte big-endian word.
#[inline]
fn push_word(buf: &mut Vec<u8>, value: U256) {
    buf.extend_from_slice(&value.to_be_bytes::<32>());
}

/// Append an address left-padded to a 32-byte word.
#[inline]
fn push_address(buf: &mut Vec<u8>, value: Address) {
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(value.as_slice());
}

/// Did a call return ABI `true`? Anything else — `false`, empty, garbage — is
/// a failure, the same reading Solidity gives `(bool)` return data.
#[inline]
fn returned_true(data: &[u8]) -> bool {
    data.len() >= 32 && data[..31].iter().all(|b| *b == 0) && data[31] == 1
}

/// The two 128-bit halves of an address as a left-padded 32-byte word —
/// `(hi, lo)`, the circuit's `recipient_hi / recipient_lo`.
#[inline]
fn split_address(value: Address) -> (U256, U256) {
    let word = U256::from_be_slice(value.as_slice());
    let mask = (U256::from(1) << 128) - U256::from(1);
    (word >> 128, word & mask)
}

impl Tidex6HiddenPoolV2 {
    /// First of `count` free positions. `append_leaf` advances the index.
    fn reserve_leaves(&self, count: u64) -> Result<U256, PoolError> {
        let leaf_index = self.next_leaf_index.get();
        if leaf_index + U256::from(count) > U256::from(1u64 << TREE_DEPTH) {
            return Err(PoolError::TreeFull(TreeFull {}));
        }
        Ok(leaf_index)
    }

    /// Record that `leaf` sits at `position`; a leaf already in the tree is
    /// refused — two equal outputs of one call included.
    fn mark_leaf(&mut self, leaf: U256, position: U256) -> Result<(), PoolError> {
        if !is_field_element(leaf) {
            return Err(PoolError::NotAFieldElement(NotAFieldElement {}));
        }
        if !self.leaf_position_plus_one.get(leaf).is_zero() {
            return Err(PoolError::CommitmentAlreadyUsed(CommitmentAlreadyUsed {}));
        }
        self.leaf_position_plus_one
            .insert(leaf, position + U256::from(1));
        Ok(())
    }

    /// Poseidon that must succeed: every input here is checked or built as a
    /// field element, so a failure is an input out of the field.
    fn h(&self, left: U256, right: U256) -> Result<U256, PoolError> {
        self.hash_pair(left, right)
            .ok_or(PoolError::NotAFieldElement(NotAFieldElement {}))
    }

    /// The leaf the pool files for `core` funded with `amount` by the caller.
    fn leaf(&self, core: U256, amount: U256, refund_after: U256) -> Result<U256, PoolError> {
        if !is_field_element(core) {
            return Err(PoolError::NotAFieldElement(NotAFieldElement {}));
        }
        if amount.is_zero() || amount > U256::from(MAX_AMOUNT) {
            return Err(PoolError::AmountOutOfRange(AmountOutOfRange {}));
        }
        let body = self.h(core, amount)?;
        let refund_tag = if refund_after.is_zero() {
            U256::ZERO
        } else {
            let funder = U256::from_be_slice(self.vm().msg_sender().as_slice());
            self.h(funder, refund_after)?
        };
        self.h(body, refund_tag)
    }

    /// File one funded note at `position`: its leaf from the amount, its
    /// position, the insertion and the log.
    fn file_note(
        &mut self,
        core: U256,
        amount: U256,
        refund_after: U256,
        envelope: Bytes,
        position: U256,
    ) -> Result<(), PoolError> {
        let leaf = self.leaf(core, amount, refund_after)?;
        self.mark_leaf(leaf, position)?;
        let new_root = self.append_leaf(position, leaf)?;
        let depositor = self.vm().msg_sender();
        self.vm().log(Deposit {
            commitment: leaf,
            leafIndex: position,
            newRoot: new_root,
            depositor,
            amount,
            refundAfter: refund_after,
            envelope: envelope.0.into(),
        });
        Ok(())
    }

    /// Core of a fee note: owned by the treasury, randomness from the sender.
    fn treasury_core(&self, fee_rho: U256) -> Result<U256, PoolError> {
        let left = self.h(U256::from(D_CORE), self.treasury_owner_pk.get())?;
        let right = self.h(fee_rho, U256::ZERO)?;
        self.h(left, right)
    }

    /// `now + window`, or 0 for "no refund".
    fn refund_after(&self, window: U256) -> Result<U256, PoolError> {
        if window.is_zero() {
            return Ok(U256::ZERO);
        }
        if window < U256::from(MIN_REFUND_WINDOW) || window > U256::from(MAX_REFUND_WINDOW) {
            return Err(PoolError::RefundWindowOutOfRange(RefundWindowOutOfRange {}));
        }
        Ok(U256::from(self.vm().block_timestamp()) + window)
    }

    /// `token.transferFrom(from, to, amount)`. Raw call on purpose: the typed
    /// interface the SDK generates decodes the answer through alloy's
    /// validating decoder, and that path alone weighed several kilobytes of
    /// WASM. Here the answer is one word, read by hand.
    fn token_transfer_from(&mut self, from: Address, to: Address, amount: U256) -> bool {
        let mut data = Vec::with_capacity(4 + 96);
        data.extend_from_slice(&SEL_TRANSFER_FROM);
        push_address(&mut data, from);
        push_address(&mut data, to);
        push_word(&mut data, amount);
        let token = self.token.get();
        let context = Call::new_mutating(self);
        match call(self.vm(), context, token, &data) {
            Ok(out) => returned_true(&out),
            Err(_) => false,
        }
    }

    /// `token.transfer(to, amount)`.
    fn token_transfer(&mut self, to: Address, amount: U256) -> bool {
        let mut data = Vec::with_capacity(4 + 64);
        data.extend_from_slice(&SEL_TRANSFER);
        push_address(&mut data, to);
        push_word(&mut data, amount);
        let token = self.token.get();
        let context = Call::new_mutating(self);
        match call(self.vm(), context, token, &data) {
            Ok(out) => returned_true(&out),
            Err(_) => false,
        }
    }

    /// `verifier.verifyProof(a, b, c, inputs)` — a static call, the verifier
    /// holds no state. `selector` picks the input-array width.
    fn verify_proof(
        &self,
        verifier: Address,
        selector: [u8; 4],
        proof_a: &[U256; 2],
        proof_b: &[[U256; 2]; 2],
        proof_c: &[U256; 2],
        public_inputs: &[U256],
    ) -> bool {
        let mut data = Vec::with_capacity(4 + (8 + public_inputs.len()) * 32);
        data.extend_from_slice(&selector);
        for w in proof_a {
            push_word(&mut data, *w);
        }
        for w in proof_b.iter().flatten() {
            push_word(&mut data, *w);
        }
        for w in proof_c {
            push_word(&mut data, *w);
        }
        for w in public_inputs {
            push_word(&mut data, *w);
        }
        match static_call(self.vm(), Call::new(), verifier, &data) {
            Ok(out) => returned_true(&out),
            Err(_) => false,
        }
    }

    /// Poseidon(left, right) through the Poseidon contract. `None` on any
    /// failure — a revert there means an input was not a field element.
    fn hash_pair(&self, left: U256, right: U256) -> Option<U256> {
        let mut data = Vec::with_capacity(4 + 64);
        data.extend_from_slice(&SEL_POSEIDON_HASH);
        push_word(&mut data, left);
        push_word(&mut data, right);
        match static_call(self.vm(), Call::new(), self.poseidon.get(), &data) {
            Ok(out) if out.len() == 32 => Some(U256::from_be_slice(&out)),
            _ => None,
        }
    }

    /// Append a leaf and return the new root. Same walk the Solana program does.
    fn append_leaf(&mut self, leaf_index: U256, leaf: U256) -> Result<U256, PoolError> {
        let mut current_index = leaf_index.to::<u64>();
        let mut current_hash = leaf;

        for level in 0..TREE_DEPTH {
            let (left, right) = if current_index & 1 == 0 {
                self.filled_subtrees
                    .setter(level)
                    .unwrap()
                    .set(current_hash);
                (
                    current_hash,
                    self.zero_subtrees.get(level).unwrap_or(U256::ZERO),
                )
            } else {
                (
                    self.filled_subtrees.get(level).unwrap_or(U256::ZERO),
                    current_hash,
                )
            };
            current_hash = self
                .hash_pair(left, right)
                .ok_or(PoolError::NotAFieldElement(NotAFieldElement {}))?;
            current_index >>= 1;
        }

        self.next_leaf_index.set(leaf_index + U256::from(1));
        let head = (self.root_ring_head.get().to::<usize>() + 1) % ROOT_RING_SIZE;
        self.root_ring_head.set(U256::from(head));
        self.root_history.setter(head).unwrap().set(current_hash);
        Ok(current_hash)
    }

    /// A root counts as known while it is still in the ring. Zero never does —
    /// an uninitialised slot must not authorise a spend.
    fn is_known_root_inner(&self, root: U256) -> bool {
        if root.is_zero() {
            return false;
        }
        (0..ROOT_RING_SIZE).any(|i| self.root_history.get(i) == Some(root))
    }
}
