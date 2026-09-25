//! Hidden-amount shielded pool for a single ERC-20, on Stylus.
//!
//! Notes of any size. The amount lives inside the commitment,
//! `Poseidon(secret, nullifier, amount)`, and the circuits prove it is in
//! range — so the chain never learns how much a note is worth, only that a
//! note exists. Three operations:
//!
//! - `deposit`: fund a note. The amount is visible here, because an ERC-20
//!   transfer is; this is the pool's only public number on the way in.
//! - `transferNote`: spend one note into two new ones (join-split). No token
//!   moves, no amount appears — a payment inside the pool is two opaque
//!   commitments and one nullifier.
//! - `withdraw`: leave the pool. The amount is public here, because the pool
//!   has to know how much to pay out.
//!
//! This mirrors `contracts/src/Tidex6HiddenPool.sol` and, through it, the
//! Solana program `programs/tidex6-confidential-pool`: same tree, same root
//! ring, same Poseidon (its own contract, see `stylus/poseidon`), same public
//! inputs in the same order. The circuits are `tidex6-confidential::withdraw`
//! (eight inputs) and `tidex6-confidential::transfer` (four).
//!
//! Recipient and relayer are bound as two 128-bit halves of the 32-byte word
//! the circuit takes — the same split the Solana program uses for a 32-byte
//! pubkey, so one circuit serves both chains. An address is 160 bits, so the
//! high half carries its top 32 bits and the low half the remaining 128.
//!
//! Multichain, not cross-chain: this pool knows nothing about any other
//! chain's state and must never be taught to. Deposit here, withdraw here.

#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
extern crate alloc;

// The stylus-proc macros (`#[storage]`, `#[public]`, `sol!`) expand to `Vec`
// and `vec!`; under `no_std` nobody imports those for us.
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

/// Depth of the incremental tree. Fixed at compile time in the circuits.
pub const TREE_DEPTH: usize = 20;

/// How many past roots stay acceptable. A proof built against a root that was
/// current when the user started is still valid a few insertions later.
pub const ROOT_RING_SIZE: usize = 30;

/// Largest note the circuits accept: the range proof covers 64 bits.
pub const MAX_AMOUNT: u64 = u64::MAX;

sol! {
    event Deposit(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, address depositor, uint256 amount, bytes envelope);
    event NoteCreated(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, bytes envelope);
    event Withdrawal(uint256 indexed nullifierHash, address indexed recipient, address relayer, uint256 fee, uint256 amount);

    error NotAFieldElement();
    error CommitmentAlreadyUsed();
    error TreeFull();
    error RootNotRecent();
    error NullifierAlreadySpent();
    error InvalidProof();
    error AmountOutOfRange();
    error FeeExceedsAmount();
    error TransferFailed();
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
}

#[storage]
#[entrypoint]
pub struct Tidex6HiddenPool {
    /// The token this pool holds.
    token: StorageAddress,
    /// Groth16 verifier for the hidden-amount withdraw circuit (8 inputs).
    withdraw_verifier: StorageAddress,
    /// Groth16 verifier for the join-split circuit (4 inputs).
    transfer_verifier: StorageAddress,
    /// Poseidon-T3 contract: the Merkle parent hash lives there, not here, so
    /// this contract fits the 24 KB code limit (see `stylus/poseidon`).
    poseidon: StorageAddress,
    /// Next free leaf.
    next_leaf_index: StorageU256,
    /// Head of the root ring.
    root_ring_head: StorageU256,
    /// Right-most filled node per level, for incremental insertion.
    filled_subtrees: StorageArray<StorageU256, TREE_DEPTH>,
    /// Hash of an empty subtree per level.
    zero_subtrees: StorageArray<StorageU256, TREE_DEPTH>,
    /// Recent roots, oldest overwritten.
    root_history: StorageArray<StorageU256, ROOT_RING_SIZE>,
    /// Spent nullifiers. The double-spend guard.
    nullifier_spent: StorageMap<U256, StorageBool>,
    /// Commitments already in the tree, so an accidental repeat is rejected
    /// rather than creating a note the owner cannot distinguish.
    commitment_known: StorageMap<U256, StorageBool>,
}

#[public]
impl Tidex6HiddenPool {
    /// Bind the pool to a token, its two verifiers and the Poseidon contract,
    /// and compute the empty-subtree hashes level by level — exactly as the
    /// Solana program does at initialisation.
    #[constructor]
    pub fn constructor(
        &mut self,
        token: Address,
        withdraw_verifier: Address,
        transfer_verifier: Address,
        poseidon: Address,
    ) {
        self.token.set(token);
        self.withdraw_verifier.set(withdraw_verifier);
        self.transfer_verifier.set(transfer_verifier);
        self.poseidon.set(poseidon);

        let mut zero_hash = U256::ZERO;
        for level in 0..TREE_DEPTH {
            self.zero_subtrees.setter(level).unwrap().set(zero_hash);
            self.filled_subtrees.setter(level).unwrap().set(zero_hash);
            // Both inputs are field elements by construction: `None` is unreachable.
            zero_hash = self.hash_pair(zero_hash, zero_hash).unwrap_or(U256::ZERO);
        }
        self.root_history.setter(0).unwrap().set(zero_hash);
    }

    /// Fund a note of `amount` base units. `commitment` is
    /// `Poseidon(secret, nullifier, amount)`, computed by the client; the pool
    /// cannot check it and does not need to — a commitment that does not match
    /// its amount is a note nobody can ever withdraw. `envelope` is sealed for
    /// the recipient before anything left the sender's browser.
    pub fn deposit(&mut self, amount: U256, commitment: U256, envelope: Bytes) -> Result<(), PoolError> {
        if amount.is_zero() || amount > U256::from(MAX_AMOUNT) {
            return Err(PoolError::AmountOutOfRange(AmountOutOfRange {}));
        }
        let leaf_index = self.reserve_leaf(commitment, 1)?;
        let depositor = self.vm().msg_sender();
        let new_root = self.append_leaf(leaf_index, commitment)?;
        self.vm().log(Deposit {
            commitment,
            leafIndex: leaf_index,
            newRoot: new_root,
            depositor,
            amount,
            envelope: envelope.0.into(),
        });

        // Token pulled last, after the tree is final — the same order as the
        // Solidity pool. Stylus already refuses re-entry; this keeps the two
        // implementations one design.
        let pool = self.vm().contract_address();
        if !self.token_transfer_from(depositor, pool, amount) {
            return Err(PoolError::TransferFailed(TransferFailed {}));
        }
        Ok(())
    }

    /// Fund a payment note and its fee note in one call: one token pull of
    /// `amount + fee_amount`, two leaves, two `Deposit` logs — the same logs
    /// two `deposit` calls emit, so every reader of the pool sees them
    /// unchanged. One call is one wallet approval, and the pair can no longer
    /// come apart when the separate fee transaction fails.
    #[selector(name = "depositWithFee")]
    pub fn deposit_with_fee(
        &mut self,
        amount: U256,
        commitment: U256,
        envelope: Bytes,
        fee_amount: U256,
        fee_commitment: U256,
        fee_envelope: Bytes,
    ) -> Result<(), PoolError> {
        let max = U256::from(MAX_AMOUNT);
        if amount.is_zero() || amount > max || fee_amount.is_zero() || fee_amount > max {
            return Err(PoolError::AmountOutOfRange(AmountOutOfRange {}));
        }
        // Equal commitments fail here: the first reservation marks it known.
        let first_leaf = self.reserve_leaf(commitment, 2)?;
        self.reserve_leaf(fee_commitment, 1)?;

        let depositor = self.vm().msg_sender();
        let root1 = self.append_leaf(first_leaf, commitment)?;
        self.vm().log(Deposit {
            commitment,
            leafIndex: first_leaf,
            newRoot: root1,
            depositor,
            amount,
            envelope: envelope.0.into(),
        });
        let second_leaf = first_leaf + U256::from(1);
        let root2 = self.append_leaf(second_leaf, fee_commitment)?;
        self.vm().log(Deposit {
            commitment: fee_commitment,
            leafIndex: second_leaf,
            newRoot: root2,
            depositor,
            amount: fee_amount,
            envelope: fee_envelope.0.into(),
        });

        // Both amounts fit 64 bits; the sum cannot overflow.
        let pool = self.vm().contract_address();
        if !self.token_transfer_from(depositor, pool, amount + fee_amount) {
            return Err(PoolError::TransferFailed(TransferFailed {}));
        }
        Ok(())
    }

    /// Spend one note into two. The proof shows the spent note is in the tree,
    /// its nullifier is this one, and the two new commitments carry amounts
    /// that sum to it — all amounts hidden. No token moves.
    #[selector(name = "transferNote")]
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_note(
        &mut self,
        proof_a: [U256; 2],
        proof_b: [[U256; 2]; 2],
        proof_c: [U256; 2],
        merkle_root: U256,
        nullifier_hash: U256,
        commitment_out1: U256,
        commitment_out2: U256,
        envelope1: Bytes,
        envelope2: Bytes,
    ) -> Result<(), PoolError> {
        if self.nullifier_spent.get(nullifier_hash) {
            return Err(PoolError::NullifierAlreadySpent(NullifierAlreadySpent {}));
        }
        if !self.is_known_root_inner(merkle_root) {
            return Err(PoolError::RootNotRecent(RootNotRecent {}));
        }
        // Two equal outputs fail here as well: the first reservation marks the
        // commitment known and the second one trips on it.
        let first_leaf = self.reserve_leaf(commitment_out1, 2)?;
        self.reserve_leaf(commitment_out2, 1)?;

        let public_inputs = [merkle_root, nullifier_hash, commitment_out1, commitment_out2];
        let verifier = self.transfer_verifier.get();
        if !self.verify_proof(verifier, SEL_VERIFY_PROOF_4, &proof_a, &proof_b, &proof_c, &public_inputs) {
            return Err(PoolError::InvalidProof(InvalidProof {}));
        }

        // Spend before inserting: the nullifier is the double-spend guard. The
        // spent nullifier is readable through `nullifierSpent`; no event, the
        // contract has 24 KB and the two `NoteCreated` logs already mark the
        // transaction.
        self.nullifier_spent.insert(nullifier_hash, true);

        let root1 = self.append_leaf(first_leaf, commitment_out1)?;
        self.vm().log(NoteCreated {
            commitment: commitment_out1,
            leafIndex: first_leaf,
            newRoot: root1,
            envelope: envelope1.0.into(),
        });
        let second_leaf = first_leaf + U256::from(1);
        let root2 = self.append_leaf(second_leaf, commitment_out2)?;
        self.vm().log(NoteCreated {
            commitment: commitment_out2,
            leafIndex: second_leaf,
            newRoot: root2,
            envelope: envelope2.0.into(),
        });
        Ok(())
    }

    /// Withdraw a note of `amount` to `recipient`, paying `relayer` a `fee` out
    /// of it. Recipient, relayer, fee and amount are public inputs to the
    /// proof: a relayer cannot redirect the payment, raise its fee or change
    /// the amount — any change invalidates the proof. The amount's range is
    /// the circuit's business: `amount` is the range-proved note amount, so
    /// no check on it here.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        &mut self,
        proof_a: [U256; 2],
        proof_b: [[U256; 2]; 2],
        proof_c: [U256; 2],
        merkle_root: U256,
        nullifier_hash: U256,
        recipient: Address,
        relayer: Address,
        fee: U256,
        amount: U256,
    ) -> Result<(), PoolError> {
        if self.nullifier_spent.get(nullifier_hash) {
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
            nullifier_hash,
            recipient_hi,
            recipient_lo,
            relayer_hi,
            relayer_lo,
            fee,
            amount,
        ];
        let verifier = self.withdraw_verifier.get();
        if !self.verify_proof(verifier, SEL_VERIFY_PROOF_8, &proof_a, &proof_b, &proof_c, &public_inputs) {
            return Err(PoolError::InvalidProof(InvalidProof {}));
        }

        // Spend before paying: the nullifier is the double-spend guard, and it
        // must be set before any external call.
        self.nullifier_spent.insert(nullifier_hash, true);

        let payout = amount - fee;
        if !self.token_transfer(recipient, payout) {
            return Err(PoolError::TransferFailed(TransferFailed {}));
        }
        if !fee.is_zero() && !self.token_transfer(relayer, fee) {
            return Err(PoolError::TransferFailed(TransferFailed {}));
        }

        self.vm().log(Withdrawal { nullifierHash: nullifier_hash, recipient, relayer, fee, amount });
        Ok(())
    }

    /// Current tree root.
    #[selector(name = "currentRoot")]
    pub fn current_root(&self) -> U256 {
        let head = self.root_ring_head.get().to::<usize>();
        self.root_history.get(head).unwrap_or(U256::ZERO)
    }

    /// Is this root recent enough to prove against?
    #[selector(name = "isKnownRoot")]
    pub fn is_known_root(&self, root: U256) -> bool {
        self.is_known_root_inner(root)
    }

    /// Has this nullifier been spent?
    #[selector(name = "nullifierSpent")]
    pub fn nullifier_spent(&self, nullifier_hash: U256) -> bool {
        self.nullifier_spent.get(nullifier_hash)
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
/// `verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[4])`.
const SEL_VERIFY_PROOF_4: [u8; 4] = [0x5f, 0xe8, 0xc1, 0x3b];

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

impl Tidex6HiddenPool {
    /// Check a commitment can enter the tree and that `count` leaves are free;
    /// mark it known and return the index of the first of them. The index is
    /// not advanced here — `append_leaf` does that as it inserts.
    fn reserve_leaf(&mut self, commitment: U256, count: u64) -> Result<U256, PoolError> {
        if !is_field_element(commitment) {
            return Err(PoolError::NotAFieldElement(NotAFieldElement {}));
        }
        if self.commitment_known.get(commitment) {
            return Err(PoolError::CommitmentAlreadyUsed(CommitmentAlreadyUsed {}));
        }
        let leaf_index = self.next_leaf_index.get();
        if leaf_index + U256::from(count) > U256::from(1u64 << TREE_DEPTH) {
            return Err(PoolError::TreeFull(TreeFull {}));
        }
        self.commitment_known.insert(commitment, true);
        Ok(leaf_index)
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
                self.filled_subtrees.setter(level).unwrap().set(current_hash);
                (current_hash, self.zero_subtrees.get(level).unwrap_or(U256::ZERO))
            } else {
                (self.filled_subtrees.get(level).unwrap_or(U256::ZERO), current_hash)
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
