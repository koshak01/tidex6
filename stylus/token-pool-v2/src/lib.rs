//! Shielded pool v2 for a confidential token, on Stylus (ADR-023).
//!
//! Mirrors `contracts/src/Tidex6TokenPoolV2.sol`: the note format, tree,
//! nullifiers, fee policy and in-pool transfer of `hidden-pool-v2`
//! (ADR-022), with custody in the confidential token. This pool holds no
//! ERC-20; the token holds the underlying for its notes as well as for the
//! encrypted balances, so value crosses between them without a transfer that
//! would print the amount.
//!
//! - `depositFromToken` — token only, after it verified `DepositFromToken`:
//!   files the payment and fee leaves the proof fixed.
//! - `withdrawToToken` — the owner proves `WithdrawToToken`; the amount lands
//!   on the recipient's pending balance as a ciphertext.
//! - `withdraw` — `withdraw_v2`; the token pays the public amount.
//! - `transferNote` — the v2 forward, unchanged.
//!
//! No `refund`: notes here never had a public amount to rebuild a leaf from.

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

sol! {
    event DepositFromToken(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, bytes envelope);
    event NoteCreated(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, bytes envelope);
    event Withdrawal(uint256 indexed nullifier, address indexed recipient, address relayer, uint256 fee, uint256 amount);
    event WithdrawalToToken(uint256 indexed nullifier);

    error NotAFieldElement();
    error CommitmentAlreadyUsed();
    error TreeFull();
    error RootNotRecent();
    error NullifierAlreadySpent();
    error InvalidProof();
    error FeeExceedsAmount();
    error OnlyToken();
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
    FeeExceedsAmount(FeeExceedsAmount),
    OnlyToken(OnlyToken),
    TransferFailed(TransferFailed),
}

#[storage]
#[entrypoint]
pub struct Tidex6TokenPoolV2 {
    /// The confidential token: custody and the only depositor.
    token: StorageAddress,
    withdraw_verifier: StorageAddress,
    transfer_verifier: StorageAddress,
    exit_verifier: StorageAddress,
    /// Poseidon-T3 contract, kept out of this one for the 24 KB limit.
    poseidon: StorageAddress,
    /// Owner key of the treasury: every fee note is filed for it.
    treasury_owner_pk: StorageU256,
    /// Smallest fee, in token units.
    fee_floor: StorageU256,
    next_leaf_index: StorageU256,
    root_ring_head: StorageU256,
    filled_subtrees: StorageArray<StorageU256, TREE_DEPTH>,
    zero_subtrees: StorageArray<StorageU256, TREE_DEPTH>,
    root_history: StorageArray<StorageU256, ROOT_RING_SIZE>,
    /// Spent nullifiers — one guard for all three spending paths.
    nullifier_spent: StorageMap<U256, StorageBool>,
    /// Leaf position plus one; zero — not in the tree.
    leaf_position_plus_one: StorageMap<U256, StorageU256>,
}

#[public]
impl Tidex6TokenPoolV2 {
    #[constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn constructor(
        &mut self,
        token: Address,
        withdraw_verifier: Address,
        transfer_verifier: Address,
        exit_verifier: Address,
        poseidon: Address,
        treasury_owner_pk: U256,
        fee_floor: U256,
    ) -> Result<(), PoolError> {
        if !is_field_element(treasury_owner_pk) {
            return Err(PoolError::NotAFieldElement(NotAFieldElement {}));
        }
        self.token.set(token);
        self.withdraw_verifier.set(withdraw_verifier);
        self.transfer_verifier.set(transfer_verifier);
        self.exit_verifier.set(exit_verifier);
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
        Ok(())
    }

    /// File the payment and fee notes of a deposit from an encrypted balance.
    /// Token only: it verified the proof that fixes both leaves and checked
    /// the fee policy against this pool's treasury key and floor.
    #[selector(name = "depositFromToken")]
    pub fn deposit_from_token(
        &mut self,
        commitment_pay: U256,
        commitment_fee: U256,
        pay_envelope: Bytes,
        fee_envelope: Bytes,
    ) -> Result<(), PoolError> {
        if self.vm().msg_sender() != self.token.get() {
            return Err(PoolError::OnlyToken(OnlyToken {}));
        }
        let first_leaf = self.reserve_leaves(2)?;
        let one = U256::from(1);
        self.mark_leaf(commitment_pay, first_leaf)?;
        self.mark_leaf(commitment_fee, first_leaf + one)?;
        for (offset, leaf, envelope) in [
            (0u64, commitment_pay, pay_envelope),
            (1, commitment_fee, fee_envelope),
        ] {
            let index = first_leaf + U256::from(offset);
            let root = self.append_leaf(index, leaf)?;
            self.vm().log(DepositFromToken {
                commitment: leaf,
                leafIndex: index,
                newRoot: root,
                envelope: envelope.0.into(),
            });
        }
        Ok(())
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

    /// Spend a note onto an encrypted balance. The ciphertext is bound to the
    /// recipient's key by the proof, so a relayer may submit it unchanged.
    #[selector(name = "withdrawToToken")]
    pub fn withdraw_to_token(
        &mut self,
        proof_a: [U256; 2],
        proof_b: [[U256; 2]; 2],
        proof_c: [U256; 2],
        merkle_root: U256,
        nullifier: U256,
        credit: ([U256; 2], [U256; 2], [U256; 2]),
    ) -> Result<(), PoolError> {
        if self.nullifier_spent.get(nullifier) {
            return Err(PoolError::NullifierAlreadySpent(NullifierAlreadySpent {}));
        }
        if !self.is_known_root_inner(merkle_root) {
            return Err(PoolError::RootNotRecent(RootNotRecent {}));
        }
        let public_inputs = [
            merkle_root,
            nullifier,
            credit.0[0],
            credit.0[1],
            credit.1[0],
            credit.1[1],
            credit.2[0],
            credit.2[1],
        ];
        let verifier = self.exit_verifier.get();
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
        if !self.token_credit_pending(&credit) {
            return Err(PoolError::TransferFailed(TransferFailed {}));
        }
        self.vm().log(WithdrawalToToken { nullifier });
        Ok(())
    }

    /// Withdraw a note to `recipient`; only the owner can build the proof.
    /// The token pays the public amount from its custody.
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

        if !self.token_pay_out(recipient, amount - fee) {
            return Err(PoolError::TransferFailed(TransferFailed {}));
        }
        if !fee.is_zero() && !self.token_pay_out(relayer, fee) {
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

    // Public reads with the Solidity pool's names: clients read the treasury
    // key and fee floor for an in-pool forward, operators check a deployment.

    pub fn token(&self) -> Address {
        self.token.get()
    }

    #[selector(name = "withdrawVerifier")]
    pub fn withdraw_verifier(&self) -> Address {
        self.withdraw_verifier.get()
    }

    #[selector(name = "transferVerifier")]
    pub fn transfer_verifier(&self) -> Address {
        self.transfer_verifier.get()
    }

    #[selector(name = "exitVerifier")]
    pub fn exit_verifier(&self) -> Address {
        self.exit_verifier.get()
    }

    pub fn poseidon(&self) -> Address {
        self.poseidon.get()
    }

    #[selector(name = "treasuryOwnerPk")]
    pub fn treasury_owner_pk(&self) -> U256 {
        self.treasury_owner_pk.get()
    }

    #[selector(name = "feeFloor")]
    pub fn fee_floor(&self) -> U256 {
        self.fee_floor.get()
    }

    #[selector(name = "nextLeafIndex")]
    pub fn next_leaf_index(&self) -> U256 {
        self.next_leaf_index.get()
    }
}

/// `payOut(address,uint256)` on the confidential token.
const SEL_PAY_OUT: [u8; 4] = stylus_sdk::function_selector!("payOut", Address, U256);
/// `creditPending(uint256[2],uint256[2],uint256[2])` on the confidential token.
const SEL_CREDIT_PENDING: [u8; 4] =
    stylus_sdk::function_selector!("creditPending", [U256; 2], [U256; 2], [U256; 2]);
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

impl Tidex6TokenPoolV2 {
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

    /// `token.payOut(to, amount)` — the token pays from the custody it holds.
    fn token_pay_out(&mut self, to: Address, amount: U256) -> bool {
        let mut data = Vec::with_capacity(4 + 64);
        data.extend_from_slice(&SEL_PAY_OUT);
        push_address(&mut data, to);
        push_word(&mut data, amount);
        let token = self.token.get();
        let context = Call::new_mutating(self);
        call(self.vm(), context, token, &data).is_ok()
    }

    /// `token.creditPending(key, commitment, handle)` — static arrays, so the
    /// arguments are twelve plain words.
    fn token_credit_pending(&mut self, credit: &([U256; 2], [U256; 2], [U256; 2])) -> bool {
        let mut data = Vec::with_capacity(4 + 6 * 32);
        data.extend_from_slice(&SEL_CREDIT_PENDING);
        for w in credit
            .0
            .iter()
            .chain(credit.1.iter())
            .chain(credit.2.iter())
        {
            push_word(&mut data, *w);
        }
        let token = self.token.get();
        let context = Call::new_mutating(self);
        call(self.vm(), context, token, &data).is_ok()
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
