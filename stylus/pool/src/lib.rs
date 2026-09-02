//! Shielded pool for a single ERC-20, on Stylus.
//!
//! Deposits append a commitment to an incremental Merkle tree; withdrawals
//! prove membership in zero knowledge and spend a nullifier. The link between
//! the two is what stays private.
//!
//! This mirrors `contracts/src/Tidex6Pool.sol` and, through it, the Solana pool:
//! same tree depth, same root ring, same Poseidon, same five public inputs.
//! The proving system is shared, so the mechanics must be too — a divergence
//! here would mean proofs that verify on one chain and not the other.
//!
//! Multichain, not cross-chain: this pool knows nothing about any other
//! chain's state and must never be taught to. Deposit here, withdraw here.
//!
//! On recipient binding: an EVM address is 160 bits, far below the field
//! order, so `U256::from(address)` is injective. Never introduce a reduction
//! on this path.

#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
extern crate alloc;

// The stylus-proc macros (`#[storage]`, `#[public]`, `sol_interface!`) expand
// to `Vec` and `vec!`; under `no_std` nobody imports those for us.
#[allow(unused_imports)]
use alloc::vec;
#[allow(unused_imports)]
use alloc::vec::Vec;

use alloy_primitives::{Address, U256};
use alloy_sol_types::sol;
use stylus_sdk::abi::Bytes;
use stylus_sdk::prelude::*;
use stylus_sdk::storage::{StorageAddress, StorageArray, StorageBool, StorageMap, StorageU256};

use tidex6_stylus_common::field::is_field_element;
use tidex6_stylus_common::poseidon::hash_pair;

/// Depth of the incremental tree. Fixed at compile time in the circuit.
pub const TREE_DEPTH: usize = 20;

/// How many past roots stay acceptable. A withdrawal proved against a root
/// that was current when the user started is still valid a few deposits
/// later — without this, every concurrent deposit would invalidate
/// in-flight withdrawals.
pub const ROOT_RING_SIZE: usize = 30;

sol_interface! {
    interface IERC20 {
        function transferFrom(address from, address to, uint256 amount) external returns (bool);
        function transfer(address to, uint256 amount) external returns (bool);
    }

    interface ITidex6Verifier {
        function verifyProof(uint256[2] pa, uint256[2][2] pb, uint256[2] pc, uint256[5] pub_signals) external view returns (bool);
    }
}

sol! {
    /// A note was funded. The envelope is opaque to the chain — meaningful
    /// only to whoever holds the key it was sealed for — and travels in the
    /// log because nothing on chain ever needs to read it back.
    event Deposit(uint256 indexed commitment, uint256 leafIndex, uint256 newRoot, address depositor, bytes envelope);
    event Withdrawal(uint256 indexed nullifierHash, address indexed recipient, address relayer, uint256 fee);

    error NotAFieldElement();
    error CommitmentAlreadyUsed();
    error TreeFull();
    error RootNotRecent();
    error NullifierAlreadySpent();
    error InvalidProof();
    error FeeExceedsDenomination();
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
    FeeExceedsDenomination(FeeExceedsDenomination),
    TransferFailed(TransferFailed),
}

#[storage]
#[entrypoint]
pub struct Tidex6Pool {
    /// The token this pool holds.
    token: StorageAddress,
    /// Groth16 verifier for the withdraw circuit.
    verifier: StorageAddress,
    /// Fixed deposit size. A pool with arbitrary amounts leaks the link
    /// through the amount itself, so every note is worth the same.
    denomination: StorageU256,
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
    /// Commitments already deposited, so an accidental repeat is rejected
    /// rather than creating a note the depositor cannot distinguish.
    commitment_known: StorageMap<U256, StorageBool>,
}

#[public]
impl Tidex6Pool {
    /// Bind the pool to a token, a verifier and a note size, and compute the
    /// empty-subtree hashes level by level — exactly as the Solana pool does at
    /// initialisation.
    #[constructor]
    pub fn constructor(&mut self, token: Address, verifier: Address, denomination: U256) {
        self.token.set(token);
        self.verifier.set(verifier);
        self.denomination.set(denomination);

        let mut zero_hash = U256::ZERO;
        for level in 0..TREE_DEPTH {
            self.zero_subtrees.setter(level).unwrap().set(zero_hash);
            self.filled_subtrees.setter(level).unwrap().set(zero_hash);
            // Both inputs are field elements by construction: `None` is unreachable.
            zero_hash = hash_pair(zero_hash, zero_hash).unwrap_or(U256::ZERO);
        }
        self.root_history.setter(0).unwrap().set(zero_hash);
    }

    /// Deposit one note. `commitment` is `Poseidon(secret, nullifier)`,
    /// computed by the client; `envelope` is sealed for the recipient before
    /// anything left the sender's browser. The pool never sees the secret — it
    /// only learns that some commitment was funded, which is the entire point.
    pub fn deposit(&mut self, commitment: U256, envelope: Bytes) -> Result<(), PoolError> {
        if !is_field_element(commitment) {
            return Err(PoolError::NotAFieldElement(NotAFieldElement {}));
        }
        if self.commitment_known.get(commitment) {
            return Err(PoolError::CommitmentAlreadyUsed(CommitmentAlreadyUsed {}));
        }
        let leaf_index = self.next_leaf_index.get();
        if leaf_index >= U256::from(1u64 << TREE_DEPTH) {
            return Err(PoolError::TreeFull(TreeFull {}));
        }
        self.commitment_known.insert(commitment, true);

        let depositor = self.vm().msg_sender();
        let pool = self.vm().contract_address();
        let amount = self.denomination.get();
        let token = IERC20::new(self.token.get());
        let call = Call::new_mutating(self);
        match token.transfer_from(self.vm(), call, depositor, pool, amount) {
            Ok(true) => {}
            _ => return Err(PoolError::TransferFailed(TransferFailed {})),
        }

        let new_root = self.append_leaf(leaf_index, commitment)?;
        self.vm().log(Deposit {
            commitment,
            leafIndex: leaf_index,
            newRoot: new_root,
            depositor,
            envelope: envelope.0.into(),
        });
        Ok(())
    }

    /// Withdraw a note to `recipient`, optionally paying `relayer` a `fee` out
    /// of the denomination. Recipient, relayer and fee are public inputs to the
    /// proof, so a relayer cannot redirect the payment or raise its own fee:
    /// any change invalidates the proof.
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
    ) -> Result<(), PoolError> {
        if self.nullifier_spent.get(nullifier_hash) {
            return Err(PoolError::NullifierAlreadySpent(NullifierAlreadySpent {}));
        }
        let denomination = self.denomination.get();
        if fee > denomination {
            return Err(PoolError::FeeExceedsDenomination(FeeExceedsDenomination {}));
        }
        if !self.is_known_root_inner(merkle_root) {
            return Err(PoolError::RootNotRecent(RootNotRecent {}));
        }

        let public_inputs = [
            merkle_root,
            nullifier_hash,
            U256::from_be_slice(recipient.as_slice()),
            U256::from_be_slice(relayer.as_slice()),
            fee,
        ];
        let verifier = ITidex6Verifier::new(self.verifier.get());
        match verifier.verify_proof(self.vm(), Call::new(), proof_a, proof_b, proof_c, public_inputs) {
            Ok(true) => {}
            _ => return Err(PoolError::InvalidProof(InvalidProof {})),
        }

        // Spend before paying: the nullifier is the double-spend guard, and it
        // must be set before any external call.
        self.nullifier_spent.insert(nullifier_hash, true);

        let token = IERC20::new(self.token.get());
        let payout = denomination - fee;
        let call = Call::new_mutating(self);
        match token.transfer(self.vm(), call, recipient, payout) {
            Ok(true) => {}
            _ => return Err(PoolError::TransferFailed(TransferFailed {})),
        }
        if !fee.is_zero() {
            let call = Call::new_mutating(self);
            match token.transfer(self.vm(), call, relayer, fee) {
                Ok(true) => {}
                _ => return Err(PoolError::TransferFailed(TransferFailed {})),
            }
        }

        self.vm().log(Withdrawal { nullifierHash: nullifier_hash, recipient, relayer, fee });
        Ok(())
    }

    /// Current tree root.
    #[selector(name = "currentRoot")]
    pub fn current_root(&self) -> U256 {
        let head = self.root_ring_head.get().to::<usize>();
        self.root_history.get(head).unwrap_or(U256::ZERO)
    }

    /// Is this root recent enough to withdraw against?
    #[selector(name = "isKnownRoot")]
    pub fn is_known_root(&self, root: U256) -> bool {
        self.is_known_root_inner(root)
    }

    #[selector(name = "nullifierSpent")]
    pub fn nullifier_spent(&self, nullifier_hash: U256) -> bool {
        self.nullifier_spent.get(nullifier_hash)
    }

    #[selector(name = "commitmentKnown")]
    pub fn commitment_known(&self, commitment: U256) -> bool {
        self.commitment_known.get(commitment)
    }

    #[selector(name = "nextLeafIndex")]
    pub fn next_leaf_index(&self) -> U256 {
        self.next_leaf_index.get()
    }

    #[selector(name = "rootRingHead")]
    pub fn root_ring_head(&self) -> U256 {
        self.root_ring_head.get()
    }

    pub fn denomination(&self) -> U256 {
        self.denomination.get()
    }

    pub fn token(&self) -> Address {
        self.token.get()
    }

    pub fn verifier(&self) -> Address {
        self.verifier.get()
    }

    #[selector(name = "TREE_DEPTH")]
    pub fn tree_depth(&self) -> U256 {
        U256::from(TREE_DEPTH)
    }

    #[selector(name = "ROOT_RING_SIZE")]
    pub fn root_ring_size(&self) -> U256 {
        U256::from(ROOT_RING_SIZE)
    }
}

impl Tidex6Pool {
    /// Append a leaf and return the new root. Same walk the Solana pool does.
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
            current_hash = hash_pair(left, right)
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
    /// an uninitialised slot must not authorise a withdrawal.
    fn is_known_root_inner(&self, root: U256) -> bool {
        if root.is_zero() {
            return false;
        }
        (0..ROOT_RING_SIZE).any(|i| self.root_history.get(i) == Some(root))
    }
}
