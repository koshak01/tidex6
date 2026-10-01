//! Confidential wrapper over an ERC-20, on Stylus (ADR-023).
//!
//! Mirrors `contracts/src/Tidex6ConfidentialToken.sol`: same ABI, events and
//! errors. Balances are twisted ElGamal ciphertexts on Baby Jubjub —
//! commitment `C = m·G + r·H` and handle `D = r·P`, where `P = s⁻¹·H` is the
//! owner's key. The chain holds `C` and `D` and learns nothing.
//!
//! Amounts appear in exactly two places, both chosen by the user: `wrap` (an
//! ERC-20 transfer in) and `unwrap` (one out). Between them everything is
//! ciphertext:
//!
//! - `transfer` — between two confidential balances; the chain sees the keys
//!   and nothing else.
//! - `depositToPool` — a balance becomes two v2 pool notes (payment and fee);
//!   no amount and no recipient anywhere.
//! - `creditPending` — the way back from the pool, pool only.
//! - `payOut` — the pool pays a public withdrawal from the ERC-20 held here:
//!   this contract is the custody for the pool's notes too.
//!
//! Incoming value lands in `pending`; the owner folds it into `available` with
//! `applyPending`, so a payment arriving mid-proof cannot invalidate the proof.
//! Every accepted proof's hash is recorded against replay.

#![cfg_attr(not(any(test, feature = "export-abi")), no_std)]
extern crate alloc;

#[allow(unused_imports)]
use alloc::vec;
#[allow(unused_imports)]
use alloc::vec::Vec;

use alloy_primitives::{Address, FixedBytes, U256, U64};
use alloy_sol_types::sol;
use stylus_sdk::abi::Bytes;
use stylus_sdk::call::{call, static_call};
use stylus_sdk::crypto::keccak;
use stylus_sdk::prelude::*;
use stylus_sdk::storage::{StorageAddress, StorageBool, StorageMap, StorageU256, StorageU64};

use tidex6_stylus_common::babyjubjub::{self, Point};
use tidex6_stylus_common::field::is_field_element;

sol! {
    event Registered(address indexed owner, uint256 keyX, uint256 keyY);
    event Wrapped(address indexed owner, uint64 amount);
    event PendingApplied(address indexed owner, uint64 credits);
    event ConfidentialTransfer(bytes32 indexed recipientKeyHash, bytes32 indexed senderKeyHash, uint256[8] points, bytes envelope);
    event Unwrapped(address indexed owner, uint64 amount);
    event DepositedToPool(bytes32 indexed senderKeyHash, uint256 commitment);
    event CreditedFromPool(bytes32 indexed recipientKeyHash, uint256 commitmentX, uint256 commitmentY);

    error AlreadyRegistered();
    error KeyTaken();
    error NotRegistered();
    error InvalidProof();
    error ProofReplay();
    error StaleBalance();
    error FieldOverflow();
    error AmountTooLarge();
    error ZeroAmount();
    error TransferFailed();
    error PoolNotSet();
    error PoolAlreadySet();
    error OnlyPool();
    error OnlyDeployer();
    error FeePolicyMismatch();
}

#[derive(SolidityError)]
pub enum TokenError {
    AlreadyRegistered(AlreadyRegistered),
    KeyTaken(KeyTaken),
    NotRegistered(NotRegistered),
    InvalidProof(InvalidProof),
    ProofReplay(ProofReplay),
    StaleBalance(StaleBalance),
    FieldOverflow(FieldOverflow),
    AmountTooLarge(AmountTooLarge),
    ZeroAmount(ZeroAmount),
    TransferFailed(TransferFailed),
    PoolNotSet(PoolNotSet),
    PoolAlreadySet(PoolAlreadySet),
    OnlyPool(OnlyPool),
    OnlyDeployer(OnlyDeployer),
    FeePolicyMismatch(FeePolicyMismatch),
}

/// One confidential account: key, spendable and incoming ciphertexts.
#[storage]
pub struct Account {
    key_x: StorageU256,
    key_y: StorageU256,
    available_c_x: StorageU256,
    available_c_y: StorageU256,
    available_d_x: StorageU256,
    available_d_y: StorageU256,
    pending_c_x: StorageU256,
    pending_c_y: StorageU256,
    pending_d_x: StorageU256,
    pending_d_y: StorageU256,
    pending_count: StorageU64,
    registered: StorageBool,
}

/// A ciphertext as two affine points: commitment and handle.
type Cipher = (Point, Point);

#[storage]
#[entrypoint]
pub struct Tidex6ConfidentialToken {
    token: StorageAddress,
    pubkey_verifier: StorageAddress,
    transfer_verifier: StorageAddress,
    unwrap_verifier: StorageAddress,
    deposit_verifier: StorageAddress,
    /// Who may call `creditPending` and `payOut`. Set once, by the deployer.
    pool: StorageAddress,
    deployer: StorageAddress,
    accounts: StorageMap<Address, Account>,
    /// Owner address by key hash — transfers name recipients by key.
    key_owner: StorageMap<FixedBytes<32>, StorageAddress>,
    /// Proofs already accepted, by hash.
    proof_used: StorageMap<FixedBytes<32>, StorageBool>,
}

#[public]
impl Tidex6ConfidentialToken {
    /// `deployer` is the address allowed to name the pool once. It is an
    /// argument rather than `msg_sender()`: `cargo stylus deploy` runs the
    /// constructor through the `StylusDeployer` factory, so the sender here
    /// is the factory, and a deployer taken from it could never call
    /// `setPool`.
    #[constructor]
    #[allow(clippy::too_many_arguments)]
    pub fn constructor(
        &mut self,
        token: Address,
        pubkey_verifier: Address,
        transfer_verifier: Address,
        unwrap_verifier: Address,
        deposit_verifier: Address,
        deployer: Address,
    ) {
        self.token.set(token);
        self.pubkey_verifier.set(pubkey_verifier);
        self.transfer_verifier.set(transfer_verifier);
        self.unwrap_verifier.set(unwrap_verifier);
        self.deposit_verifier.set(deposit_verifier);
        self.deployer.set(deployer);
    }

    /// Name the pool once. It can move value into any account, so it is not
    /// something a deployer should be able to re-point later.
    #[selector(name = "setPool")]
    pub fn set_pool(&mut self, pool: Address) -> Result<(), TokenError> {
        if self.vm().msg_sender() != self.deployer.get() {
            return Err(TokenError::OnlyDeployer(OnlyDeployer {}));
        }
        if self.pool.get() != Address::ZERO {
            return Err(TokenError::PoolAlreadySet(PoolAlreadySet {}));
        }
        self.pool.set(pool);
        Ok(())
    }

    /// Open a confidential account under `key`; the proof shows `s·P == H`.
    pub fn register(
        &mut self,
        key: [U256; 2],
        proof_a: [U256; 2],
        proof_b: [[U256; 2]; 2],
        proof_c: [U256; 2],
    ) -> Result<(), TokenError> {
        let owner = self.vm().msg_sender();
        if self.accounts.getter(owner).registered.get() {
            return Err(TokenError::AlreadyRegistered(AlreadyRegistered {}));
        }
        require_fields(&key)?;
        let key_hash = key_hash(key[0], key[1]);
        if self.key_owner.get(key_hash) != Address::ZERO {
            return Err(TokenError::KeyTaken(KeyTaken {}));
        }
        // Bound to the caller: a proof copied from the mempool and sent from
        // another address does not verify, so nobody can claim a key first.
        let word = U256::from_be_slice(owner.as_slice());
        let mask = (U256::from(1) << 128) - U256::from(1);
        let input = [key[0], key[1], word >> 128, word & mask];
        let verifier = self.pubkey_verifier.get();
        if !self.verify(verifier, SEL_VERIFY_4, &proof_a, &proof_b, &proof_c, &input) {
            return Err(TokenError::InvalidProof(InvalidProof {}));
        }
        let identity = babyjubjub::identity();
        let mut account = self.accounts.setter(owner);
        account.key_x.set(key[0]);
        account.key_y.set(key[1]);
        set_available(&mut account, (identity, identity));
        set_pending(&mut account, (identity, identity));
        account.registered.set(true);
        self.key_owner.insert(key_hash, owner);
        self.vm().log(Registered {
            owner,
            keyX: key[0],
            keyY: key[1],
        });
        Ok(())
    }

    /// Move `amount` of the plain token into your pending balance, as the
    /// unblinded ciphertext `(m·G, O)` — the amount is public here anyway.
    pub fn wrap(&mut self, amount: u64) -> Result<(), TokenError> {
        if amount == 0 {
            return Err(TokenError::ZeroAmount(ZeroAmount {}));
        }
        let owner = self.vm().msg_sender();
        if !self.accounts.getter(owner).registered.get() {
            return Err(TokenError::NotRegistered(NotRegistered {}));
        }
        let this = self.vm().contract_address();
        if !self.erc20_call(SEL_TRANSFER_FROM, Some(owner), this, U256::from(amount)) {
            return Err(TokenError::TransferFailed(TransferFailed {}));
        }
        let credit = (babyjubjub::mul_g(amount), babyjubjub::identity());
        self.credit(owner, credit)?;
        self.vm().log(Wrapped { owner, amount });
        Ok(())
    }

    /// Fold `pending` into `available`. Owner only: anyone else could
    /// invalidate a proof the owner is building.
    #[selector(name = "applyPending")]
    pub fn apply_pending(&mut self) -> Result<(), TokenError> {
        let owner = self.vm().msg_sender();
        let mut account = self.accounts.setter(owner);
        if !account.registered.get() {
            return Err(TokenError::NotRegistered(NotRegistered {}));
        }
        let available = get_available(&account);
        let pending = get_pending(&account);
        let sum = (
            add_points(available.0, pending.0)?,
            add_points(available.1, pending.1)?,
        );
        set_available(&mut account, sum);
        let identity = babyjubjub::identity();
        set_pending(&mut account, (identity, identity));
        let credits = account.pending_count.get().to::<u64>();
        account.pending_count.set(U64::ZERO);
        self.vm().log(PendingApplied { owner, credits });
        Ok(())
    }

    /// Pay from one confidential balance to another; no amount anywhere.
    /// Inputs in circuit order: sender key, sender available `(C, D)`, amount
    /// commitment, sender handle, recipient key, recipient handle, auditor
    /// key, auditor handle.
    pub fn transfer(
        &mut self,
        proof_a: [U256; 2],
        proof_b: [[U256; 2]; 2],
        proof_c: [U256; 2],
        input: [U256; 18],
        envelope: Bytes,
    ) -> Result<(), TokenError> {
        require_fields(&input)?;
        let sender = self.owner_of_key(input[0], input[1])?;
        self.require_available(sender, &input[2..6])?;
        let recipient = self.owner_of_key(input[10], input[11])?;
        self.consume_proof(&proof_a, &proof_b, &proof_c, &input)?;
        let verifier = self.transfer_verifier.get();
        if !self.verify(
            verifier,
            SEL_VERIFY_18,
            &proof_a,
            &proof_b,
            &proof_c,
            &input,
        ) {
            return Err(TokenError::InvalidProof(InvalidProof {}));
        }
        let commitment = (input[6], input[7]);
        self.debit(sender, (commitment, (input[8], input[9])))?;
        self.credit(recipient, (commitment, (input[12], input[13])))?;
        self.vm().log(ConfidentialTransfer {
            recipientKeyHash: key_hash(input[10], input[11]),
            senderKeyHash: key_hash(input[0], input[1]),
            points: [
                input[6], input[7], input[12], input[13], input[14], input[15], input[16],
                input[17],
            ],
            envelope: envelope.0.into(),
        });
        Ok(())
    }

    /// Leave for the plain token. The payout goes to the caller, who must own
    /// the key: the circuit has no recipient field, so the destination is
    /// bound here.
    pub fn unwrap(
        &mut self,
        proof_a: [U256; 2],
        proof_b: [[U256; 2]; 2],
        proof_c: [U256; 2],
        input: [U256; 7],
    ) -> Result<(), TokenError> {
        require_fields(&input)?;
        if input[6] > U256::from(u64::MAX) {
            return Err(TokenError::AmountTooLarge(AmountTooLarge {}));
        }
        let amount = input[6].to::<u64>();
        if amount == 0 {
            return Err(TokenError::ZeroAmount(ZeroAmount {}));
        }
        let owner = self.vm().msg_sender();
        {
            let account = self.accounts.getter(owner);
            if !account.registered.get()
                || account.key_x.get() != input[0]
                || account.key_y.get() != input[1]
            {
                return Err(TokenError::NotRegistered(NotRegistered {}));
            }
        }
        self.require_available(owner, &input[2..6])?;
        self.consume_proof(&proof_a, &proof_b, &proof_c, &input)?;
        let verifier = self.unwrap_verifier.get();
        if !self.verify(verifier, SEL_VERIFY_7, &proof_a, &proof_b, &proof_c, &input) {
            return Err(TokenError::InvalidProof(InvalidProof {}));
        }
        self.debit(owner, (babyjubjub::mul_g(amount), babyjubjub::identity()))?;
        if !self.erc20_call(SEL_TRANSFER, None, owner, U256::from(amount)) {
            return Err(TokenError::TransferFailed(TransferFailed {}));
        }
        self.vm().log(Unwrapped { owner, amount });
        Ok(())
    }

    /// Turn part of a balance into two pool notes. Inputs: sender key, sender
    /// available `(C, D)`, the debited ciphertext of payment plus fee, the
    /// payment and fee leaves, the treasury key and the fee floor — the last
    /// two must be the pool's own.
    #[selector(name = "depositToPool")]
    pub fn deposit_to_pool(
        &mut self,
        proof_a: [U256; 2],
        proof_b: [[U256; 2]; 2],
        proof_c: [U256; 2],
        input: [U256; 14],
        pay_envelope: Bytes,
        fee_envelope: Bytes,
    ) -> Result<(), TokenError> {
        let pool = self.pool.get();
        if pool == Address::ZERO {
            return Err(TokenError::PoolNotSet(PoolNotSet {}));
        }
        require_fields(&input)?;
        if self.read_word(pool, SEL_TREASURY_OWNER_PK) != Some(input[12])
            || self.read_word(pool, SEL_FEE_FLOOR) != Some(input[13])
        {
            return Err(TokenError::FeePolicyMismatch(FeePolicyMismatch {}));
        }
        let sender = self.owner_of_key(input[0], input[1])?;
        self.require_available(sender, &input[2..6])?;
        self.consume_proof(&proof_a, &proof_b, &proof_c, &input)?;
        let verifier = self.deposit_verifier.get();
        if !self.verify(
            verifier,
            SEL_VERIFY_14,
            &proof_a,
            &proof_b,
            &proof_c,
            &input,
        ) {
            return Err(TokenError::InvalidProof(InvalidProof {}));
        }
        self.debit(sender, ((input[6], input[7]), (input[8], input[9])))?;
        self.vm().log(DepositedToPool {
            senderKeyHash: key_hash(input[0], input[1]),
            commitment: input[10],
        });
        let data = encode_deposit_from_token(input[10], input[11], &pay_envelope, &fee_envelope);
        let context = Call::new_mutating(self);
        if call(self.vm(), context, pool, &data).is_err() {
            return Err(TokenError::TransferFailed(TransferFailed {}));
        }
        Ok(())
    }

    /// Pay a public withdrawal from the pool's notes in the open ERC-20. Pool
    /// only: it verified the proof and spent the note.
    #[selector(name = "payOut")]
    pub fn pay_out(&mut self, to: Address, amount: U256) -> Result<(), TokenError> {
        if self.vm().msg_sender() != self.pool.get() {
            return Err(TokenError::OnlyPool(OnlyPool {}));
        }
        if !self.erc20_call(SEL_TRANSFER, None, to, amount) {
            return Err(TokenError::TransferFailed(TransferFailed {}));
        }
        Ok(())
    }

    /// Credit a ciphertext on the way out of the pool. Pool only: the pool
    /// verified the exit proof that binds it to this recipient.
    #[selector(name = "creditPending")]
    pub fn credit_pending(
        &mut self,
        recipient_key: [U256; 2],
        commitment: [U256; 2],
        handle: [U256; 2],
    ) -> Result<(), TokenError> {
        if self.vm().msg_sender() != self.pool.get() {
            return Err(TokenError::OnlyPool(OnlyPool {}));
        }
        require_fields(&commitment)?;
        require_fields(&handle)?;
        let recipient = self.owner_of_key(recipient_key[0], recipient_key[1])?;
        self.credit(
            recipient,
            ((commitment[0], commitment[1]), (handle[0], handle[1])),
        )?;
        self.vm().log(CreditedFromPool {
            recipientKeyHash: key_hash(recipient_key[0], recipient_key[1]),
            commitmentX: commitment[0],
            commitmentY: commitment[1],
        });
        Ok(())
    }

    /// Key, available `(C, D)`, pending `(C, D)` as ten coordinates; then the
    /// waiting credits and whether the account exists.
    #[selector(name = "accountOf")]
    pub fn account_of(&self, owner: Address) -> ([U256; 10], u64, bool) {
        let account = self.accounts.getter(owner);
        let available = get_available(&account);
        let pending = get_pending(&account);
        (
            [
                account.key_x.get(),
                account.key_y.get(),
                available.0 .0,
                available.0 .1,
                available.1 .0,
                available.1 .1,
                pending.0 .0,
                pending.0 .1,
                pending.1 .0,
                pending.1 .1,
            ],
            account.pending_count.get().to::<u64>(),
            account.registered.get(),
        )
    }

    pub fn token(&self) -> Address {
        self.token.get()
    }

    pub fn pool(&self) -> Address {
        self.pool.get()
    }

    #[selector(name = "keyOwner")]
    pub fn key_owner(&self, key_hash: FixedBytes<32>) -> Address {
        self.key_owner.get(key_hash)
    }

    #[selector(name = "proofUsed")]
    pub fn proof_used(&self, digest: FixedBytes<32>) -> bool {
        self.proof_used.get(digest)
    }
}

/// `transferFrom(address,address,uint256)`.
const SEL_TRANSFER_FROM: [u8; 4] = [0x23, 0xb8, 0x72, 0xdd];
/// `transfer(address,uint256)`.
const SEL_TRANSFER: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
const SEL_TREASURY_OWNER_PK: [u8; 4] = stylus_sdk::function_selector!("treasuryOwnerPk");
const SEL_FEE_FLOOR: [u8; 4] = stylus_sdk::function_selector!("feeFloor");
const SEL_DEPOSIT_FROM_TOKEN: [u8; 4] =
    stylus_sdk::function_selector!("depositFromToken", U256, U256, Bytes, Bytes);
const SEL_VERIFY_4: [u8; 4] = stylus_sdk::function_selector!(
    "verifyProof",
    [U256; 2],
    [[U256; 2]; 2],
    [U256; 2],
    [U256; 4]
);
const SEL_VERIFY_7: [u8; 4] = stylus_sdk::function_selector!(
    "verifyProof",
    [U256; 2],
    [[U256; 2]; 2],
    [U256; 2],
    [U256; 7]
);
const SEL_VERIFY_14: [u8; 4] = stylus_sdk::function_selector!(
    "verifyProof",
    [U256; 2],
    [[U256; 2]; 2],
    [U256; 2],
    [U256; 14]
);
const SEL_VERIFY_18: [u8; 4] = stylus_sdk::function_selector!(
    "verifyProof",
    [U256; 2],
    [[U256; 2]; 2],
    [U256; 2],
    [U256; 18]
);

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

/// Did a call return ABI `true`?
#[inline]
fn returned_true(data: &[u8]) -> bool {
    data.len() >= 32 && data[..31].iter().all(|b| *b == 0) && data[31] == 1
}

/// `keccak256(abi.encodePacked(x, y))` — how a key is named.
fn key_hash(x: U256, y: U256) -> FixedBytes<32> {
    let mut data = Vec::with_capacity(64);
    push_word(&mut data, x);
    push_word(&mut data, y);
    keccak(&data)
}

/// Every word must be a field element: a silent reduction later on a path
/// that binds value is how proofs stop meaning what they say.
fn require_fields(words: &[U256]) -> Result<(), TokenError> {
    if words.iter().all(|w| is_field_element(*w)) {
        Ok(())
    } else {
        Err(TokenError::FieldOverflow(FieldOverflow {}))
    }
}

fn add_points(a: Point, b: Point) -> Result<Point, TokenError> {
    babyjubjub::add(a, b).ok_or(TokenError::FieldOverflow(FieldOverflow {}))
}

fn sub_points(a: Point, b: Point) -> Result<Point, TokenError> {
    babyjubjub::sub(a, b).ok_or(TokenError::FieldOverflow(FieldOverflow {}))
}

/// ABI `depositFromToken(uint256,uint256,bytes,bytes)`: two words, two
/// offsets, then each byte string as length and padded data.
fn encode_deposit_from_token(pay: U256, fee: U256, pay_env: &Bytes, fee_env: &Bytes) -> Vec<u8> {
    let padded = |len: usize| len.div_ceil(32) * 32;
    let first = 4 * 32;
    let second = first + 32 + padded(pay_env.0.len());
    let mut data = Vec::with_capacity(4 + second + 32 + padded(fee_env.0.len()));
    data.extend_from_slice(&SEL_DEPOSIT_FROM_TOKEN);
    push_word(&mut data, pay);
    push_word(&mut data, fee);
    push_word(&mut data, U256::from(first));
    push_word(&mut data, U256::from(second));
    for env in [pay_env, fee_env] {
        push_word(&mut data, U256::from(env.0.len()));
        data.extend_from_slice(&env.0);
        data.resize(data.len() + padded(env.0.len()) - env.0.len(), 0);
    }
    data
}

fn get_available<A: core::ops::Deref<Target = Account>>(account: &A) -> Cipher {
    (
        (account.available_c_x.get(), account.available_c_y.get()),
        (account.available_d_x.get(), account.available_d_y.get()),
    )
}

fn get_pending<A: core::ops::Deref<Target = Account>>(account: &A) -> Cipher {
    (
        (account.pending_c_x.get(), account.pending_c_y.get()),
        (account.pending_d_x.get(), account.pending_d_y.get()),
    )
}

fn set_available<A: core::ops::DerefMut<Target = Account>>(account: &mut A, value: Cipher) {
    account.available_c_x.set(value.0 .0);
    account.available_c_y.set(value.0 .1);
    account.available_d_x.set(value.1 .0);
    account.available_d_y.set(value.1 .1);
}

fn set_pending<A: core::ops::DerefMut<Target = Account>>(account: &mut A, value: Cipher) {
    account.pending_c_x.set(value.0 .0);
    account.pending_c_y.set(value.0 .1);
    account.pending_d_x.set(value.1 .0);
    account.pending_d_y.set(value.1 .1);
}

impl Tidex6ConfidentialToken {
    /// Registered owner of a key, or `NotRegistered`.
    fn owner_of_key(&self, x: U256, y: U256) -> Result<Address, TokenError> {
        let owner = self.key_owner.get(key_hash(x, y));
        if owner == Address::ZERO {
            return Err(TokenError::NotRegistered(NotRegistered {}));
        }
        Ok(owner)
    }

    /// The proof must be against the balance as it stands now.
    fn require_available(&self, owner: Address, words: &[U256]) -> Result<(), TokenError> {
        let account = self.accounts.getter(owner);
        let (c, d) = get_available(&account);
        if [c.0, c.1, d.0, d.1] != [words[0], words[1], words[2], words[3]] {
            return Err(TokenError::StaleBalance(StaleBalance {}));
        }
        Ok(())
    }

    /// Record a proof by hash, rejecting the exact same bytes twice.
    fn consume_proof(
        &mut self,
        proof_a: &[U256; 2],
        proof_b: &[[U256; 2]; 2],
        proof_c: &[U256; 2],
        input: &[U256],
    ) -> Result<(), TokenError> {
        let mut data = Vec::with_capacity((8 + input.len()) * 32);
        for w in proof_a
            .iter()
            .chain(proof_b.iter().flatten())
            .chain(proof_c.iter())
            .chain(input.iter())
        {
            push_word(&mut data, *w);
        }
        let digest = keccak(&data);
        if self.proof_used.get(digest) {
            return Err(TokenError::ProofReplay(ProofReplay {}));
        }
        self.proof_used.insert(digest, true);
        Ok(())
    }

    /// Subtract a ciphertext from `available`.
    fn debit(&mut self, owner: Address, amount: Cipher) -> Result<(), TokenError> {
        let mut account = self.accounts.setter(owner);
        let available = get_available(&account);
        let rest = (
            sub_points(available.0, amount.0)?,
            sub_points(available.1, amount.1)?,
        );
        set_available(&mut account, rest);
        Ok(())
    }

    /// Add a ciphertext to `pending`.
    fn credit(&mut self, owner: Address, amount: Cipher) -> Result<(), TokenError> {
        let mut account = self.accounts.setter(owner);
        let pending = get_pending(&account);
        let sum = (
            add_points(pending.0, amount.0)?,
            add_points(pending.1, amount.1)?,
        );
        set_pending(&mut account, sum);
        let count = account.pending_count.get();
        account.pending_count.set(count + U64::from(1));
        Ok(())
    }

    /// `token.transferFrom(from, to, amount)` when `from` is given, else
    /// `token.transfer(to, amount)`.
    fn erc20_call(
        &mut self,
        selector: [u8; 4],
        from: Option<Address>,
        to: Address,
        amount: U256,
    ) -> bool {
        let mut data = Vec::with_capacity(4 + 96);
        data.extend_from_slice(&selector);
        if let Some(from) = from {
            push_address(&mut data, from);
        }
        push_address(&mut data, to);
        push_word(&mut data, amount);
        let token = self.token.get();
        let context = Call::new_mutating(self);
        match call(self.vm(), context, token, &data) {
            Ok(out) => returned_true(&out),
            Err(_) => false,
        }
    }

    /// A no-argument view returning one word.
    fn read_word(&self, target: Address, selector: [u8; 4]) -> Option<U256> {
        match static_call(self.vm(), Call::new(), target, &selector) {
            Ok(out) if out.len() == 32 => Some(U256::from_be_slice(&out)),
            _ => None,
        }
    }

    /// `verifier.verifyProof(a, b, c, inputs)`; `selector` picks the width.
    fn verify(
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
        for w in proof_a
            .iter()
            .chain(proof_b.iter().flatten())
            .chain(proof_c.iter())
            .chain(public_inputs.iter())
        {
            push_word(&mut data, *w);
        }
        match static_call(self.vm(), Call::new(), verifier, &data) {
            Ok(out) => returned_true(&out),
            Err(_) => false,
        }
    }
}
