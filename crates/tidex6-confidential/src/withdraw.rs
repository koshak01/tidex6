//! Withdraw-схема со скрытой суммой: доказывает право вывести ноту, не
//! раскрывая, какая это нота (несвязываемость deposit↔withdraw), с суммой
//! внутри commitment.
//!
//! Доказывает:
//!   1. commitment = Poseidon(secret, nullifier, amount)
//!   2. nullifier_hash = Poseidon(nullifier)                 (анти-double-spend)
//!   3. commitment лежит в дереве с корнем merkle_root        (membership)
//!   4. 0 ≤ amount < 2^64                                     (range)
//!   5. amount == amount_public                               (выплата = сумма ноты)
//!   6. recipient/relayer/relayer_fee связаны в proof         (ADR-011, фикс GAP2)
//!
//! Отличия от phase2-прототипа (доведено до боевого уровня mainnet-линии):
//!   - relayer_address + relayer_fee как в ADR-011 (fee-in-circuit);
//!   - recipient и relayer связаны ПОЛНЫМ 256-битным ключом (по два limb'а
//!     hi/lo, [`crate::bytes::split_pubkey`]) вместо lossy `reduce_mod_bn254`
//!     — закрывает GAP2 (P+r griefing).
//!
//! Публичные входы (порядок load-bearing — он же в on-chain верификаторе):
//!   [merkle_root, nullifier_hash, recipient_hi, recipient_lo,
//!    relayer_hi, relayer_lo, relayer_fee, amount_public]

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use tidex6_circuits::poseidon_gadget::{poseidon_hash_n_var, poseidon_hash_pair_var};

use crate::bytes::{fr_from_u64, fr_to_be_bytes, split_pubkey};

/// Глубина дерева пула — совпадает с mainnet-верификатором.
pub const POOL_TREE_DEPTH: usize = 20;
/// Разрядность суммы.
pub const AMOUNT_BITS: usize = 64;
/// Число публичных входов withdraw-схемы.
pub const WITHDRAW_NR_PUBLIC_INPUTS: usize = 8;

/// Свидетели + публичные входы withdraw-доказательства. `None` на setup.
#[derive(Clone)]
pub struct WithdrawCircuit {
    // приватные свидетели
    pub amount: Option<Fr>,
    pub secret: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub path_siblings: Option<[Fr; POOL_TREE_DEPTH]>,
    pub path_indices: Option<[bool; POOL_TREE_DEPTH]>,
    // публичные входы
    pub merkle_root: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub recipient_hi: Option<Fr>,
    pub recipient_lo: Option<Fr>,
    pub relayer_hi: Option<Fr>,
    pub relayer_lo: Option<Fr>,
    pub relayer_fee: Option<Fr>,
    pub amount_public: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for WithdrawCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;

        // ── Приватные свидетели ──────────────────────────────────────
        let amount = FpVar::<Fr>::new_witness(cs.clone(), || self.amount.ok_or_else(missing))?;
        let secret = FpVar::<Fr>::new_witness(cs.clone(), || self.secret.ok_or_else(missing))?;
        let nullifier =
            FpVar::<Fr>::new_witness(cs.clone(), || self.nullifier.ok_or_else(missing))?;

        let mut siblings = Vec::with_capacity(POOL_TREE_DEPTH);
        let mut index_bits = Vec::with_capacity(POOL_TREE_DEPTH);
        for level in 0..POOL_TREE_DEPTH {
            siblings.push(FpVar::<Fr>::new_witness(cs.clone(), || {
                self.path_siblings.ok_or_else(missing).map(|s| s[level])
            })?);
            index_bits.push(Boolean::<Fr>::new_witness(cs.clone(), || {
                self.path_indices.ok_or_else(missing).map(|b| b[level])
            })?);
        }

        // ── Публичные входы (порядок load-bearing) ───────────────────
        let merkle_root =
            FpVar::<Fr>::new_input(cs.clone(), || self.merkle_root.ok_or_else(missing))?;
        let nullifier_hash =
            FpVar::<Fr>::new_input(cs.clone(), || self.nullifier_hash.ok_or_else(missing))?;
        let recipient_hi =
            FpVar::<Fr>::new_input(cs.clone(), || self.recipient_hi.ok_or_else(missing))?;
        let recipient_lo =
            FpVar::<Fr>::new_input(cs.clone(), || self.recipient_lo.ok_or_else(missing))?;
        let relayer_hi =
            FpVar::<Fr>::new_input(cs.clone(), || self.relayer_hi.ok_or_else(missing))?;
        let relayer_lo =
            FpVar::<Fr>::new_input(cs.clone(), || self.relayer_lo.ok_or_else(missing))?;
        let relayer_fee =
            FpVar::<Fr>::new_input(cs.clone(), || self.relayer_fee.ok_or_else(missing))?;
        let amount_public =
            FpVar::<Fr>::new_input(cs.clone(), || self.amount_public.ok_or_else(missing))?;

        // 1. commitment = Poseidon(secret, nullifier, amount).
        let commitment = poseidon_hash_n_var(
            cs.clone(),
            &[secret, nullifier.clone(), amount.clone()],
        )?;

        // 2. nullifier_hash = Poseidon(nullifier).
        let computed_nh = poseidon_hash_n_var(cs.clone(), std::slice::from_ref(&nullifier))?;
        computed_nh.enforce_equal(&nullifier_hash)?;

        // 3. Merkle membership: пройти от листа к корню.
        let mut current = commitment;
        for level in 0..POOL_TREE_DEPTH {
            let bit = &index_bits[level];
            let sib = &siblings[level];
            let left = FpVar::conditionally_select(bit, sib, &current)?;
            let right = FpVar::conditionally_select(bit, &current, sib)?;
            current = poseidon_hash_pair_var(cs.clone(), &left, &right)?;
        }
        current.enforce_equal(&merkle_root)?;

        // 4. range: 0 ≤ amount < 2^64.
        enforce_u64_range(cs.clone(), self.amount, &amount)?;

        // 5. Выплачиваемая сумма = сумма ноты.
        amount.enforce_equal(&amount_public)?;

        // 6. Tornado-style binding recipient/relayer/fee: любая подмена
        //    инвалидирует proof. Degenerate `x*x` затягивает вход в CS.
        //    Оба limb'а каждого ключа связаны отдельно → полный 256-битный
        //    ключ зафиксирован без коллизий (фикс GAP2).
        let _ = &recipient_hi * &recipient_hi;
        let _ = &recipient_lo * &recipient_lo;
        let _ = &relayer_hi * &relayer_hi;
        let _ = &relayer_lo * &relayer_lo;
        let _ = &relayer_fee * &relayer_fee;

        Ok(())
    }
}

/// Доказать `0 ≤ amount < 2^64` через битовое разложение.
fn enforce_u64_range(
    cs: ConstraintSystemRef<Fr>,
    amount_opt: Option<Fr>,
    amount_var: &FpVar<Fr>,
) -> Result<(), SynthesisError> {
    let missing = || SynthesisError::AssignmentMissing;
    let mut acc = FpVar::<Fr>::zero();
    let mut coeff = Fr::ONE;
    for i in 0..AMOUNT_BITS {
        let bit = Boolean::<Fr>::new_witness(cs.clone(), || {
            amount_opt
                .map(|a| a.into_bigint().get_bit(i))
                .ok_or_else(missing)
        })?;
        let term = &FpVar::from(bit) * &FpVar::constant(coeff);
        acc = &acc + &term;
        coeff = coeff + coeff;
    }
    acc.enforce_equal(amount_var)?;
    Ok(())
}

/// Off-circuit `commitment = Poseidon(secret, nullifier, amount)` — байт-
/// эквивалентно in-circuit `poseidon_hash_n_var`.
pub fn note_commitment(secret: Fr, nullifier: Fr, amount: Fr) -> Fr {
    let bytes = tidex6_core::poseidon::hash(&[
        &fr_to_be_bytes(secret),
        &fr_to_be_bytes(nullifier),
        &fr_to_be_bytes(amount),
    ])
    .expect("poseidon hash(3)");
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Off-circuit `nullifier_hash = Poseidon(nullifier)`.
pub fn nullifier_hash(nullifier: Fr) -> Fr {
    let bytes =
        tidex6_core::poseidon::hash(&[&fr_to_be_bytes(nullifier)]).expect("poseidon hash(1)");
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Локальный dev trusted setup (single-contributor — прод требует церемонии).
pub fn setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    let shape = WithdrawCircuit {
        amount: None,
        secret: None,
        nullifier: None,
        path_siblings: None,
        path_indices: None,
        merkle_root: None,
        nullifier_hash: None,
        recipient_hi: None,
        recipient_lo: None,
        relayer_hi: None,
        relayer_lo: None,
        relayer_fee: None,
        amount_public: None,
    };
    Groth16::<Bn254>::circuit_specific_setup(shape, rng)
}

/// Свидетель для доказательства вывода ноты.
pub struct WithdrawWitness {
    pub amount: u64,
    pub secret: Fr,
    pub nullifier: Fr,
    pub path_siblings: [Fr; POOL_TREE_DEPTH],
    pub path_indices: [bool; POOL_TREE_DEPTH],
    pub merkle_root: Fr,
    /// 32-байтный pubkey получателя.
    pub recipient: [u8; 32],
    /// 32-байтный pubkey релеера.
    pub relayer: [u8; 32],
    pub relayer_fee: u64,
}

/// Доказать право вывести ноту. Возвращает proof + публичные входы в
/// каноническом порядке (см. модульный docstring).
pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    w: &WithdrawWitness,
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; WITHDRAW_NR_PUBLIC_INPUTS]), SynthesisError> {
    let amount = fr_from_u64(w.amount);
    let nh = nullifier_hash(w.nullifier);
    let (recipient_hi, recipient_lo) = split_pubkey(&w.recipient);
    let (relayer_hi, relayer_lo) = split_pubkey(&w.relayer);
    let relayer_fee = fr_from_u64(w.relayer_fee);

    let circuit = WithdrawCircuit {
        amount: Some(amount),
        secret: Some(w.secret),
        nullifier: Some(w.nullifier),
        path_siblings: Some(w.path_siblings),
        path_indices: Some(w.path_indices),
        merkle_root: Some(w.merkle_root),
        nullifier_hash: Some(nh),
        recipient_hi: Some(recipient_hi),
        recipient_lo: Some(recipient_lo),
        relayer_hi: Some(relayer_hi),
        relayer_lo: Some(relayer_lo),
        relayer_fee: Some(relayer_fee),
        amount_public: Some(amount),
    };
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    let public_inputs = [
        w.merkle_root,
        nh,
        recipient_hi,
        recipient_lo,
        relayer_hi,
        relayer_lo,
        relayer_fee,
        amount,
    ];
    Ok((proof, public_inputs))
}

pub fn verify(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; WITHDRAW_NR_PUBLIC_INPUTS],
) -> Result<bool, SynthesisError> {
    Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, public_inputs, proof)
}

pub fn prepare_vk(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    Groth16::<Bn254>::process_vk(vk).expect("process_vk")
}
