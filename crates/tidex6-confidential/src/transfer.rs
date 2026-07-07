//! Transfer-схема (JoinSplit): тратит одну ноту и создаёт две новые, сохраняя
//! сумму — всё со скрытыми суммами. Это конфиденциальный перевод: на цепи
//! гасится нуллификатор входной ноты и появляются два новых commitment'а, но
//! ни одной суммы не видно. Ценность остаётся в vault пула — двигаются
//! только claim'ы (ноты). Это ядро полного скрытия суммы: внутренние переводы
//! не раскрывают ни отправителя↔получателя, ни величину.
//!
//! Доказывает:
//!   1. commitment_in = Poseidon(secret_in, nullifier_in, amount_in)
//!   2. nullifier_hash = Poseidon(nullifier_in)              (анти-double-spend)
//!   3. commitment_in лежит в дереве с корнем merkle_root     (membership)
//!   4. commitment_out1 = Poseidon(secret_out1, nullifier_out1, amount_out1)
//!   5. commitment_out2 = Poseidon(secret_out2, nullifier_out2, amount_out2)
//!   6. 0 ≤ amount_{in,out1,out2} < 2^64                      (range)
//!   7. amount_in == amount_out1 + amount_out2               (conservation)
//!
//! Публичные входы (порядок load-bearing — он же в on-chain верификаторе):
//!   [merkle_root, nullifier_hash, commitment_out1, commitment_out2]

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

use crate::bytes::fr_from_u64;
use crate::withdraw::{note_commitment, nullifier_hash, AMOUNT_BITS, POOL_TREE_DEPTH};

/// Число публичных входов transfer-схемы.
pub const TRANSFER_NR_PUBLIC_INPUTS: usize = 4;

/// Свидетели + публичные входы transfer-доказательства. `None` на setup.
#[derive(Clone)]
pub struct TransferCircuit {
    // входная нота (тратится)
    pub amount_in: Option<Fr>,
    pub secret_in: Option<Fr>,
    pub nullifier_in: Option<Fr>,
    pub path_siblings: Option<[Fr; POOL_TREE_DEPTH]>,
    pub path_indices: Option<[bool; POOL_TREE_DEPTH]>,
    // выходная нота 1 (получателю)
    pub amount_out1: Option<Fr>,
    pub secret_out1: Option<Fr>,
    pub nullifier_out1: Option<Fr>,
    // выходная нота 2 (сдача)
    pub amount_out2: Option<Fr>,
    pub secret_out2: Option<Fr>,
    pub nullifier_out2: Option<Fr>,
    // публичные входы
    pub merkle_root: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub commitment_out1: Option<Fr>,
    pub commitment_out2: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;

        // ── Приватные свидетели входной ноты ─────────────────────────
        let amount_in =
            FpVar::<Fr>::new_witness(cs.clone(), || self.amount_in.ok_or_else(missing))?;
        let secret_in =
            FpVar::<Fr>::new_witness(cs.clone(), || self.secret_in.ok_or_else(missing))?;
        let nullifier_in =
            FpVar::<Fr>::new_witness(cs.clone(), || self.nullifier_in.ok_or_else(missing))?;

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

        // ── Приватные свидетели выходных нот ─────────────────────────
        let amount_out1 =
            FpVar::<Fr>::new_witness(cs.clone(), || self.amount_out1.ok_or_else(missing))?;
        let secret_out1 =
            FpVar::<Fr>::new_witness(cs.clone(), || self.secret_out1.ok_or_else(missing))?;
        let nullifier_out1 =
            FpVar::<Fr>::new_witness(cs.clone(), || self.nullifier_out1.ok_or_else(missing))?;

        let amount_out2 =
            FpVar::<Fr>::new_witness(cs.clone(), || self.amount_out2.ok_or_else(missing))?;
        let secret_out2 =
            FpVar::<Fr>::new_witness(cs.clone(), || self.secret_out2.ok_or_else(missing))?;
        let nullifier_out2 =
            FpVar::<Fr>::new_witness(cs.clone(), || self.nullifier_out2.ok_or_else(missing))?;

        // ── Публичные входы ──────────────────────────────────────────
        let merkle_root =
            FpVar::<Fr>::new_input(cs.clone(), || self.merkle_root.ok_or_else(missing))?;
        let nullifier_hash_pub =
            FpVar::<Fr>::new_input(cs.clone(), || self.nullifier_hash.ok_or_else(missing))?;
        let commitment_out1_pub =
            FpVar::<Fr>::new_input(cs.clone(), || self.commitment_out1.ok_or_else(missing))?;
        let commitment_out2_pub =
            FpVar::<Fr>::new_input(cs.clone(), || self.commitment_out2.ok_or_else(missing))?;

        // 1. commitment_in = Poseidon(secret_in, nullifier_in, amount_in).
        let commitment_in = poseidon_hash_n_var(
            cs.clone(),
            &[secret_in, nullifier_in.clone(), amount_in.clone()],
        )?;

        // 2. nullifier_hash = Poseidon(nullifier_in).
        let computed_nh = poseidon_hash_n_var(cs.clone(), std::slice::from_ref(&nullifier_in))?;
        computed_nh.enforce_equal(&nullifier_hash_pub)?;

        // 3. Merkle membership: пройти от листа к корню.
        let mut current = commitment_in;
        for level in 0..POOL_TREE_DEPTH {
            let bit = &index_bits[level];
            let sib = &siblings[level];
            let left = FpVar::conditionally_select(bit, sib, &current)?;
            let right = FpVar::conditionally_select(bit, &current, sib)?;
            current = poseidon_hash_pair_var(cs.clone(), &left, &right)?;
        }
        current.enforce_equal(&merkle_root)?;

        // 4. commitment_out1 = Poseidon(secret_out1, nullifier_out1, amount_out1).
        let c_out1 = poseidon_hash_n_var(
            cs.clone(),
            &[secret_out1, nullifier_out1, amount_out1.clone()],
        )?;
        c_out1.enforce_equal(&commitment_out1_pub)?;

        // 5. commitment_out2 = Poseidon(secret_out2, nullifier_out2, amount_out2).
        let c_out2 = poseidon_hash_n_var(
            cs.clone(),
            &[secret_out2, nullifier_out2, amount_out2.clone()],
        )?;
        c_out2.enforce_equal(&commitment_out2_pub)?;

        // 6. range: 0 ≤ amount < 2^64 для всех трёх сумм.
        enforce_u64_range(cs.clone(), self.amount_in, &amount_in)?;
        enforce_u64_range(cs.clone(), self.amount_out1, &amount_out1)?;
        enforce_u64_range(cs.clone(), self.amount_out2, &amount_out2)?;

        // 7. conservation: in == out1 + out2 (нельзя выпустить больше, чем зашло).
        let sum = &amount_out1 + &amount_out2;
        sum.enforce_equal(&amount_in)?;

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

/// Локальный dev trusted setup (single-contributor — прод требует церемонии).
pub fn setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    let shape = TransferCircuit {
        amount_in: None,
        secret_in: None,
        nullifier_in: None,
        path_siblings: None,
        path_indices: None,
        amount_out1: None,
        secret_out1: None,
        nullifier_out1: None,
        amount_out2: None,
        secret_out2: None,
        nullifier_out2: None,
        merkle_root: None,
        nullifier_hash: None,
        commitment_out1: None,
        commitment_out2: None,
    };
    Groth16::<Bn254>::circuit_specific_setup(shape, rng)
}

/// Свидетель для доказательства перевода. Суммы задаются как `u64` base-units.
pub struct TransferWitness {
    pub amount_in: u64,
    pub secret_in: Fr,
    pub nullifier_in: Fr,
    pub path_siblings: [Fr; POOL_TREE_DEPTH],
    pub path_indices: [bool; POOL_TREE_DEPTH],
    pub amount_out1: u64,
    pub secret_out1: Fr,
    pub nullifier_out1: Fr,
    pub amount_out2: u64,
    pub secret_out2: Fr,
    pub nullifier_out2: Fr,
    pub merkle_root: Fr,
}

/// Доказать перевод. Возвращает proof + публичные входы
/// `[merkle_root, nullifier_hash, commitment_out1, commitment_out2]`.
pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    w: &TransferWitness,
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; TRANSFER_NR_PUBLIC_INPUTS]), SynthesisError> {
    let amount_in = fr_from_u64(w.amount_in);
    let amount_out1 = fr_from_u64(w.amount_out1);
    let amount_out2 = fr_from_u64(w.amount_out2);
    let nh = nullifier_hash(w.nullifier_in);
    let c_out1 = note_commitment(w.secret_out1, w.nullifier_out1, amount_out1);
    let c_out2 = note_commitment(w.secret_out2, w.nullifier_out2, amount_out2);

    let circuit = TransferCircuit {
        amount_in: Some(amount_in),
        secret_in: Some(w.secret_in),
        nullifier_in: Some(w.nullifier_in),
        path_siblings: Some(w.path_siblings),
        path_indices: Some(w.path_indices),
        amount_out1: Some(amount_out1),
        secret_out1: Some(w.secret_out1),
        nullifier_out1: Some(w.nullifier_out1),
        amount_out2: Some(amount_out2),
        secret_out2: Some(w.secret_out2),
        nullifier_out2: Some(w.nullifier_out2),
        merkle_root: Some(w.merkle_root),
        nullifier_hash: Some(nh),
        commitment_out1: Some(c_out1),
        commitment_out2: Some(c_out2),
    };
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok((proof, [w.merkle_root, nh, c_out1, c_out2]))
}

pub fn verify(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; TRANSFER_NR_PUBLIC_INPUTS],
) -> Result<bool, SynthesisError> {
    Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, public_inputs, proof)
}

pub fn prepare_vk(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    Groth16::<Bn254>::process_vk(vk).expect("process_vk")
}
