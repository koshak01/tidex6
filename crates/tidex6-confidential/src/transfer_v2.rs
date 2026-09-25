//! Перевод внутри пула v2 (ADR-022): нота владельца → платёж, сдача, комиссия.
//!
//! Доказывает:
//!   1. входную ноту тратит её владелец (как в `withdraw_v2`), она в дереве,
//!      nf = H(H(D_NF, rho), pos)
//!   2. платёж: cm_pay = H(H(core_pay, amount_pay), 0) — ядро под ключ
//!      получателя считает переводящий
//!   3. сдача возвращается ТОМУ ЖЕ владельцу: core_change строится в схеме из
//!      его owner_pk. Иначе платёж можно было бы выдать за «сдачу» и заплатить
//!      комиссию с копейки
//!   4. комиссия — нота казны: core_fee строится в схеме из `treasury_pk`
//!      (публичный вход, контракт подставляет свой), у неё нет возврата
//!   5. комиссия не меньше 1% платежа, с округлением вверх
//!      (`fee·100 ≥ amount_pay`), и не меньше минимума `fee_floor`
//!   6. все суммы < 2^64, amount_in = amount_pay + amount_change + fee
//!
//! У нот, рождённых в пуле, возврата нет: вернуть их было бы некому, кроме
//! владельца.
//!
//! Публичные входы (порядок load-bearing — он же в контракте):
//!   [merkle_root, nullifier, commitment_pay, commitment_change,
//!    commitment_fee, treasury_pk, fee_floor]

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use tidex6_circuits::circom_qap::CircomReduction;

use crate::bytes::fr_from_u64;
use crate::note_v2::{self, core_var, leaf_var, nullifier_var, owner_pk_var, position_var};
use crate::withdraw::{POOL_TREE_DEPTH, enforce_u64_range};
use crate::withdraw_v2::{enforce_membership, path_witness};

/// Число публичных входов перевода v2.
pub const TRANSFER_V2_NR_PUBLIC_INPUTS: usize = 7;

/// Комиссия — 1% платежа, в сотых долях.
pub const FEE_PERCENT_DIVISOR: u64 = 100;

/// Разрядность проверки `fee·100 − amount_pay ≥ 0`: обе суммы меньше 2^64,
/// значит честная разность меньше 2^71. Отрицательная в поле становится
/// числом около 2^254 и в 72 бита не ляжет.
const FEE_GAP_BITS: usize = 72;

/// Свидетели + публичные входы. `None` на setup.
#[derive(Clone, Default)]
pub struct TransferV2Circuit {
    // входная нота
    pub sk_spend: Option<Fr>,
    pub rho_in: Option<Fr>,
    pub aux_in: Option<Fr>,
    pub amount_in: Option<Fr>,
    pub refund_in: Option<Fr>,
    pub path_siblings: Option<[Fr; POOL_TREE_DEPTH]>,
    pub path_indices: Option<[bool; POOL_TREE_DEPTH]>,
    // платёж
    pub core_pay: Option<Fr>,
    pub amount_pay: Option<Fr>,
    // сдача — себе
    pub rho_change: Option<Fr>,
    pub aux_change: Option<Fr>,
    pub amount_change: Option<Fr>,
    // комиссия — казне
    pub rho_fee: Option<Fr>,
    pub amount_fee: Option<Fr>,
    // публичные входы
    pub merkle_root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub commitment_pay: Option<Fr>,
    pub commitment_change: Option<Fr>,
    pub commitment_fee: Option<Fr>,
    pub treasury_pk: Option<Fr>,
    pub fee_floor: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for TransferV2Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;
        let witness =
            |v: Option<Fr>| FpVar::<Fr>::new_witness(cs.clone(), || v.ok_or_else(missing));
        let input = |v: Option<Fr>| FpVar::<Fr>::new_input(cs.clone(), || v.ok_or_else(missing));

        // ── Приватные свидетели ──────────────────────────────────────
        let sk = witness(self.sk_spend)?;
        let rho_in = witness(self.rho_in)?;
        let aux_in = witness(self.aux_in)?;
        let amount_in = witness(self.amount_in)?;
        let refund_in = witness(self.refund_in)?;
        let (siblings, bits) = path_witness(cs.clone(), self.path_siblings, self.path_indices)?;
        let core_pay = witness(self.core_pay)?;
        let amount_pay = witness(self.amount_pay)?;
        let rho_change = witness(self.rho_change)?;
        let aux_change = witness(self.aux_change)?;
        let amount_change = witness(self.amount_change)?;
        let rho_fee = witness(self.rho_fee)?;
        let amount_fee = witness(self.amount_fee)?;

        // ── Публичные входы (порядок load-bearing) ───────────────────
        let merkle_root = input(self.merkle_root)?;
        let nullifier = input(self.nullifier)?;
        let commitment_pay = input(self.commitment_pay)?;
        let commitment_change = input(self.commitment_change)?;
        let commitment_fee = input(self.commitment_fee)?;
        let treasury_pk = input(self.treasury_pk)?;
        let fee_floor = input(self.fee_floor)?;

        // 1. Вход тратит владелец, вход в дереве, nullifier от позиции.
        let owner_pk = owner_pk_var(cs.clone(), &sk)?;
        let core_in = core_var(cs.clone(), &owner_pk, &rho_in, &aux_in)?;
        let leaf_in = leaf_var(cs.clone(), &core_in, &amount_in, &refund_in)?;
        enforce_membership(cs.clone(), leaf_in, &siblings, &bits, &merkle_root)?;
        let pos = position_var(&bits);
        nullifier_var(cs.clone(), &rho_in, &pos)?.enforce_equal(&nullifier)?;

        let no_refund = FpVar::<Fr>::zero();
        // 2. Платёж.
        leaf_var(cs.clone(), &core_pay, &amount_pay, &no_refund)?.enforce_equal(&commitment_pay)?;
        // 3. Сдача — тому же владельцу.
        let core_change = core_var(cs.clone(), &owner_pk, &rho_change, &aux_change)?;
        leaf_var(cs.clone(), &core_change, &amount_change, &no_refund)?
            .enforce_equal(&commitment_change)?;
        // 4. Комиссия — казне.
        let core_fee = core_var(cs.clone(), &treasury_pk, &rho_fee, &FpVar::zero())?;
        leaf_var(cs.clone(), &core_fee, &amount_fee, &no_refund)?.enforce_equal(&commitment_fee)?;

        // 6. Диапазоны и сохранение.
        enforce_u64_range(cs.clone(), self.amount_in, &amount_in)?;
        enforce_u64_range(cs.clone(), self.amount_pay, &amount_pay)?;
        enforce_u64_range(cs.clone(), self.amount_change, &amount_change)?;
        enforce_u64_range(cs.clone(), self.amount_fee, &amount_fee)?;
        (&amount_pay + &amount_change + &amount_fee).enforce_equal(&amount_in)?;

        // 5. Комиссия: fee·100 ≥ платёж и fee ≥ минимум — обе разности
        //    неотрицательны, то есть укладываются в свою разрядность.
        let hundred = FpVar::constant(fr_from_u64(FEE_PERCENT_DIVISOR));
        let gap_percent = &amount_fee * &hundred - &amount_pay;
        let gap_percent_value = match (self.amount_fee, self.amount_pay) {
            (Some(f), Some(p)) => Some(f * fr_from_u64(FEE_PERCENT_DIVISOR) - p),
            _ => None,
        };
        enforce_bits(cs.clone(), gap_percent_value, &gap_percent, FEE_GAP_BITS)?;
        let gap_floor = &amount_fee - &fee_floor;
        let gap_floor_value = match (self.amount_fee, self.fee_floor) {
            (Some(f), Some(m)) => Some(f - m),
            _ => None,
        };
        enforce_bits(cs, gap_floor_value, &gap_floor, 64)?;
        Ok(())
    }
}

/// `0 ≤ value < 2^bits` через битовое разложение.
fn enforce_bits(
    cs: ConstraintSystemRef<Fr>,
    value: Option<Fr>,
    var: &FpVar<Fr>,
    bits: usize,
) -> Result<(), SynthesisError> {
    let missing = || SynthesisError::AssignmentMissing;
    let mut acc = FpVar::<Fr>::zero();
    let mut coeff = Fr::from(1u64);
    for i in 0..bits {
        let bit = Boolean::<Fr>::new_witness(cs.clone(), || {
            value
                .map(|v| v.into_bigint().get_bit(i))
                .ok_or_else(missing)
        })?;
        acc += FpVar::from(bit) * FpVar::constant(coeff);
        coeff += coeff;
    }
    acc.enforce_equal(var)
}

/// Комиссия с платежа: 1% с округлением вверх, но не меньше `floor`. Та же
/// формула у контракта на входе и у клиента при пересылке.
pub fn fee_for(amount: u64, floor: u64) -> u64 {
    amount.div_ceil(FEE_PERCENT_DIVISOR).max(floor)
}

/// Свидетель перевода.
pub struct TransferV2Witness {
    pub sk_spend: Fr,
    pub rho_in: Fr,
    pub aux_in: Fr,
    pub amount_in: u64,
    pub refund_in: Fr,
    pub path_siblings: [Fr; POOL_TREE_DEPTH],
    pub path_indices: [bool; POOL_TREE_DEPTH],
    pub core_pay: Fr,
    pub amount_pay: u64,
    pub rho_change: Fr,
    pub aux_change: Fr,
    pub amount_change: u64,
    pub rho_fee: Fr,
    pub amount_fee: u64,
    pub merkle_root: Fr,
    pub treasury_pk: Fr,
    pub fee_floor: u64,
}

/// Доказательство ключом церемонии.
pub fn prove_ceremony<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    w: &TransferV2Witness,
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; TRANSFER_V2_NR_PUBLIC_INPUTS]), SynthesisError> {
    let (circuit, public_inputs) = circuit_and_inputs(w);
    Ok((
        Groth16::<Bn254, CircomReduction>::prove(pk, circuit, rng)?,
        public_inputs,
    ))
}

fn circuit_and_inputs(
    w: &TransferV2Witness,
) -> (TransferV2Circuit, [Fr; TRANSFER_V2_NR_PUBLIC_INPUTS]) {
    let position = w
        .path_indices
        .iter()
        .enumerate()
        .fold(0u64, |acc, (i, bit)| acc | (u64::from(*bit) << i));
    let nf = note_v2::nullifier(w.rho_in, position);
    let zero = Fr::from(0u64);
    let owner = note_v2::owner_pk(w.sk_spend);
    let cm_pay = note_v2::leaf(note_v2::body(w.core_pay, w.amount_pay), zero);
    let core_change = note_v2::core(owner, w.rho_change, w.aux_change);
    let cm_change = note_v2::leaf(note_v2::body(core_change, w.amount_change), zero);
    let core_fee = note_v2::core(w.treasury_pk, w.rho_fee, zero);
    let cm_fee = note_v2::leaf(note_v2::body(core_fee, w.amount_fee), zero);
    let fee_floor = fr_from_u64(w.fee_floor);
    let circuit = TransferV2Circuit {
        sk_spend: Some(w.sk_spend),
        rho_in: Some(w.rho_in),
        aux_in: Some(w.aux_in),
        amount_in: Some(fr_from_u64(w.amount_in)),
        refund_in: Some(w.refund_in),
        path_siblings: Some(w.path_siblings),
        path_indices: Some(w.path_indices),
        core_pay: Some(w.core_pay),
        amount_pay: Some(fr_from_u64(w.amount_pay)),
        rho_change: Some(w.rho_change),
        aux_change: Some(w.aux_change),
        amount_change: Some(fr_from_u64(w.amount_change)),
        rho_fee: Some(w.rho_fee),
        amount_fee: Some(fr_from_u64(w.amount_fee)),
        merkle_root: Some(w.merkle_root),
        nullifier: Some(nf),
        commitment_pay: Some(cm_pay),
        commitment_change: Some(cm_change),
        commitment_fee: Some(cm_fee),
        treasury_pk: Some(w.treasury_pk),
        fee_floor: Some(fee_floor),
    };
    let public_inputs = [
        w.merkle_root,
        nf,
        cm_pay,
        cm_change,
        cm_fee,
        w.treasury_pk,
        fee_floor,
    ];
    (circuit, public_inputs)
}

pub fn verify(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; TRANSFER_V2_NR_PUBLIC_INPUTS],
) -> Result<bool, SynthesisError> {
    Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, public_inputs, proof)
}
