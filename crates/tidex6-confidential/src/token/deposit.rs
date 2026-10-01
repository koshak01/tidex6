//! Схема депозита в пул v2 с конфиденциального баланса (ADR-023).
//!
//! Граница «токен → пул» без числа. Контракт токена списывает шифротекст
//! `(C_d, D_s)` суммы `платёж + комиссия`, пул добавляет два листа v2: платёж
//! получателю и ноту комиссии казне. Схема доказывает:
//!
//!   1. ключ отправителя его (`s·P_s == H`), баланс расшифровывается в `b`;
//!   2. списание шифрует `total = pay + fee`, остаток `b − total ≥ 0`;
//!   3. лист платежа `H(H(core_pay, pay), 0)` — ядро получателя считает
//!      отправитель, как в `transfer_v2`;
//!   4. лист комиссии `H(H(core(treasury_pk, rho_fee, 0), fee), 0)`;
//!   5. `fee·100 ≥ pay` и `fee ≥ fee_floor` — та же политика, что у пула;
//!   6. все суммы < 2^64.
//!
//! Возврата у таких нот нет: пул пересчитывает лист возврата из открытой
//! суммы, а здесь её нет на цепи. Возврат через схему — отдельный шаг.
//!
//! Публичные входы (порядок load-bearing):
//!   [P_s, C_a, D_a, C_d, D_s] по две координаты,
//!   commitment_pay, commitment_fee, treasury_pk, fee_floor — всего 14.

use ark_bn254::{Bn254, Fr};
use ark_ed_on_bn254::{EdwardsAffine, Fr as BjjFr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use super::elgamal::{self, Ciphertext, SecretKey, point_inputs};
use super::gadget;
use crate::bytes::fr_from_u64;
use crate::note_v2::{self, core_var, leaf_var};
use crate::transfer_v2::{FEE_GAP_BITS, FEE_PERCENT_DIVISOR, enforce_bits};

pub const DEPOSIT_NR_PUBLIC_INPUTS: usize = 14;

#[derive(Clone, Default)]
pub struct DepositFromTokenCircuit {
    // приватные свидетели
    pub secret: Option<BjjFr>,
    pub balance: Option<u64>,
    pub amount_pay: Option<u64>,
    pub amount_fee: Option<u64>,
    pub opening: Option<BjjFr>,
    pub core_pay: Option<Fr>,
    pub rho_fee: Option<Fr>,
    // публичные входы
    pub sender_key: Option<EdwardsAffine>,
    pub balance_commitment: Option<EdwardsAffine>,
    pub balance_handle: Option<EdwardsAffine>,
    pub debit_commitment: Option<EdwardsAffine>,
    pub debit_handle: Option<EdwardsAffine>,
    pub commitment_pay: Option<Fr>,
    pub commitment_fee: Option<Fr>,
    pub treasury_pk: Option<Fr>,
    pub fee_floor: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for DepositFromTokenCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;
        let input = |v: Option<Fr>| FpVar::<Fr>::new_input(cs.clone(), || v.ok_or_else(missing));
        let witness =
            |v: Option<Fr>| FpVar::<Fr>::new_witness(cs.clone(), || v.ok_or_else(missing));

        // ── Публичные входы (порядок load-bearing) ───────────────────
        let sender_key = gadget::point_input(cs.clone(), self.sender_key)?;
        let balance_commitment = gadget::point_input(cs.clone(), self.balance_commitment)?;
        let balance_handle = gadget::point_input(cs.clone(), self.balance_handle)?;
        let debit_commitment = gadget::point_input(cs.clone(), self.debit_commitment)?;
        let debit_handle = gadget::point_input(cs.clone(), self.debit_handle)?;
        let commitment_pay = input(self.commitment_pay)?;
        let commitment_fee = input(self.commitment_fee)?;
        let treasury_pk = input(self.treasury_pk)?;
        let fee_floor = input(self.fee_floor)?;

        // ── Свидетели ────────────────────────────────────────────────
        let secret_bits = gadget::scalar_witness(cs.clone(), self.secret)?;
        let (balance, balance_bits) = gadget::amount_witness(cs.clone(), self.balance)?;
        let (pay, _) = gadget::amount_witness(cs.clone(), self.amount_pay)?;
        let (fee, _) = gadget::amount_witness(cs.clone(), self.amount_fee)?;
        let total_value = match (self.amount_pay, self.amount_fee) {
            (Some(p), Some(f)) => Some(p.checked_add(f).ok_or(SynthesisError::Unsatisfiable)?),
            _ => None,
        };
        let (total, total_bits) = gadget::amount_witness(cs.clone(), total_value)?;
        let remaining_value = match (self.balance, total_value) {
            (Some(b), Some(t)) => Some(b.checked_sub(t).ok_or(SynthesisError::Unsatisfiable)?),
            _ => None,
        };
        let (remaining, _) = gadget::amount_witness(cs.clone(), remaining_value)?;
        let opening_bits = gadget::scalar_witness(cs.clone(), self.opening)?;
        let core_pay = witness(self.core_pay)?;
        let rho_fee = witness(self.rho_fee)?;

        // 1. Ключ и баланс.
        gadget::enforce_public_key(&secret_bits, &sender_key)?;
        gadget::enforce_balance(
            &secret_bits,
            &balance_commitment,
            &balance_handle,
            &balance_bits,
        )?;
        // 2. Списание — ровно платёж с комиссией, остаток неотрицателен.
        total.enforce_equal(&(&pay + &fee))?;
        balance.enforce_equal(&(&remaining + &total))?;
        gadget::commitment(&total_bits, &opening_bits)?.enforce_equal(&debit_commitment)?;
        gadget::mul(&sender_key, &opening_bits)?.enforce_equal(&debit_handle)?;

        // 3–4. Листы пула v2: платёж и комиссия, без возврата.
        let no_refund = FpVar::<Fr>::zero();
        leaf_var(cs.clone(), &core_pay, &pay, &no_refund)?.enforce_equal(&commitment_pay)?;
        let core_fee = core_var(cs.clone(), &treasury_pk, &rho_fee, &FpVar::zero())?;
        leaf_var(cs.clone(), &core_fee, &fee, &no_refund)?.enforce_equal(&commitment_fee)?;

        // 5. Комиссия не меньше 1% платежа и не меньше минимума.
        let hundred = FpVar::constant(fr_from_u64(FEE_PERCENT_DIVISOR));
        let gap_percent_value = match (self.amount_fee, self.amount_pay) {
            (Some(f), Some(p)) => {
                Some(fr_from_u64(f) * fr_from_u64(FEE_PERCENT_DIVISOR) - fr_from_u64(p))
            }
            _ => None,
        };
        enforce_bits(
            cs.clone(),
            gap_percent_value,
            &(&fee * &hundred - &pay),
            FEE_GAP_BITS,
        )?;
        let gap_floor_value = match (self.amount_fee, self.fee_floor) {
            (Some(f), Some(m)) => Some(fr_from_u64(f) - m),
            _ => None,
        };
        enforce_bits(cs, gap_floor_value, &(&fee - &fee_floor), 64)
    }
}

pub fn setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::circuit_specific_setup(DepositFromTokenCircuit::default(), rng)
}

pub struct DepositFromTokenWitness {
    pub secret: SecretKey,
    pub balance: u64,
    pub available: Ciphertext,
    pub amount_pay: u64,
    pub amount_fee: u64,
    pub opening: BjjFr,
    /// Ядро ноты получателя: `core(owner_pk получателя, rho, aux)`.
    pub core_pay: Fr,
    pub rho_fee: Fr,
    /// Ключ казны и минимум комиссии — константы пула.
    pub treasury_pk: Fr,
    pub fee_floor: u64,
}

pub struct DepositFromTokenPublic {
    pub sender_key: EdwardsAffine,
    pub available: Ciphertext,
    /// Списываемый шифротекст суммы `pay + fee`.
    pub debit: Ciphertext,
    pub commitment_pay: Fr,
    pub commitment_fee: Fr,
    pub treasury_pk: Fr,
    pub fee_floor: Fr,
}

impl DepositFromTokenPublic {
    pub fn inputs(&self) -> [Fr; DEPOSIT_NR_PUBLIC_INPUTS] {
        let points = [
            self.sender_key,
            self.available.commitment,
            self.available.handle,
            self.debit.commitment,
            self.debit.handle,
        ];
        let mut out = [Fr::from(0u64); DEPOSIT_NR_PUBLIC_INPUTS];
        for (i, point) in points.iter().enumerate() {
            let [x, y] = point_inputs(point);
            out[2 * i] = x;
            out[2 * i + 1] = y;
        }
        out[10] = self.commitment_pay;
        out[11] = self.commitment_fee;
        out[12] = self.treasury_pk;
        out[13] = self.fee_floor;
        out
    }
}

pub fn public_part(
    w: &DepositFromTokenWitness,
) -> Result<DepositFromTokenPublic, elgamal::ElGamalError> {
    let sender = w.secret.public_key()?;
    let total = w
        .amount_pay
        .checked_add(w.amount_fee)
        .ok_or(elgamal::ElGamalError::AmountTooLarge)?;
    let no_refund = Fr::from(0u64);
    let core_fee = note_v2::core(w.treasury_pk, w.rho_fee, Fr::from(0u64));
    Ok(DepositFromTokenPublic {
        sender_key: sender.0,
        available: w.available,
        debit: elgamal::encrypt(&sender, total, w.opening),
        commitment_pay: note_v2::leaf(note_v2::body(w.core_pay, w.amount_pay), no_refund),
        commitment_fee: note_v2::leaf(note_v2::body(core_fee, w.amount_fee), no_refund),
        treasury_pk: w.treasury_pk,
        fee_floor: fr_from_u64(w.fee_floor),
    })
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    w: &DepositFromTokenWitness,
    rng: &mut R,
) -> Result<(Proof<Bn254>, DepositFromTokenPublic), SynthesisError> {
    let public = public_part(w).map_err(|_| SynthesisError::Unsatisfiable)?;
    let circuit = DepositFromTokenCircuit {
        secret: Some(w.secret.0),
        balance: Some(w.balance),
        amount_pay: Some(w.amount_pay),
        amount_fee: Some(w.amount_fee),
        opening: Some(w.opening),
        core_pay: Some(w.core_pay),
        rho_fee: Some(w.rho_fee),
        sender_key: Some(public.sender_key),
        balance_commitment: Some(public.available.commitment),
        balance_handle: Some(public.available.handle),
        debit_commitment: Some(public.debit.commitment),
        debit_handle: Some(public.debit.handle),
        commitment_pay: Some(public.commitment_pay),
        commitment_fee: Some(public.commitment_fee),
        treasury_pk: Some(public.treasury_pk),
        fee_floor: Some(public.fee_floor),
    };
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok((proof, public))
}

pub fn verify(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; DEPOSIT_NR_PUBLIC_INPUTS],
) -> Result<bool, SynthesisError> {
    Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, public_inputs, proof)
}

pub fn prepare_vk(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    Groth16::<Bn254>::process_vk(vk).expect("process_vk")
}
