//! Схема перевода конфиденциального токена.
//!
//! Отправитель доказывает, не раскрывая ни ключа, ни баланса, ни суммы:
//!
//!   1. `s·P_s == H`                    — знает ключ от счёта `P_s`;
//!   2. `C_a − s·D_a == b·G`            — его доступный баланс равен `b`;
//!   3. `0 ≤ b − m < 2^64`, `0 ≤ m < 2^64` — хватает и без переполнения;
//!   4. `C_m == m·G + r·H`              — коммитмент суммы сделан честно;
//!   5. `D_s == r·P_s`, `D_r == r·P_r`, `D_x == r·P_x` — ручки отправителю,
//!      получателю и аудитору на то же открытие `r`.
//!
//! Контракт после проверки делает `available_s −= (C_m, D_s)` и
//! `pending_r += (C_m, D_r)`; ручка аудитора уходит в событие. Нет аудитора —
//! в `P_x` подставляется `P_s`, ручка получается второй ручкой отправителя.
//!
//! Публичные входы, по две координаты `(x, y)` на точку, порядок load-bearing:
//!   `[P_s, C_a, D_a, C_m, D_s, P_r, D_r, P_x, D_x]` — 18 элементов.

use ark_bn254::{Bn254, Fr};
use ark_ed_on_bn254::{EdwardsAffine, Fr as BjjFr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::eq::EqGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use super::elgamal::{self, point_inputs, Ciphertext, PublicKey, SecretKey};
use super::gadget;

pub const TRANSFER_NR_PUBLIC_INPUTS: usize = 18;

#[derive(Clone, Default)]
pub struct TokenTransferCircuit {
    // приватные свидетели
    pub secret: Option<BjjFr>,
    pub balance: Option<u64>,
    pub amount: Option<u64>,
    pub opening: Option<BjjFr>,
    // публичные входы
    pub sender_key: Option<EdwardsAffine>,
    pub balance_commitment: Option<EdwardsAffine>,
    pub balance_handle: Option<EdwardsAffine>,
    pub amount_commitment: Option<EdwardsAffine>,
    pub sender_handle: Option<EdwardsAffine>,
    pub recipient_key: Option<EdwardsAffine>,
    pub recipient_handle: Option<EdwardsAffine>,
    pub auditor_key: Option<EdwardsAffine>,
    pub auditor_handle: Option<EdwardsAffine>,
}

impl ConstraintSynthesizer<Fr> for TokenTransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ── Публичные входы, порядок load-bearing ────────────────────
        let sender_key = gadget::point_input(cs.clone(), self.sender_key)?;
        let balance_commitment = gadget::point_input(cs.clone(), self.balance_commitment)?;
        let balance_handle = gadget::point_input(cs.clone(), self.balance_handle)?;
        let amount_commitment = gadget::point_input(cs.clone(), self.amount_commitment)?;
        let sender_handle = gadget::point_input(cs.clone(), self.sender_handle)?;
        let recipient_key = gadget::point_input(cs.clone(), self.recipient_key)?;
        let recipient_handle = gadget::point_input(cs.clone(), self.recipient_handle)?;
        let auditor_key = gadget::point_input(cs.clone(), self.auditor_key)?;
        let auditor_handle = gadget::point_input(cs.clone(), self.auditor_handle)?;

        // ── Приватные свидетели ──────────────────────────────────────
        let secret_bits = gadget::scalar_witness(cs.clone(), self.secret)?;
        let (balance, balance_bits) = gadget::amount_witness(cs.clone(), self.balance)?;
        let (amount, amount_bits) = gadget::amount_witness(cs.clone(), self.amount)?;
        let remaining_value = match (self.balance, self.amount) {
            (Some(b), Some(m)) => Some(b.checked_sub(m).ok_or(SynthesisError::Unsatisfiable)?),
            _ => None,
        };
        let (remaining, _remaining_bits) = gadget::amount_witness(cs.clone(), remaining_value)?;
        let opening_bits = gadget::scalar_witness(cs, self.opening)?;

        // 1. Ключ от счёта.
        gadget::enforce_public_key(&secret_bits, &sender_key)?;
        // 2. Баланс расшифровывается в `b`.
        gadget::enforce_balance(&secret_bits, &balance_commitment, &balance_handle, &balance_bits)?;
        // 3. `b == (b − m) + m`; оба слагаемых уже ограничены 64 битами.
        balance.enforce_equal(&(remaining + amount))?;
        // 4. Коммитмент суммы.
        gadget::commitment(&amount_bits, &opening_bits)?.enforce_equal(&amount_commitment)?;
        // 5. Ручки на то же открытие.
        gadget::mul(&sender_key, &opening_bits)?.enforce_equal(&sender_handle)?;
        gadget::mul(&recipient_key, &opening_bits)?.enforce_equal(&recipient_handle)?;
        gadget::mul(&auditor_key, &opening_bits)?.enforce_equal(&auditor_handle)
    }
}

pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::circuit_specific_setup(TokenTransferCircuit::default(), rng)
}

/// Свидетель перевода. `balance` — расшифрованный доступный баланс
/// отправителя, `available` — его шифротекст из контракта.
pub struct TokenTransferWitness {
    pub secret: SecretKey,
    pub balance: u64,
    pub available: Ciphertext,
    pub amount: u64,
    pub opening: BjjFr,
    pub recipient: PublicKey,
    /// Аудитор платежа; без него — ключ отправителя.
    pub auditor: PublicKey,
}

/// Публичная часть перевода — то, что уходит в контракт вместе с proof.
pub struct TokenTransferPublic {
    pub sender_key: EdwardsAffine,
    pub available: Ciphertext,
    pub amount_commitment: EdwardsAffine,
    pub sender_handle: EdwardsAffine,
    pub recipient_key: EdwardsAffine,
    pub recipient_handle: EdwardsAffine,
    pub auditor_key: EdwardsAffine,
    pub auditor_handle: EdwardsAffine,
}

impl TokenTransferPublic {
    /// Публичные входы в порядке схемы.
    pub fn inputs(&self) -> [Fr; TRANSFER_NR_PUBLIC_INPUTS] {
        let points = [
            self.sender_key,
            self.available.commitment,
            self.available.handle,
            self.amount_commitment,
            self.sender_handle,
            self.recipient_key,
            self.recipient_handle,
            self.auditor_key,
            self.auditor_handle,
        ];
        let mut out = [Fr::from(0u64); TRANSFER_NR_PUBLIC_INPUTS];
        for (i, point) in points.iter().enumerate() {
            let [x, y] = point_inputs(point);
            out[2 * i] = x;
            out[2 * i + 1] = y;
        }
        out
    }
}

/// Собрать публичную часть из свидетеля: коммитмент и три ручки.
pub fn public_part(w: &TokenTransferWitness) -> Result<TokenTransferPublic, elgamal::ElGamalError> {
    let sender = w.secret.public_key()?;
    Ok(TokenTransferPublic {
        sender_key: sender.0,
        available: w.available,
        amount_commitment: elgamal::commit(w.amount, w.opening),
        sender_handle: sender.handle(w.opening),
        recipient_key: w.recipient.0,
        recipient_handle: w.recipient.handle(w.opening),
        auditor_key: w.auditor.0,
        auditor_handle: w.auditor.handle(w.opening),
    })
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    w: &TokenTransferWitness,
    rng: &mut R,
) -> Result<(Proof<Bn254>, TokenTransferPublic), SynthesisError> {
    let public = public_part(w).map_err(|_| SynthesisError::Unsatisfiable)?;
    let circuit = TokenTransferCircuit {
        secret: Some(w.secret.0),
        balance: Some(w.balance),
        amount: Some(w.amount),
        opening: Some(w.opening),
        sender_key: Some(public.sender_key),
        balance_commitment: Some(public.available.commitment),
        balance_handle: Some(public.available.handle),
        amount_commitment: Some(public.amount_commitment),
        sender_handle: Some(public.sender_handle),
        recipient_key: Some(public.recipient_key),
        recipient_handle: Some(public.recipient_handle),
        auditor_key: Some(public.auditor_key),
        auditor_handle: Some(public.auditor_handle),
    };
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok((proof, public))
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
