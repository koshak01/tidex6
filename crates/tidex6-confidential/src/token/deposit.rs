//! Схема депозита в пул с конфиденциального баланса.
//!
//! Граница «токен → пул» без числа: контракт токена списывает шифротекст
//! `(C_m, D_s)`, пул получает лист `Poseidon(secret, nullifier, m)`. Схема
//! доказывает, что за обоими стоит одна и та же сумма `m`, что она была на
//! балансе, и что ключ у отправителя есть.
//!
//! Публичные входы: `[P_s, C_a, D_a, C_m, D_s]` по две координаты и
//! `commitment` — 11 элементов.

use ark_bn254::{Bn254, Fr};
use ark_ed_on_bn254::{EdwardsAffine, Fr as BjjFr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use super::elgamal::{self, Ciphertext, SecretKey, point_inputs};
use super::gadget;
use crate::bytes::fr_from_u64;

pub const DEPOSIT_NR_PUBLIC_INPUTS: usize = 11;

#[derive(Clone, Default)]
pub struct DepositFromTokenCircuit {
    // приватные свидетели
    pub secret: Option<BjjFr>,
    pub balance: Option<u64>,
    pub amount: Option<u64>,
    pub opening: Option<BjjFr>,
    pub note_secret: Option<Fr>,
    pub note_nullifier: Option<Fr>,
    // публичные входы
    pub sender_key: Option<EdwardsAffine>,
    pub balance_commitment: Option<EdwardsAffine>,
    pub balance_handle: Option<EdwardsAffine>,
    pub amount_commitment: Option<EdwardsAffine>,
    pub sender_handle: Option<EdwardsAffine>,
    pub note_commitment: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for DepositFromTokenCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;
        let sender_key = gadget::point_input(cs.clone(), self.sender_key)?;
        let balance_commitment = gadget::point_input(cs.clone(), self.balance_commitment)?;
        let balance_handle = gadget::point_input(cs.clone(), self.balance_handle)?;
        let amount_commitment = gadget::point_input(cs.clone(), self.amount_commitment)?;
        let sender_handle = gadget::point_input(cs.clone(), self.sender_handle)?;
        let note_commitment =
            FpVar::new_input(cs.clone(), || self.note_commitment.ok_or_else(missing))?;

        let secret_bits = gadget::scalar_witness(cs.clone(), self.secret)?;
        let (balance, balance_bits) = gadget::amount_witness(cs.clone(), self.balance)?;
        let (amount, amount_bits) = gadget::amount_witness(cs.clone(), self.amount)?;
        let remaining_value = match (self.balance, self.amount) {
            (Some(b), Some(m)) => Some(b.checked_sub(m).ok_or(SynthesisError::Unsatisfiable)?),
            _ => None,
        };
        let (remaining, _) = gadget::amount_witness(cs.clone(), remaining_value)?;
        let opening_bits = gadget::scalar_witness(cs.clone(), self.opening)?;
        let note_secret = FpVar::new_witness(cs.clone(), || self.note_secret.ok_or_else(missing))?;
        let note_nullifier =
            FpVar::new_witness(cs.clone(), || self.note_nullifier.ok_or_else(missing))?;

        gadget::enforce_public_key(&secret_bits, &sender_key)?;
        gadget::enforce_balance(
            &secret_bits,
            &balance_commitment,
            &balance_handle,
            &balance_bits,
        )?;
        balance.enforce_equal(&(remaining + &amount))?;
        gadget::commitment(&amount_bits, &opening_bits)?.enforce_equal(&amount_commitment)?;
        gadget::mul(&sender_key, &opening_bits)?.enforce_equal(&sender_handle)?;
        // Та же сумма — в ноте пула.
        gadget::note_commitment(cs, &note_secret, &note_nullifier, &amount)?
            .enforce_equal(&note_commitment)
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
    pub amount: u64,
    pub opening: BjjFr,
    pub note_secret: Fr,
    pub note_nullifier: Fr,
}

pub struct DepositFromTokenPublic {
    pub sender_key: EdwardsAffine,
    pub available: Ciphertext,
    /// Списываемый шифротекст `(C_m, D_s)`.
    pub spent: Ciphertext,
    pub note_commitment: Fr,
}

impl DepositFromTokenPublic {
    pub fn inputs(&self) -> [Fr; DEPOSIT_NR_PUBLIC_INPUTS] {
        let points = [
            self.sender_key,
            self.available.commitment,
            self.available.handle,
            self.spent.commitment,
            self.spent.handle,
        ];
        let mut out = [Fr::from(0u64); DEPOSIT_NR_PUBLIC_INPUTS];
        for (i, point) in points.iter().enumerate() {
            let [x, y] = point_inputs(point);
            out[2 * i] = x;
            out[2 * i + 1] = y;
        }
        out[10] = self.note_commitment;
        out
    }
}

pub fn public_part(
    w: &DepositFromTokenWitness,
) -> Result<DepositFromTokenPublic, elgamal::ElGamalError> {
    let sender = w.secret.public_key()?;
    Ok(DepositFromTokenPublic {
        sender_key: sender.0,
        available: w.available,
        spent: elgamal::encrypt(&sender, w.amount, w.opening),
        note_commitment: crate::withdraw::note_commitment(
            w.note_secret,
            w.note_nullifier,
            fr_from_u64(w.amount),
        ),
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
        amount: Some(w.amount),
        opening: Some(w.opening),
        note_secret: Some(w.note_secret),
        note_nullifier: Some(w.note_nullifier),
        sender_key: Some(public.sender_key),
        balance_commitment: Some(public.available.commitment),
        balance_handle: Some(public.available.handle),
        amount_commitment: Some(public.spent.commitment),
        sender_handle: Some(public.spent.handle),
        note_commitment: Some(public.note_commitment),
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
