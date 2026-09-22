//! Схема вывода из конфиденциального баланса в открытый ERC-20 (`unwrap`).
//!
//! Сумма здесь публична — контракт должен знать, сколько отдать. Доказывается
//! знание ключа, расшифровка баланса в `b` и `b − amount ≥ 0`. Контракт после
//! проверки делает `available −= (amount·G, O)` (см. `elgamal::plain`).
//!
//! Публичные входы: `[P_s.x, P_s.y, C_a.x, C_a.y, D_a.x, D_a.y, amount]` — 7.
//! Контракт сам проверяет `amount < 2^64`; в схеме 64 битами ограничен
//! остаток, поэтому `b == remaining + amount` не переполняется.

use ark_bn254::{Bn254, Fr};
use ark_ed_on_bn254::{EdwardsAffine, Fr as BjjFr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use super::elgamal::{Ciphertext, SecretKey, point_inputs};
use super::gadget;

pub const UNWRAP_NR_PUBLIC_INPUTS: usize = 7;

#[derive(Clone, Default)]
pub struct TokenUnwrapCircuit {
    pub secret: Option<BjjFr>,
    pub balance: Option<u64>,
    pub sender_key: Option<EdwardsAffine>,
    pub balance_commitment: Option<EdwardsAffine>,
    pub balance_handle: Option<EdwardsAffine>,
    pub amount: Option<u64>,
}

impl ConstraintSynthesizer<Fr> for TokenUnwrapCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let sender_key = gadget::point_input(cs.clone(), self.sender_key)?;
        let balance_commitment = gadget::point_input(cs.clone(), self.balance_commitment)?;
        let balance_handle = gadget::point_input(cs.clone(), self.balance_handle)?;
        let amount = FpVar::new_input(cs.clone(), || {
            self.amount
                .map(Fr::from)
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let secret_bits = gadget::scalar_witness(cs.clone(), self.secret)?;
        let (balance, balance_bits) = gadget::amount_witness(cs.clone(), self.balance)?;
        let remaining_value = match (self.balance, self.amount) {
            (Some(b), Some(m)) => Some(b.checked_sub(m).ok_or(SynthesisError::Unsatisfiable)?),
            _ => None,
        };
        let (remaining, _) = gadget::amount_witness(cs, remaining_value)?;

        gadget::enforce_public_key(&secret_bits, &sender_key)?;
        gadget::enforce_balance(
            &secret_bits,
            &balance_commitment,
            &balance_handle,
            &balance_bits,
        )?;
        balance.enforce_equal(&(remaining + amount))
    }
}

pub fn setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::circuit_specific_setup(TokenUnwrapCircuit::default(), rng)
}

pub struct TokenUnwrapWitness {
    pub secret: SecretKey,
    pub balance: u64,
    pub available: Ciphertext,
    pub amount: u64,
}

/// Публичные входы в порядке схемы.
pub fn public_inputs(
    sender_key: &EdwardsAffine,
    available: &Ciphertext,
    amount: u64,
) -> [Fr; UNWRAP_NR_PUBLIC_INPUTS] {
    let [px, py] = point_inputs(sender_key);
    let [cx, cy] = point_inputs(&available.commitment);
    let [dx, dy] = point_inputs(&available.handle);
    [px, py, cx, cy, dx, dy, Fr::from(amount)]
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    w: &TokenUnwrapWitness,
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; UNWRAP_NR_PUBLIC_INPUTS]), SynthesisError> {
    let sender_key = w
        .secret
        .public_key()
        .map_err(|_| SynthesisError::Unsatisfiable)?
        .0;
    let circuit = TokenUnwrapCircuit {
        secret: Some(w.secret.0),
        balance: Some(w.balance),
        sender_key: Some(sender_key),
        balance_commitment: Some(w.available.commitment),
        balance_handle: Some(w.available.handle),
        amount: Some(w.amount),
    };
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok((proof, public_inputs(&sender_key, &w.available, w.amount)))
}

pub fn verify(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; UNWRAP_NR_PUBLIC_INPUTS],
) -> Result<bool, SynthesisError> {
    Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, public_inputs, proof)
}

pub fn prepare_vk(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    Groth16::<Bn254>::process_vk(vk).expect("process_vk")
}
