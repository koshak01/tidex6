//! Схема корректности ключа: `s·P == H`.
//!
//! Нужна при регистрации ключа в контракте токена. Точка, принятая без
//! доказательства, могла бы лежать вне подгруппы простого порядка, и ручка
//! `r·P` на такую точку сливала бы младшие биты открытия. Проверять
//! принадлежность подгруппе в контракте дорого (умножение на порядок), а
//! доказательство стоит одну проверку Groth16.
//!
//! Доказательство привязано к адресу, который регистрирует ключ: без этого
//! чужой мог бы скопировать доказательство из мемпула и первым записать ключ
//! за собой. Ключ выводится из подписи кошелька детерминированно, сменить его
//! владелец не может — перехват навсегда отрезал бы его от собственного ключа.
//!
//! Публичные входы: `[P.x, P.y, owner_hi, owner_lo]` — адрес как 32-байтное
//! слово (EVM-адрес дополнен нулями слева), две половины по 128 бит.

use ark_bn254::{Bn254, Fr};
use ark_ed_on_bn254::{EdwardsAffine, Fr as BjjFr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use super::elgamal::{PublicKey, SecretKey, point_inputs};
use super::gadget;
use crate::bytes::split_pubkey;

pub const PUBKEY_NR_PUBLIC_INPUTS: usize = 4;

#[derive(Clone, Default)]
pub struct PubkeyValidityCircuit {
    pub secret: Option<BjjFr>,
    pub public_key: Option<EdwardsAffine>,
    pub owner_hi: Option<Fr>,
    pub owner_lo: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for PubkeyValidityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;
        let public_key = gadget::point_input(cs.clone(), self.public_key)?;
        let owner_hi = FpVar::new_input(cs.clone(), || self.owner_hi.ok_or_else(missing))?;
        let owner_lo = FpVar::new_input(cs.clone(), || self.owner_lo.ok_or_else(missing))?;
        let secret_bits = gadget::scalar_witness(cs, self.secret)?;
        gadget::enforce_public_key(&secret_bits, &public_key)?;
        // Владелец затянут в систему: другой адрес — другое доказательство.
        for bound in [&owner_hi, &owner_lo] {
            let _ = bound * bound;
        }
        Ok(())
    }
}

pub fn setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::circuit_specific_setup(PubkeyValidityCircuit::default(), rng)
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    secret: &SecretKey,
    public_key: &PublicKey,
    owner: &[u8; 32],
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; PUBKEY_NR_PUBLIC_INPUTS]), SynthesisError> {
    let (owner_hi, owner_lo) = split_pubkey(owner);
    let circuit = PubkeyValidityCircuit {
        secret: Some(secret.0),
        public_key: Some(public_key.0),
        owner_hi: Some(owner_hi),
        owner_lo: Some(owner_lo),
    };
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    let [x, y] = point_inputs(&public_key.0);
    Ok((proof, [x, y, owner_hi, owner_lo]))
}

pub fn verify(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; PUBKEY_NR_PUBLIC_INPUTS],
) -> Result<bool, SynthesisError> {
    Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, public_inputs, proof)
}

pub fn prepare_vk(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    Groth16::<Bn254>::process_vk(vk).expect("process_vk")
}
