//! Схема корректности ключа: `s·P == H`.
//!
//! Нужна при регистрации ключа в контракте токена. Точка, принятая без
//! доказательства, могла бы лежать вне подгруппы простого порядка, и ручка
//! `r·P` на такую точку сливала бы младшие биты открытия. Проверять
//! принадлежность подгруппе в контракте дорого (умножение на порядок), а
//! доказательство стоит одну проверку Groth16.
//!
//! Публичные входы: `[P.x, P.y]`.

use ark_bn254::{Bn254, Fr};
use ark_ed_on_bn254::{EdwardsAffine, Fr as BjjFr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use super::elgamal::{point_inputs, PublicKey, SecretKey};
use super::gadget;

pub const PUBKEY_NR_PUBLIC_INPUTS: usize = 2;

#[derive(Clone, Default)]
pub struct PubkeyValidityCircuit {
    pub secret: Option<BjjFr>,
    pub public_key: Option<EdwardsAffine>,
}

impl ConstraintSynthesizer<Fr> for PubkeyValidityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let public_key = gadget::point_input(cs.clone(), self.public_key)?;
        let secret_bits = gadget::scalar_witness(cs, self.secret)?;
        gadget::enforce_public_key(&secret_bits, &public_key)
    }
}

pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::circuit_specific_setup(PubkeyValidityCircuit::default(), rng)
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    secret: &SecretKey,
    public_key: &PublicKey,
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; PUBKEY_NR_PUBLIC_INPUTS]), SynthesisError> {
    let circuit = PubkeyValidityCircuit {
        secret: Some(secret.0),
        public_key: Some(public_key.0),
    };
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok((proof, point_inputs(&public_key.0)))
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
