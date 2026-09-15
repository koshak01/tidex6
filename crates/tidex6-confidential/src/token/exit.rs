//! Схема вывода из пула на конфиденциальный баланс получателя.
//!
//! Граница «пул → токен» без числа: нота гасится, а получателю на pending
//! ложится шифротекст `(C_m, D_r)` на его ключ. Никакой публичной суммы —
//! в отличие от `crate::withdraw`, где выплата в открытый ERC-20 обязана
//! назвать число. Получатель читает сумму из конверта.
//!
//! Публичные входы: `[merkle_root, nullifier_hash, P_r.x, P_r.y, C_m.x, C_m.y,
//! D_r.x, D_r.y]` — 8.

use ark_bn254::{Bn254, Fr};
use ark_ed_on_bn254::{EdwardsAffine, Fr as BjjFr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};

use super::elgamal::{self, point_inputs, Ciphertext, PublicKey};
use super::gadget;
use crate::withdraw::POOL_TREE_DEPTH;

pub const EXIT_NR_PUBLIC_INPUTS: usize = 8;

#[derive(Clone, Default)]
pub struct WithdrawToTokenCircuit {
    // приватные свидетели
    pub note_secret: Option<Fr>,
    pub note_nullifier: Option<Fr>,
    pub amount: Option<u64>,
    pub path_siblings: Option<[Fr; POOL_TREE_DEPTH]>,
    pub path_indices: Option<[bool; POOL_TREE_DEPTH]>,
    pub opening: Option<BjjFr>,
    // публичные входы
    pub merkle_root: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub recipient_key: Option<EdwardsAffine>,
    pub amount_commitment: Option<EdwardsAffine>,
    pub recipient_handle: Option<EdwardsAffine>,
}

impl ConstraintSynthesizer<Fr> for WithdrawToTokenCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;
        let merkle_root = FpVar::new_input(cs.clone(), || self.merkle_root.ok_or_else(missing))?;
        let nullifier_hash = FpVar::new_input(cs.clone(), || self.nullifier_hash.ok_or_else(missing))?;
        let recipient_key = gadget::point_input(cs.clone(), self.recipient_key)?;
        let amount_commitment = gadget::point_input(cs.clone(), self.amount_commitment)?;
        let recipient_handle = gadget::point_input(cs.clone(), self.recipient_handle)?;

        let note_secret = FpVar::new_witness(cs.clone(), || self.note_secret.ok_or_else(missing))?;
        let note_nullifier = FpVar::new_witness(cs.clone(), || self.note_nullifier.ok_or_else(missing))?;
        let (amount, amount_bits) = gadget::amount_witness(cs.clone(), self.amount)?;
        let (siblings, index_bits) = gadget::merkle_witness(cs.clone(), self.path_siblings, self.path_indices)?;
        let opening_bits = gadget::scalar_witness(cs.clone(), self.opening)?;

        let leaf = gadget::note_commitment(cs.clone(), &note_secret, &note_nullifier, &amount)?;
        gadget::nullifier_hash(cs.clone(), &note_nullifier)?.enforce_equal(&nullifier_hash)?;
        gadget::merkle_root(cs, leaf, &siblings, &index_bits)?.enforce_equal(&merkle_root)?;
        gadget::commitment(&amount_bits, &opening_bits)?.enforce_equal(&amount_commitment)?;
        gadget::mul(&recipient_key, &opening_bits)?.enforce_equal(&recipient_handle)
    }
}

pub fn setup<R: RngCore + CryptoRng>(rng: &mut R) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::circuit_specific_setup(WithdrawToTokenCircuit::default(), rng)
}

pub struct WithdrawToTokenWitness {
    pub note_secret: Fr,
    pub note_nullifier: Fr,
    pub amount: u64,
    pub path_siblings: [Fr; POOL_TREE_DEPTH],
    pub path_indices: [bool; POOL_TREE_DEPTH],
    pub merkle_root: Fr,
    pub opening: BjjFr,
    pub recipient: PublicKey,
}

pub struct WithdrawToTokenPublic {
    pub merkle_root: Fr,
    pub nullifier_hash: Fr,
    pub recipient_key: EdwardsAffine,
    /// Шифротекст `(C_m, D_r)`, который контракт кладёт получателю в pending.
    pub credited: Ciphertext,
}

impl WithdrawToTokenPublic {
    pub fn inputs(&self) -> [Fr; EXIT_NR_PUBLIC_INPUTS] {
        let [px, py] = point_inputs(&self.recipient_key);
        let [cx, cy] = point_inputs(&self.credited.commitment);
        let [dx, dy] = point_inputs(&self.credited.handle);
        [self.merkle_root, self.nullifier_hash, px, py, cx, cy, dx, dy]
    }
}

pub fn public_part(w: &WithdrawToTokenWitness) -> WithdrawToTokenPublic {
    WithdrawToTokenPublic {
        merkle_root: w.merkle_root,
        nullifier_hash: crate::withdraw::nullifier_hash(w.note_nullifier),
        recipient_key: w.recipient.0,
        credited: elgamal::encrypt(&w.recipient, w.amount, w.opening),
    }
}

pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    w: &WithdrawToTokenWitness,
    rng: &mut R,
) -> Result<(Proof<Bn254>, WithdrawToTokenPublic), SynthesisError> {
    let public = public_part(w);
    let circuit = WithdrawToTokenCircuit {
        note_secret: Some(w.note_secret),
        note_nullifier: Some(w.note_nullifier),
        amount: Some(w.amount),
        path_siblings: Some(w.path_siblings),
        path_indices: Some(w.path_indices),
        opening: Some(w.opening),
        merkle_root: Some(public.merkle_root),
        nullifier_hash: Some(public.nullifier_hash),
        recipient_key: Some(public.recipient_key),
        amount_commitment: Some(public.credited.commitment),
        recipient_handle: Some(public.credited.handle),
    };
    let proof = Groth16::<Bn254>::prove(pk, circuit, rng)?;
    Ok((proof, public))
}

pub fn verify(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; EXIT_NR_PUBLIC_INPUTS],
) -> Result<bool, SynthesisError> {
    Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, public_inputs, proof)
}

pub fn prepare_vk(vk: &VerifyingKey<Bn254>) -> PreparedVerifyingKey<Bn254> {
    Groth16::<Bn254>::process_vk(vk).expect("process_vk")
}
