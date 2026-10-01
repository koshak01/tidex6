//! Схема вывода из пула v2 на конфиденциальный баланс получателя (ADR-023).
//!
//! Граница «пул → токен» без числа: нота v2 гасится её владельцем, а
//! получателю на pending ложится шифротекст `(C_m, D_r)` на его ключ. В
//! отличие от `withdraw_v2`, где выплата в открытый ERC-20 обязана назвать
//! число, здесь его нет. Получатель читает сумму из конверта.
//!
//! Доказывает то же, что `withdraw_v2` для ноты, и вместо публичной суммы:
//!   1. owner_pk = H(D_OWNER, sk) — тратит владелец;
//!   2. лист H(H(core, amount), refund) лежит в дереве с корнем `merkle_root`;
//!   3. nf = H(H(D_NF, rho), pos) — один на оба пути траты ноты;
//!   4. 0 ≤ amount < 2^64;
//!   5. `C_m = amount·G + r·H`, `D_r = r·P_r` — та же сумма зашифрована
//!      получателю.
//!
//! Куда зачислить, контракт решает по `P_r`: ключ зарегистрирован за счётом
//! получателя, подменить его без нового доказательства нельзя.
//!
//! Публичные входы: `[merkle_root, nullifier, P_r.x, P_r.y, C_m.x, C_m.y,
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

use super::elgamal::{self, Ciphertext, PublicKey, point_inputs};
use super::gadget;
use crate::note_v2::{self, core_var, leaf_var, nullifier_var, owner_pk_var, position_var};
use crate::withdraw::POOL_TREE_DEPTH;
use crate::withdraw_v2::{enforce_membership, path_witness};

pub const EXIT_NR_PUBLIC_INPUTS: usize = 8;

#[derive(Clone, Default)]
pub struct WithdrawToTokenCircuit {
    // приватные свидетели
    pub sk_spend: Option<Fr>,
    pub rho: Option<Fr>,
    pub aux: Option<Fr>,
    pub amount: Option<u64>,
    pub refund: Option<Fr>,
    pub path_siblings: Option<[Fr; POOL_TREE_DEPTH]>,
    pub path_indices: Option<[bool; POOL_TREE_DEPTH]>,
    pub opening: Option<BjjFr>,
    // публичные входы
    pub merkle_root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub recipient_key: Option<EdwardsAffine>,
    pub amount_commitment: Option<EdwardsAffine>,
    pub recipient_handle: Option<EdwardsAffine>,
}

impl ConstraintSynthesizer<Fr> for WithdrawToTokenCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;
        let witness =
            |v: Option<Fr>| FpVar::<Fr>::new_witness(cs.clone(), || v.ok_or_else(missing));

        // ── Публичные входы (порядок load-bearing) ───────────────────
        let merkle_root = FpVar::new_input(cs.clone(), || self.merkle_root.ok_or_else(missing))?;
        let nullifier = FpVar::new_input(cs.clone(), || self.nullifier.ok_or_else(missing))?;
        let recipient_key = gadget::point_input(cs.clone(), self.recipient_key)?;
        let amount_commitment = gadget::point_input(cs.clone(), self.amount_commitment)?;
        let recipient_handle = gadget::point_input(cs.clone(), self.recipient_handle)?;

        // ── Свидетели ────────────────────────────────────────────────
        let sk = witness(self.sk_spend)?;
        let rho = witness(self.rho)?;
        let aux = witness(self.aux)?;
        let refund = witness(self.refund)?;
        let (amount, amount_bits) = gadget::amount_witness(cs.clone(), self.amount)?;
        let (siblings, bits) = path_witness(cs.clone(), self.path_siblings, self.path_indices)?;
        let opening_bits = gadget::scalar_witness(cs.clone(), self.opening)?;

        // 1–2. Лист владельца в дереве.
        let owner_pk = owner_pk_var(cs.clone(), &sk)?;
        let core = core_var(cs.clone(), &owner_pk, &rho, &aux)?;
        let leaf = leaf_var(cs.clone(), &core, &amount, &refund)?;
        enforce_membership(cs.clone(), leaf, &siblings, &bits, &merkle_root)?;

        // 3. Nullifier от позиции, которую назначил пул.
        nullifier_var(cs, &rho, &position_var(&bits))?.enforce_equal(&nullifier)?;

        // 4–5. Та же сумма — получателю шифротекстом.
        gadget::commitment(&amount_bits, &opening_bits)?.enforce_equal(&amount_commitment)?;
        gadget::mul(&recipient_key, &opening_bits)?.enforce_equal(&recipient_handle)
    }
}

pub fn setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::circuit_specific_setup(WithdrawToTokenCircuit::default(), rng)
}

pub struct WithdrawToTokenWitness {
    pub sk_spend: Fr,
    pub rho: Fr,
    pub aux: Fr,
    pub amount: u64,
    /// Метка возврата листа, `0` — нота без возврата.
    pub refund: Fr,
    pub path_siblings: [Fr; POOL_TREE_DEPTH],
    pub path_indices: [bool; POOL_TREE_DEPTH],
    pub merkle_root: Fr,
    pub opening: BjjFr,
    pub recipient: PublicKey,
}

impl WithdrawToTokenWitness {
    /// Позиция листа — из битов пути.
    pub fn position(&self) -> u64 {
        self.path_indices
            .iter()
            .enumerate()
            .fold(0u64, |acc, (i, bit)| acc | (u64::from(*bit) << i))
    }
}

pub struct WithdrawToTokenPublic {
    pub merkle_root: Fr,
    pub nullifier: Fr,
    pub recipient_key: EdwardsAffine,
    /// Шифротекст `(C_m, D_r)`, который контракт кладёт получателю в pending.
    pub credited: Ciphertext,
}

impl WithdrawToTokenPublic {
    pub fn inputs(&self) -> [Fr; EXIT_NR_PUBLIC_INPUTS] {
        let [px, py] = point_inputs(&self.recipient_key);
        let [cx, cy] = point_inputs(&self.credited.commitment);
        let [dx, dy] = point_inputs(&self.credited.handle);
        [self.merkle_root, self.nullifier, px, py, cx, cy, dx, dy]
    }
}

pub fn public_part(w: &WithdrawToTokenWitness) -> WithdrawToTokenPublic {
    WithdrawToTokenPublic {
        merkle_root: w.merkle_root,
        nullifier: note_v2::nullifier(w.rho, w.position()),
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
        sk_spend: Some(w.sk_spend),
        rho: Some(w.rho),
        aux: Some(w.aux),
        amount: Some(w.amount),
        refund: Some(w.refund),
        path_siblings: Some(w.path_siblings),
        path_indices: Some(w.path_indices),
        opening: Some(w.opening),
        merkle_root: Some(public.merkle_root),
        nullifier: Some(public.nullifier),
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
