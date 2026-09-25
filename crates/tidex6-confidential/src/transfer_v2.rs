//! Перевод внутри пула v2 (ADR-022): одна нота владельца → две новые.
//!
//! Доказывает:
//!   1. входную ноту тратит её владелец (как в `withdraw_v2`)
//!   2. вход лежит в дереве, nf = H(H(D_NF, rho), pos)
//!   3. cm_out_i = H(H(core_out_i, amount_out_i), 0) — у нот, рождённых в пуле,
//!      возврата нет: вернуть их было бы некому, кроме владельца
//!   4. 0 ≤ суммы < 2^64, amount_in = amount_out1 + amount_out2
//!
//! Ядра выходов (`core_out_i`) считает переводящий под ключи получателей —
//! схема за них не отвечает: чужое ядро означает ноту, которую потратит
//! только её владелец.
//!
//! Публичные входы — те же четыре, что у v1:
//!   [merkle_root, nullifier, commitment_out1, commitment_out2]

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use tidex6_circuits::circom_qap::CircomReduction;

use crate::bytes::fr_from_u64;
use crate::note_v2::{self, core_var, leaf_var, nullifier_var, owner_pk_var, position_var};
use crate::transfer::TRANSFER_NR_PUBLIC_INPUTS;
use crate::withdraw::{POOL_TREE_DEPTH, enforce_u64_range};
use crate::withdraw_v2::{enforce_membership, path_witness};

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
    // выходы
    pub core_out1: Option<Fr>,
    pub amount_out1: Option<Fr>,
    pub core_out2: Option<Fr>,
    pub amount_out2: Option<Fr>,
    // публичные входы
    pub merkle_root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub commitment_out1: Option<Fr>,
    pub commitment_out2: Option<Fr>,
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
        let core_out1 = witness(self.core_out1)?;
        let amount_out1 = witness(self.amount_out1)?;
        let core_out2 = witness(self.core_out2)?;
        let amount_out2 = witness(self.amount_out2)?;

        // ── Публичные входы (порядок load-bearing) ───────────────────
        let merkle_root = input(self.merkle_root)?;
        let nullifier = input(self.nullifier)?;
        let commitment_out1 = input(self.commitment_out1)?;
        let commitment_out2 = input(self.commitment_out2)?;

        // 1–2. Вход тратит владелец, вход в дереве, nullifier от позиции.
        let owner_pk = owner_pk_var(cs.clone(), &sk)?;
        let core_in = core_var(cs.clone(), &owner_pk, &rho_in, &aux_in)?;
        let leaf_in = leaf_var(cs.clone(), &core_in, &amount_in, &refund_in)?;
        enforce_membership(cs.clone(), leaf_in, &siblings, &bits, &merkle_root)?;
        let pos = position_var(&bits);
        nullifier_var(cs.clone(), &rho_in, &pos)?.enforce_equal(&nullifier)?;

        // 3. Выходы — без возврата.
        let no_refund = FpVar::<Fr>::zero();
        leaf_var(cs.clone(), &core_out1, &amount_out1, &no_refund)?
            .enforce_equal(&commitment_out1)?;
        leaf_var(cs.clone(), &core_out2, &amount_out2, &no_refund)?
            .enforce_equal(&commitment_out2)?;

        // 4. Диапазоны и сохранение: из ноты не выходит больше, чем в ней было.
        enforce_u64_range(cs.clone(), self.amount_in, &amount_in)?;
        enforce_u64_range(cs.clone(), self.amount_out1, &amount_out1)?;
        enforce_u64_range(cs.clone(), self.amount_out2, &amount_out2)?;
        (&amount_out1 + &amount_out2).enforce_equal(&amount_in)?;
        Ok(())
    }
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
    pub core_out1: Fr,
    pub amount_out1: u64,
    pub core_out2: Fr,
    pub amount_out2: u64,
    pub merkle_root: Fr,
}

/// Локальный dev trusted setup (прод — церемония).
pub fn setup<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Groth16::<Bn254>::circuit_specific_setup(TransferV2Circuit::default(), rng)
}

/// Доказательство ключом из `setup`.
pub fn prove<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    w: &TransferV2Witness,
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; TRANSFER_NR_PUBLIC_INPUTS]), SynthesisError> {
    let (circuit, public_inputs) = circuit_and_inputs(w);
    Ok((Groth16::<Bn254>::prove(pk, circuit, rng)?, public_inputs))
}

/// Доказательство ключом церемонии.
pub fn prove_ceremony<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    w: &TransferV2Witness,
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; TRANSFER_NR_PUBLIC_INPUTS]), SynthesisError> {
    let (circuit, public_inputs) = circuit_and_inputs(w);
    Ok((
        Groth16::<Bn254, CircomReduction>::prove(pk, circuit, rng)?,
        public_inputs,
    ))
}

fn circuit_and_inputs(
    w: &TransferV2Witness,
) -> (TransferV2Circuit, [Fr; TRANSFER_NR_PUBLIC_INPUTS]) {
    let position = w
        .path_indices
        .iter()
        .enumerate()
        .fold(0u64, |acc, (i, bit)| acc | (u64::from(*bit) << i));
    let nf = note_v2::nullifier(w.rho_in, position);
    let cm1 = note_v2::leaf(note_v2::body(w.core_out1, w.amount_out1), Fr::from(0u64));
    let cm2 = note_v2::leaf(note_v2::body(w.core_out2, w.amount_out2), Fr::from(0u64));
    let circuit = TransferV2Circuit {
        sk_spend: Some(w.sk_spend),
        rho_in: Some(w.rho_in),
        aux_in: Some(w.aux_in),
        amount_in: Some(fr_from_u64(w.amount_in)),
        refund_in: Some(w.refund_in),
        path_siblings: Some(w.path_siblings),
        path_indices: Some(w.path_indices),
        core_out1: Some(w.core_out1),
        amount_out1: Some(fr_from_u64(w.amount_out1)),
        core_out2: Some(w.core_out2),
        amount_out2: Some(fr_from_u64(w.amount_out2)),
        merkle_root: Some(w.merkle_root),
        nullifier: Some(nf),
        commitment_out1: Some(cm1),
        commitment_out2: Some(cm2),
    };
    (circuit, [w.merkle_root, nf, cm1, cm2])
}

pub fn verify(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; TRANSFER_NR_PUBLIC_INPUTS],
) -> Result<bool, SynthesisError> {
    Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, public_inputs, proof)
}
