//! Вывод ноты v2 (ADR-022): потратить может только владелец ключа.
//!
//! Доказывает:
//!   1. owner_pk = H(D_OWNER, sk)                          — тратит владелец
//!   2. cm = H(H(core, amount), refund), core из owner_pk, rho, aux
//!   3. cm лежит в дереве с корнем merkle_root              (membership)
//!   4. nf = H(H(D_NF, rho), pos), pos — позиция листа      (анти-double-spend)
//!   5. 0 ≤ amount < 2^64, amount = amount_public
//!   6. recipient/relayer/relayer_fee связаны в proof       (ADR-011)
//!
//! Метка возврата `refund` — свидетель как есть: владельцу не нужно знать,
//! кто и когда мог бы забрать ноту назад, ему нужен только лист целиком.
//!
//! Публичные входы — те же восемь и в том же порядке, что у v1:
//!   [merkle_root, nullifier, recipient_hi, recipient_lo,
//!    relayer_hi, relayer_lo, relayer_fee, amount_public]

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::select::CondSelectGadget;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use tidex6_circuits::circom_qap::CircomReduction;
use tidex6_circuits::poseidon_gadget::poseidon_hash_pair_var;

use crate::bytes::{fr_from_u64, split_pubkey};
use crate::note_v2::{self, core_var, leaf_var, nullifier_var, owner_pk_var, position_var};
use crate::withdraw::{POOL_TREE_DEPTH, WITHDRAW_NR_PUBLIC_INPUTS, enforce_u64_range};

/// Свидетели + публичные входы. `None` на setup.
#[derive(Clone, Default)]
pub struct WithdrawV2Circuit {
    // приватные свидетели
    pub sk_spend: Option<Fr>,
    pub rho: Option<Fr>,
    pub aux: Option<Fr>,
    pub amount: Option<Fr>,
    pub refund: Option<Fr>,
    pub path_siblings: Option<[Fr; POOL_TREE_DEPTH]>,
    pub path_indices: Option<[bool; POOL_TREE_DEPTH]>,
    // публичные входы
    pub merkle_root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub recipient_hi: Option<Fr>,
    pub recipient_lo: Option<Fr>,
    pub relayer_hi: Option<Fr>,
    pub relayer_lo: Option<Fr>,
    pub relayer_fee: Option<Fr>,
    pub amount_public: Option<Fr>,
}

impl ConstraintSynthesizer<Fr> for WithdrawV2Circuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let missing = || SynthesisError::AssignmentMissing;
        let witness =
            |v: Option<Fr>| FpVar::<Fr>::new_witness(cs.clone(), || v.ok_or_else(missing));
        let input = |v: Option<Fr>| FpVar::<Fr>::new_input(cs.clone(), || v.ok_or_else(missing));

        // ── Приватные свидетели ──────────────────────────────────────
        let sk = witness(self.sk_spend)?;
        let rho = witness(self.rho)?;
        let aux = witness(self.aux)?;
        let amount = witness(self.amount)?;
        let refund = witness(self.refund)?;
        let (siblings, bits) = path_witness(cs.clone(), self.path_siblings, self.path_indices)?;

        // ── Публичные входы (порядок load-bearing) ───────────────────
        let merkle_root = input(self.merkle_root)?;
        let nullifier = input(self.nullifier)?;
        let recipient_hi = input(self.recipient_hi)?;
        let recipient_lo = input(self.recipient_lo)?;
        let relayer_hi = input(self.relayer_hi)?;
        let relayer_lo = input(self.relayer_lo)?;
        let relayer_fee = input(self.relayer_fee)?;
        let amount_public = input(self.amount_public)?;

        // 1–2. Лист, собранный из ключа владельца.
        let owner_pk = owner_pk_var(cs.clone(), &sk)?;
        let core = core_var(cs.clone(), &owner_pk, &rho, &aux)?;
        let leaf = leaf_var(cs.clone(), &core, &amount, &refund)?;

        // 3. Лист в дереве.
        enforce_membership(cs.clone(), leaf, &siblings, &bits, &merkle_root)?;

        // 4. Nullifier от позиции, которую назначил пул.
        let pos = position_var(&bits);
        nullifier_var(cs.clone(), &rho, &pos)?.enforce_equal(&nullifier)?;

        // 5. Сумма в диапазоне и равна публичной.
        enforce_u64_range(cs.clone(), self.amount, &amount)?;
        amount.enforce_equal(&amount_public)?;

        // 6. Получатель, релеер и комиссия затянуты в систему: подмена любого
        //    инвалидирует доказательство.
        for bound in [
            &recipient_hi,
            &recipient_lo,
            &relayer_hi,
            &relayer_lo,
            &relayer_fee,
        ] {
            let _ = bound * bound;
        }
        Ok(())
    }
}

/// Соседи и биты направления пути — снизу вверх.
pub(crate) type PathVars = (Vec<FpVar<Fr>>, Vec<Boolean<Fr>>);

/// Свидетели пути по дереву: соседи и биты направления снизу вверх.
pub(crate) fn path_witness(
    cs: ConstraintSystemRef<Fr>,
    siblings: Option<[Fr; POOL_TREE_DEPTH]>,
    indices: Option<[bool; POOL_TREE_DEPTH]>,
) -> Result<PathVars, SynthesisError> {
    let missing = || SynthesisError::AssignmentMissing;
    let mut sibling_vars = Vec::with_capacity(POOL_TREE_DEPTH);
    let mut bit_vars = Vec::with_capacity(POOL_TREE_DEPTH);
    for level in 0..POOL_TREE_DEPTH {
        sibling_vars.push(FpVar::<Fr>::new_witness(cs.clone(), || {
            siblings.ok_or_else(missing).map(|s| s[level])
        })?);
        bit_vars.push(Boolean::<Fr>::new_witness(cs.clone(), || {
            indices.ok_or_else(missing).map(|b| b[level])
        })?);
    }
    Ok((sibling_vars, bit_vars))
}

/// Пройти от листа к корню и потребовать совпадения с `root`.
pub(crate) fn enforce_membership(
    cs: ConstraintSystemRef<Fr>,
    leaf: FpVar<Fr>,
    siblings: &[FpVar<Fr>],
    bits: &[Boolean<Fr>],
    root: &FpVar<Fr>,
) -> Result<(), SynthesisError> {
    let mut current = leaf;
    for (sibling, bit) in siblings.iter().zip(bits) {
        let left = FpVar::conditionally_select(bit, sibling, &current)?;
        let right = FpVar::conditionally_select(bit, &current, sibling)?;
        current = poseidon_hash_pair_var(cs.clone(), &left, &right)?;
    }
    current.enforce_equal(root)
}

/// Свидетель вывода.
pub struct WithdrawV2Witness {
    pub sk_spend: Fr,
    pub rho: Fr,
    pub aux: Fr,
    pub amount: u64,
    /// Метка возврата листа, `0` — нота без возврата.
    pub refund: Fr,
    pub path_siblings: [Fr; POOL_TREE_DEPTH],
    pub path_indices: [bool; POOL_TREE_DEPTH],
    pub merkle_root: Fr,
    /// 32-байтный получатель (адрес EVM дополнен нулями слева).
    pub recipient: [u8; 32],
    pub relayer: [u8; 32],
    pub relayer_fee: u64,
}

impl WithdrawV2Witness {
    /// Позиция листа — из битов пути.
    pub fn position(&self) -> u64 {
        self.path_indices
            .iter()
            .enumerate()
            .fold(0u64, |acc, (i, bit)| acc | (u64::from(*bit) << i))
    }
}

/// Доказательство ключом церемонии (раскладка snarkjs, см. `withdraw::prove_ceremony`).
pub fn prove_ceremony<R: RngCore + CryptoRng>(
    pk: &ProvingKey<Bn254>,
    w: &WithdrawV2Witness,
    rng: &mut R,
) -> Result<(Proof<Bn254>, [Fr; WITHDRAW_NR_PUBLIC_INPUTS]), SynthesisError> {
    let (circuit, public_inputs) = circuit_and_inputs(w);
    Ok((
        Groth16::<Bn254, CircomReduction>::prove(pk, circuit, rng)?,
        public_inputs,
    ))
}

fn circuit_and_inputs(
    w: &WithdrawV2Witness,
) -> (WithdrawV2Circuit, [Fr; WITHDRAW_NR_PUBLIC_INPUTS]) {
    let amount = fr_from_u64(w.amount);
    let nf = note_v2::nullifier(w.rho, w.position());
    let (recipient_hi, recipient_lo) = split_pubkey(&w.recipient);
    let (relayer_hi, relayer_lo) = split_pubkey(&w.relayer);
    let relayer_fee = fr_from_u64(w.relayer_fee);
    let circuit = WithdrawV2Circuit {
        sk_spend: Some(w.sk_spend),
        rho: Some(w.rho),
        aux: Some(w.aux),
        amount: Some(amount),
        refund: Some(w.refund),
        path_siblings: Some(w.path_siblings),
        path_indices: Some(w.path_indices),
        merkle_root: Some(w.merkle_root),
        nullifier: Some(nf),
        recipient_hi: Some(recipient_hi),
        recipient_lo: Some(recipient_lo),
        relayer_hi: Some(relayer_hi),
        relayer_lo: Some(relayer_lo),
        relayer_fee: Some(relayer_fee),
        amount_public: Some(amount),
    };
    let public_inputs = [
        w.merkle_root,
        nf,
        recipient_hi,
        recipient_lo,
        relayer_hi,
        relayer_lo,
        relayer_fee,
        amount,
    ];
    (circuit, public_inputs)
}

pub fn verify(
    prepared_vk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    public_inputs: &[Fr; WITHDRAW_NR_PUBLIC_INPUTS],
) -> Result<bool, SynthesisError> {
    Groth16::<Bn254>::verify_with_processed_vk(prepared_vk, public_inputs, proof)
}
