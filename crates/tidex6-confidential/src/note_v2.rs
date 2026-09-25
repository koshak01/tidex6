//! Нота v2 (ADR-022): сумма привязана пулом на входе, трата — ключом владельца.
//!
//! Всё собрано из двухвходового Poseidon: на EVM в контракте есть только он
//! (`PoseidonT3`), а возврат по истечении срока пересчитывает ноту на цепи.
//!
//! ```text
//! owner_pk = H(D_OWNER, sk_spend)
//! core     = H(H(D_CORE, owner_pk), H(rho, aux))
//! body     = H(core, amount)                    ← считает пул из полученной суммы
//! refund   = H(refund_addr, refund_after)  или 0 — «без возврата»
//! cm       = H(body, refund)                    ← лист дерева
//! nf       = H(H(D_NF, rho), pos)               ← один на оба пути траты
//! ```
//!
//! Функции ниже — для клиента и сверок; те же формулы в схемах задают
//! гаджеты `*_var` этого модуля, чтобы вне схемы и внутри неё не разошлось.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use tidex6_circuits::poseidon_gadget::poseidon_hash_pair_var;

use crate::bytes::{fr_from_u64, fr_to_be_bytes, split_pubkey};

/// Домены хеша: `"tidex6"` в старших байтах и номер назначения в младшем.
/// Разные назначения не могут дать совпадающий вход ни при каких данных.
pub const D_OWNER: u64 = 0x7469_6478_3601;
pub const D_CORE: u64 = 0x7469_6478_3602;
pub const D_NF: u64 = 0x7469_6478_3603;

/// Двухвходовый Poseidon вне схемы — байт в байт `poseidon_hash_pair_var`.
pub fn h2(a: Fr, b: Fr) -> Fr {
    let bytes = tidex6_core::poseidon::hash(&[&fr_to_be_bytes(a), &fr_to_be_bytes(b)])
        .expect("poseidon hash(2)");
    Fr::from_be_bytes_mod_order(&bytes)
}

/// Открытый ключ владельца из секрета траты.
pub fn owner_pk(sk_spend: Fr) -> Fr {
    h2(fr_from_u64(D_OWNER), sk_spend)
}

/// Ядро ноты: кому и какая случайность. Отправитель считает его сам и
/// передаёт пулу вместе с деньгами.
pub fn core(owner_pk: Fr, rho: Fr, aux: Fr) -> Fr {
    h2(h2(fr_from_u64(D_CORE), owner_pk), h2(rho, aux))
}

/// Тело ноты — ядро с суммой. Его считает пул из полученной суммы.
pub fn body(core: Fr, amount: u64) -> Fr {
    h2(core, fr_from_u64(amount))
}

/// Метка возврата: кто и с какого момента может забрать ноту назад.
pub fn refund_tag(refund_addr: Fr, refund_after: u64) -> Fr {
    h2(refund_addr, fr_from_u64(refund_after))
}

/// Лист дерева. `refund = 0` — нота без возврата (комиссия, выходы перевода).
pub fn leaf(body: Fr, refund: Fr) -> Fr {
    h2(body, refund)
}

/// Nullifier: один для обоих путей траты, различен для разных позиций.
pub fn nullifier(rho: Fr, pos: u64) -> Fr {
    h2(h2(fr_from_u64(D_NF), rho), fr_from_u64(pos))
}

/// Адрес возврата для EVM: 20 байт адреса как число (меньше порядка поля).
pub fn refund_addr_evm(address: [u8; 20]) -> Fr {
    Fr::from_be_bytes_mod_order(&address)
}

/// Адрес возврата для Solana: 32 байта ключа не влезают в поле без
/// редукции, поэтому — хеш двух половин, та же раскладка, что у получателя.
pub fn refund_addr_solana(pubkey: &[u8; 32]) -> Fr {
    let (hi, lo) = split_pubkey(pubkey);
    h2(hi, lo)
}

// ── Гаджеты: те же формулы внутри схемы ─────────────────────────────────

pub(crate) fn owner_pk_var(
    cs: ConstraintSystemRef<Fr>,
    sk: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    poseidon_hash_pair_var(cs, &FpVar::constant(fr_from_u64(D_OWNER)), sk)
}

pub(crate) fn core_var(
    cs: ConstraintSystemRef<Fr>,
    owner_pk: &FpVar<Fr>,
    rho: &FpVar<Fr>,
    aux: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let left = poseidon_hash_pair_var(cs.clone(), &FpVar::constant(fr_from_u64(D_CORE)), owner_pk)?;
    let right = poseidon_hash_pair_var(cs.clone(), rho, aux)?;
    poseidon_hash_pair_var(cs, &left, &right)
}

pub(crate) fn leaf_var(
    cs: ConstraintSystemRef<Fr>,
    core: &FpVar<Fr>,
    amount: &FpVar<Fr>,
    refund: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let body = poseidon_hash_pair_var(cs.clone(), core, amount)?;
    poseidon_hash_pair_var(cs, &body, refund)
}

/// Позиция листа из битов пути — пул назначил её при вставке, доказывающий
/// выбрать её не может: другие биты дают другой корень.
pub(crate) fn position_var(bits: &[Boolean<Fr>]) -> FpVar<Fr> {
    let mut acc = FpVar::<Fr>::zero();
    let mut coeff = Fr::from(1u64);
    for bit in bits {
        acc += FpVar::from(bit.clone()) * FpVar::constant(coeff);
        coeff += coeff;
    }
    acc
}

pub(crate) fn nullifier_var(
    cs: ConstraintSystemRef<Fr>,
    rho: &FpVar<Fr>,
    pos: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let tagged = poseidon_hash_pair_var(cs.clone(), &FpVar::constant(fr_from_u64(D_NF)), rho)?;
    poseidon_hash_pair_var(cs, &tagged, pos)
}
