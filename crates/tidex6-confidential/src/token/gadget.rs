//! Гаджеты twisted ElGamal на Baby Jubjub для схем над BN254.
//!
//! Все скаляры входят в схему битами: скаляр Baby Jubjub живёт в другом поле,
//! и любое произведение скаляров внутри схемы было бы «чужой» арифметикой.
//! Битами же умножение точки на скаляр — обычное double-and-add, а проверки
//! вида `s·P == H` и `C − s·D == b·G` — сравнение точек.

use ark_bn254::Fr;
use ark_ed_on_bn254::constraints::EdwardsVar;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective, Fr as BjjFr};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::groups::CurveVar;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::elgamal::{amount_bits_le, generator_g, generator_h, scalar_bits_le, AMOUNT_BITS, SCALAR_BITS};

fn missing() -> SynthesisError {
    SynthesisError::AssignmentMissing
}

/// Точка как публичный вход: две координаты, `x` затем `y`, плюс проверка,
/// что пара лежит на кривой.
pub fn point_input(cs: ConstraintSystemRef<Fr>, point: Option<EdwardsAffine>) -> Result<EdwardsVar, SynthesisError> {
    EdwardsVar::new_input(cs, || point.map(EdwardsProjective::from).ok_or_else(missing))
}

/// Скаляр Baby Jubjub как [`SCALAR_BITS`] свидетельских бит, младший первым.
pub fn scalar_witness(cs: ConstraintSystemRef<Fr>, scalar: Option<BjjFr>) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let bits = scalar.map(|s| scalar_bits_le(&s));
    (0..SCALAR_BITS)
        .map(|i| Boolean::new_witness(cs.clone(), || bits.as_ref().map(|b| b[i]).ok_or_else(missing)))
        .collect()
}

/// Сумма как [`AMOUNT_BITS`] свидетельских бит и как элемент поля, равный
/// их сумме — одновременно диапазон `0 ≤ amount < 2^64` и число для
/// линейных проверок.
pub fn amount_witness(cs: ConstraintSystemRef<Fr>, amount: Option<u64>) -> Result<(FpVar<Fr>, Vec<Boolean<Fr>>), SynthesisError> {
    let bits = amount.map(amount_bits_le);
    let bit_vars: Vec<Boolean<Fr>> = (0..AMOUNT_BITS)
        .map(|i| Boolean::new_witness(cs.clone(), || bits.as_ref().map(|b| b[i]).ok_or_else(missing)))
        .collect::<Result<_, _>>()?;
    let value = Boolean::le_bits_to_fp(&bit_vars)?;
    Ok((value, bit_vars))
}

/// Генератор `G` как константа схемы.
pub fn constant_g() -> EdwardsVar {
    EdwardsVar::constant(EdwardsProjective::from(generator_g()))
}

/// Генератор `H` как константа схемы.
pub fn constant_h() -> EdwardsVar {
    EdwardsVar::constant(EdwardsProjective::from(generator_h()))
}

/// `bits · point`, биты младшим первым.
pub fn mul(point: &EdwardsVar, bits: &[Boolean<Fr>]) -> Result<EdwardsVar, SynthesisError> {
    point.scalar_mul_le(bits.iter())
}

/// Ключ корректен: `s·P == H`, то есть `P = s⁻¹·H` и лежит в подгруппе.
pub fn enforce_public_key(secret_bits: &[Boolean<Fr>], public_key: &EdwardsVar) -> Result<(), SynthesisError> {
    mul(public_key, secret_bits)?.enforce_equal(&constant_h())
}

/// Баланс расшифровывается в `balance`: `C − s·D == b·G`.
pub fn enforce_balance(
    secret_bits: &[Boolean<Fr>],
    commitment: &EdwardsVar,
    handle: &EdwardsVar,
    balance_bits: &[Boolean<Fr>],
) -> Result<(), SynthesisError> {
    let masked = mul(handle, secret_bits)?;
    let decrypted = commitment.clone() - masked;
    decrypted.enforce_equal(&mul(&constant_g(), balance_bits)?)
}

/// Коммитмент `m·G + r·H`.
pub fn commitment(amount_bits: &[Boolean<Fr>], opening_bits: &[Boolean<Fr>]) -> Result<EdwardsVar, SynthesisError> {
    Ok(mul(&constant_g(), amount_bits)? + mul(&constant_h(), opening_bits)?)
}
