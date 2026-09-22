//! Twisted ElGamal на Baby Jubjub — нативная сторона (клиент, тесты, экспорт
//! констант). Схемная сторона — [`super::gadget`], и обе обязаны считать
//! одно и то же: генераторы здесь, константы там берутся из этого модуля.

use std::collections::HashMap;
use std::sync::OnceLock;

use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bn254::{EdwardsAffine, EdwardsConfig, EdwardsProjective, Fq, Fr as BjjFr};
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use ark_std::UniformRand;
use ark_std::rand::{CryptoRng, RngCore};
use thiserror::Error;

/// Метка домена для вывода второго генератора `H`. Первый вход Poseidon.
const H_DOMAIN: &[u8] = b"tidex6/ct/H";

/// Сколько бит суммы допускает схема (тот же предел, что у нот пула).
pub const AMOUNT_BITS: usize = 64;

/// Сколько бит несёт скаляр Baby Jubjub: порядок подгруппы `l < 2^251`.
pub const SCALAR_BITS: usize = 251;

#[derive(Debug, Error)]
pub enum ElGamalError {
    #[error("secret key is zero — its public key would be undefined")]
    ZeroSecret,
    #[error("point is not in the prime-order subgroup")]
    NotInSubgroup,
    #[error("amount exceeds {AMOUNT_BITS} bits")]
    AmountTooLarge,
    #[error("no amount below 2^{0} decrypts to this point")]
    Undecodable(u32),
}

/// Генератор `G` — базовая точка Baby Jubjub из `ark-ed-on-bn254`.
pub fn generator_g() -> EdwardsAffine {
    EdwardsConfig::GENERATOR
}

/// Второй генератор `H` с неизвестным логарифмом по `G`.
///
/// Выводится детерминированно: `y_i = Poseidon(H_DOMAIN, i)` для `i = 0, 1, …`,
/// первая `y`, дающая точку на кривой, умножается на кофактор 8 — так точка
/// попадает в подгруппу простого порядка. Никто не выбирал `H` руками,
/// поэтому никто не знает `log_G H`; на этом стоит связывание коммитмента.
pub fn generator_h() -> EdwardsAffine {
    static H: OnceLock<EdwardsAffine> = OnceLock::new();
    *H.get_or_init(derive_h)
}

fn derive_h() -> EdwardsAffine {
    let mut domain = [0u8; 32];
    domain[32 - H_DOMAIN.len()..].copy_from_slice(H_DOMAIN);
    for counter in 0u64.. {
        let mut counter_bytes = [0u8; 32];
        counter_bytes[24..].copy_from_slice(&counter.to_be_bytes());
        let digest = tidex6_core::poseidon::hash(&[&domain, &counter_bytes])
            .expect("Poseidon over two field elements cannot fail");
        let y = Fq::from_be_bytes_mod_order(&digest);
        if let Some(point) = EdwardsAffine::get_point_from_y_unchecked(y, false) {
            let cleared = point.mul_by_cofactor();
            if !cleared.is_zero() {
                return cleared;
            }
        }
    }
    unreachable!("the search over counters terminates on the first valid point")
}

/// Секретный ключ расшифровки — скаляр Baby Jubjub.
#[derive(Clone)]
pub struct SecretKey(pub BjjFr);

/// Публичный ключ шифрования `P = s⁻¹·H`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(pub EdwardsAffine);

/// Шифротекст: коммитмент, общий для всех читателей, и одна ручка.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    /// `C = m·G + r·H`.
    pub commitment: EdwardsAffine,
    /// `D = r·P` для конкретного ключа.
    pub handle: EdwardsAffine,
}

impl SecretKey {
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        loop {
            let s = BjjFr::rand(rng);
            if !s.is_zero() {
                return Self(s);
            }
        }
    }

    /// `P = s⁻¹·H`.
    pub fn public_key(&self) -> Result<PublicKey, ElGamalError> {
        let inverse = self.0.inverse().ok_or(ElGamalError::ZeroSecret)?;
        Ok(PublicKey((generator_h() * inverse).into_affine()))
    }

    /// `C − s·D = m·G` — точка, кодирующая сумму.
    pub fn decrypt_point(&self, ciphertext: &Ciphertext) -> EdwardsAffine {
        let masked = EdwardsProjective::from(ciphertext.handle) * self.0;
        (EdwardsProjective::from(ciphertext.commitment) - masked).into_affine()
    }
}

impl PublicKey {
    /// Точка принимается только из подгруппы простого порядка: точка с
    /// компонентой малого порядка сливала бы младшие биты чужого ключа.
    pub fn from_affine(point: EdwardsAffine) -> Result<Self, ElGamalError> {
        if point.is_zero()
            || !point.is_on_curve()
            || !point.is_in_correct_subgroup_assuming_on_curve()
        {
            return Err(ElGamalError::NotInSubgroup);
        }
        Ok(Self(point))
    }

    /// Ручка `D = r·P`.
    pub fn handle(&self, opening: BjjFr) -> EdwardsAffine {
        (EdwardsProjective::from(self.0) * opening).into_affine()
    }
}

/// Коммитмент `C = m·G + r·H`.
pub fn commit(amount: u64, opening: BjjFr) -> EdwardsAffine {
    let m_g = EdwardsProjective::from(generator_g()) * BjjFr::from(amount);
    let r_h = EdwardsProjective::from(generator_h()) * opening;
    (m_g + r_h).into_affine()
}

/// Шифротекст суммы для одного читателя. Один коммитмент с несколькими
/// ручками собирается вызовом [`PublicKey::handle`] с тем же `opening`.
pub fn encrypt(recipient: &PublicKey, amount: u64, opening: BjjFr) -> Ciphertext {
    Ciphertext {
        commitment: commit(amount, opening),
        handle: recipient.handle(opening),
    }
}

/// Свежее открытие.
pub fn random_opening<R: RngCore + CryptoRng>(rng: &mut R) -> BjjFr {
    BjjFr::rand(rng)
}

/// Гомоморфное сложение шифротекстов под одним ключом — то, что делает
/// контракт с балансом.
pub fn add(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    Ciphertext {
        commitment: (EdwardsProjective::from(a.commitment) + b.commitment).into_affine(),
        handle: (EdwardsProjective::from(a.handle) + b.handle).into_affine(),
    }
}

/// Вычитание — списание с баланса.
pub fn sub(a: &Ciphertext, b: &Ciphertext) -> Ciphertext {
    Ciphertext {
        commitment: (EdwardsProjective::from(a.commitment) - b.commitment).into_affine(),
        handle: (EdwardsProjective::from(a.handle) - b.handle).into_affine(),
    }
}

/// Шифротекст открытой суммы: `(m·G, O)`, открытие ноль. Так контракт кладёт
/// на баланс то, что пришло из открытого ERC-20 (`wrap`), и списывает при
/// `unwrap` — без умножения на скаляр внутри контракта для ручки.
pub fn plain(amount: u64) -> Ciphertext {
    Ciphertext {
        commitment: (EdwardsProjective::from(generator_g()) * BjjFr::from(amount)).into_affine(),
        handle: EdwardsAffine::zero(),
    }
}

/// Проверить открытие коммитмента: `C == m·G + r·H`. Так получатель читает
/// сумму из конверта без дискретного логарифма.
pub fn opens_to(commitment: &EdwardsAffine, amount: u64, opening: BjjFr) -> bool {
    commit(amount, opening) == *commitment
}

/// Аварийная расшифровка: найти `m < 2^bits` такое, что `m·G == point`.
///
/// Baby-step giant-step: таблица из `2^(bits/2)` точек и столько же шагов
/// онлайн. Для 32 бит это 65 536 записей и доли секунды — тот же приём,
/// что у Token-2022 (`decode_u32`). Штатный путь — открытие из конверта.
pub fn decode_amount(point: &EdwardsAffine, bits: u32) -> Result<u64, ElGamalError> {
    let half = bits.div_ceil(2);
    let table_size: u64 = 1 << half;
    let g = EdwardsProjective::from(generator_g());
    // Baby steps: j·G для j < 2^half.
    let mut table: HashMap<[u8; 32], u64> = HashMap::with_capacity(table_size as usize);
    let mut step = EdwardsProjective::zero();
    for j in 0..table_size {
        table.insert(coords_key(&step.into_affine()), j);
        step += g;
    }
    // Giant steps: point − i·2^half·G.
    let giant = g * BjjFr::from(table_size);
    let mut current = EdwardsProjective::from(*point);
    for i in 0..table_size {
        if let Some(j) = table.get(&coords_key(&current.into_affine())) {
            return Ok(i * table_size + j);
        }
        current -= giant;
    }
    Err(ElGamalError::Undecodable(bits))
}

fn coords_key(point: &EdwardsAffine) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = point.x.into_bigint().to_bytes_be();
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

/// Скаляр Baby Jubjub как `SCALAR_BITS` бит, младший первым — раскладка, в
/// которой его берут схемы.
pub fn scalar_bits_le(scalar: &BjjFr) -> Vec<bool> {
    let mut bits = scalar.into_bigint().to_bits_le();
    bits.truncate(SCALAR_BITS);
    bits
}

/// Сумма как `AMOUNT_BITS` бит, младший первым.
pub fn amount_bits_le(amount: u64) -> [bool; AMOUNT_BITS] {
    std::array::from_fn(|i| (amount >> i) & 1 == 1)
}

/// Координаты точки как элементы поля схемы — в таком виде точка становится
/// публичным входом: сначала `x`, затем `y`.
pub fn point_inputs(point: &EdwardsAffine) -> [Fq; 2] {
    [point.x, point.y]
}
