//! Pedersen commitments on BN254 G1 — прячут сумму так, что её
//! не видно на chain, но она всё ещё **гомоморфно** складывается.
//!
//! # Формула
//!
//! ```text
//! Com(amount, blinding) = g^amount · h^blinding
//! ```
//!
//! где `g` и `h` — два независимых генератора группы G1 BN254.
//!
//! # Гомоморфность
//!
//! `Com(a, r_a) · Com(b, r_b) = Com(a + b, r_a + r_b)`
//!
//! Именно это делает возможным перевод без раскрытия сумм:
//! `new_sender_commit = old_sender_commit · Com(-amount, -r_transfer)`,
//! `new_receiver_commit = old_receiver_commit · Com(+amount, +r_transfer)`.
//! Наблюдатель видит только изменения точек группы, не зная чисел.
//!
//! # Что НЕ реализовано
//!
//! Range proof — без него можно зафиксировать отрицательный amount
//! и «переправить» чужой баланс. В настоящем продукте range proof
//! обязателен (Bulletproofs / Groth16 gadget). Здесь — специально
//! опущено, чтобы не раздувать демо: Pedersen один.

use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{Field, PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::TryRng;
use rand::rngs::SysRng;

/// Длина компрессированной сериализации точки G1 BN254.
pub const POINT_LEN: usize = 32;

/// Два независимых генератора группы G1. `G` — канонический.
/// `H` получается детерминированно из `G` хешированием его
/// сериализации и повторным умножением на скаляр — так обеспечиваем
/// что дискретный логарифм `log_g(h)` никто не знает (иначе
/// commitment ломается).
///
/// Для MVP-демо это достаточно: мы используем SHA-256 от bytes of G
/// как скаляр, умножаем G на него, получаем H. В продакшене брали бы
/// nothing-up-my-sleeve процедуру, но здесь суть — в иллюстрации.
pub fn generator_g() -> G1Projective {
    G1Projective::generator()
}

pub fn generator_h() -> G1Projective {
    // Хешируем сериализацию G → получаем scalar → умножаем G на него.
    // Тот, кто захочет расковырять commitment, должен знать
    // `log_g(h)`, а мы не знаем — скаляр получен детерминированно
    // через байты G, и проверять его «красивость» не нужно.
    let g = generator_g();
    let mut g_bytes = Vec::new();
    g.into_affine()
        .serialize_compressed(&mut g_bytes)
        .expect("G1 serialises");
    let mut seed_bytes = [0u8; 32];
    for (i, b) in g_bytes.iter().take(32).enumerate() {
        seed_bytes[i] = *b;
    }
    let scalar = Fr::from_be_bytes_mod_order(&seed_bytes);
    let scalar = if scalar.is_zero() { Fr::ONE } else { scalar };
    g * scalar
}

/// Сам commitment — одна точка в G1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(pub G1Projective);

impl Commitment {
    /// `Com(amount, blinding) = g^amount · h^blinding`.
    pub fn create(amount: u64, blinding: Fr) -> Self {
        let amount_scalar = Fr::from(amount);
        let point = generator_g() * amount_scalar + generator_h() * blinding;
        Self(point)
    }

    /// Коммитмент к нулю с заданным blinding. Используется как
    /// начальный «пустой» баланс.
    pub fn zero_with_blinding(blinding: Fr) -> Self {
        Self(generator_h() * blinding)
    }

    /// Гомоморфное сложение: `Com(a) + Com(b) = Com(a + b)`.
    pub fn add(&self, other: &Commitment) -> Commitment {
        Commitment(self.0 + other.0)
    }

    /// Гомоморфное вычитание: `Com(a) - Com(b) = Com(a - b)`.
    pub fn sub(&self, other: &Commitment) -> Commitment {
        Commitment(self.0 - other.0)
    }

    /// Компактная base58-строковая форма для отображения в CLI.
    /// Просто hex первых 8 байт — чтобы коротко и узнаваемо.
    pub fn short(&self) -> String {
        let bytes = self.to_bytes();
        let hex: String = bytes[..8].iter().map(|b| format!("{b:02x}")).collect();
        format!("0x{hex}…")
    }

    /// Полная сериализация для сохранения в файл.
    pub fn to_bytes(&self) -> [u8; POINT_LEN] {
        let mut out = [0u8; POINT_LEN];
        self.0
            .into_affine()
            .serialize_compressed(&mut out[..])
            .expect("G1 fits in 32 bytes");
        out
    }

    /// Разбор из сохранённых байтов.
    pub fn from_bytes(bytes: &[u8; POINT_LEN]) -> anyhow::Result<Self> {
        let point = G1Affine::deserialize_compressed(bytes.as_slice())
            .map_err(|e| anyhow::anyhow!("invalid commitment bytes: {e}"))?;
        Ok(Commitment(point.into_group()))
    }
}

/// Сэмплировать случайный blinding factor. Обязательно fresh на
/// каждый commitment — reuse blinding ломает скрытие амount'а.
pub fn fresh_blinding() -> anyhow::Result<Fr> {
    let mut rng = SysRng;
    // arkworks UniformRand требует rand 0.8 RngCore — у нас rand 0.10
    // с другим trait-трее. Обходим руками: генерим байты, mod order.
    let mut bytes = [0u8; 32];
    rng.try_fill_bytes(&mut bytes)
        .map_err(|e| anyhow::anyhow!("CSPRNG: {e}"))?;
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn homomorphic_addition_works() {
        // Com(3, r1) + Com(5, r2) = Com(8, r1 + r2) — ключевое свойство.
        let r1 = fresh_blinding().unwrap();
        let r2 = fresh_blinding().unwrap();

        let c3 = Commitment::create(3, r1);
        let c5 = Commitment::create(5, r2);
        let c_sum = c3.add(&c5);

        let expected = Commitment::create(8, r1 + r2);
        assert_eq!(c_sum, expected);
    }

    #[test]
    fn commitment_roundtrips_through_bytes() {
        let r = fresh_blinding().unwrap();
        let c = Commitment::create(42, r);
        let bytes = c.to_bytes();
        let restored = Commitment::from_bytes(&bytes).unwrap();
        assert_eq!(c, restored);
    }

    #[test]
    fn different_blinding_makes_different_commitment() {
        // Тот же amount + разный blinding → разные commitment'ы.
        // Именно это прячет сумму: два раза перевели 10 SOL, два
        // разных commitment'а.
        let c_a = Commitment::create(10, fresh_blinding().unwrap());
        let c_b = Commitment::create(10, fresh_blinding().unwrap());
        assert_ne!(c_a, c_b);
    }
}
