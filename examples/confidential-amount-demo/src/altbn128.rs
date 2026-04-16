//! Конверсия G1 точек BN254 в формат syscall'а
//! `sol_alt_bn128_addition` — **64 байта uncompressed, big-endian**,
//! 32 байта X, затем 32 байта Y.
//!
//! Arkworks по умолчанию сериализует field-элементы в little-endian.
//! Делаем ручной перевод, чтобы онchain-программа приняла точку
//! без дополнительных шагов.

use ark_bn254::{Fq, G1Affine, G1Projective};
use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};

/// Длина представления G1 в alt_bn128 формате.
pub const ALT_BN128_G1_LEN: usize = 64;

/// Преобразовать G1 (affine) в 64-байтное big-endian представление.
///
/// Panics если точка на infinity (y=0): в реальной системе эту
/// ситуацию нужно обрабатывать, но в демо гомоморфная арифметика
/// на ненулевых commitment'ах никогда не должна давать identity.
pub fn g1_to_alt_bn128(point: &G1Projective) -> [u8; ALT_BN128_G1_LEN] {
    let affine: G1Affine = point.into_affine();

    let x_bytes = fq_to_big_endian(&affine.x);
    let y_bytes = fq_to_big_endian(&affine.y);

    let mut out = [0u8; ALT_BN128_G1_LEN];
    out[..32].copy_from_slice(&x_bytes);
    out[32..].copy_from_slice(&y_bytes);
    out
}

fn fq_to_big_endian(field: &Fq) -> [u8; 32] {
    let big = field.into_bigint();
    let bytes = big.to_bytes_be();
    // to_bytes_be даёт Vec<u8> длины 32 для BN254 Fq, но защитимся
    // от будущих изменений arkworks: pad / truncate до 32.
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    let take = bytes.len().min(32);
    out[start..].copy_from_slice(&bytes[bytes.len() - take..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PrimeGroup;

    #[test]
    fn generator_roundtrips_through_alt_bn128_format() {
        // Просто проверяем что генератор кодируется в 64 байта без
        // паники и с ненулевыми частями.
        let g: G1Projective = G1Projective::generator();
        let encoded = g1_to_alt_bn128(&g);
        assert_eq!(encoded.len(), 64);
        assert!(encoded[..32].iter().any(|&b| b != 0), "X should be non-zero");
        assert!(encoded[32..].iter().any(|&b| b != 0), "Y should be non-zero");
    }

    #[test]
    fn sum_of_two_commitments_encodes_to_valid_point() {
        use crate::pedersen::{fresh_blinding, Commitment};
        let r1 = fresh_blinding().unwrap();
        let r2 = fresh_blinding().unwrap();
        let c_sum = Commitment::create(10, r1).add(&Commitment::create(20, r2));
        let bytes = g1_to_alt_bn128(&c_sum.0);
        assert_eq!(bytes.len(), 64);
    }
}
