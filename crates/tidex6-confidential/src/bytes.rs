//! Кодирование field-элементов и разбиение pubkey для exact binding.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

/// 32-байтное big-endian представление `Fr` (с левым нуль-паддингом).
///
/// Байт-эквивалентно тому, что кладёт `tidex6_core::poseidon` на входе и
/// возвращает on-chain-верификатор в публичных входах.
pub fn fr_to_be_bytes(value: Fr) -> [u8; 32] {
    let mut bytes = value.into_bigint().to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.append(&mut bytes);
        bytes = padded;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[bytes.len() - 32..]);
    out
}

/// Кодирует `u64` (сумма/комиссия в base-units) в `Fr` — младшие 64 бита.
///
/// Range-проруф в схеме гарантирует `0 ≤ amount < 2^64`, поэтому обратного
/// переполнения поля не происходит.
pub fn fr_from_u64(value: u64) -> Fr {
    Fr::from(value)
}

/// Разбивает 32-байтный pubkey на два field-элемента `(hi, lo)` по 16 байт.
///
/// Фикс GAP2: mainnet-верификатор связывает получателя как
/// `reduce_mod_bn254(pubkey)` — lossy остаток по модулю ~254-битного поля,
/// из-за чего `reduce(P) == reduce(P + n·modulus)` и злой релеер может
/// подменить адрес выплаты на коллизию, сохранив валидность proof.
///
/// Здесь связывается **полный** 256-битный ключ двумя половинами по 128 бит.
/// Каждая половина заведомо меньше модуля BN254 (≈2^254) → инъективно, без
/// коллизий: `hi = ключ[0..16]`, `lo = ключ[16..32]` (big-endian).
pub fn split_pubkey(pubkey: &[u8; 32]) -> (Fr, Fr) {
    let hi = Fr::from_be_bytes_mod_order(&pubkey[0..16]);
    let lo = Fr::from_be_bytes_mod_order(&pubkey[16..32]);
    (hi, lo)
}
