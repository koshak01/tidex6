//! Проверка proof через ON-CHAIN путь (`groth16-solana`).
//!
//! Конвертирует arkworks proof + VK в байтовую раскладку `groth16-solana` и
//! проверяет тем же крейтом и тем же `alt_bn128`-путём, что крутит верификатор
//! на mainnet. Off-chain прогон байт-в-байт совпадает с on-chain — способ
//! убедиться, что схему примет on-chain верификатор, ничего не деплоя.

use ark_bn254::Bn254;
use ark_groth16::{Proof, VerifyingKey};
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};
use tidex6_circuits::solana_bytes::groth16_to_solana_bytes;

/// Проверяет proof через `groth16-solana` (on-chain-совместимо) для схемы с
/// `N` публичными входами. Возвращает `true`, если on-chain верификатор
/// принял бы этот proof.
pub fn verify_onchain_compat<const N: usize>(
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
    public_inputs: &[[u8; 32]; N],
) -> bool {
    let bytes = match groth16_to_solana_bytes(proof, vk) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let vk_ic = bytes.vk_ic.clone();
    let groth_vk = Groth16Verifyingkey {
        nr_pubinputs: vk_ic.len(),
        vk_alpha_g1: bytes.vk_alpha_g1,
        vk_beta_g2: bytes.vk_beta_g2,
        vk_gamme_g2: bytes.vk_gamma_g2,
        vk_delta_g2: bytes.vk_delta_g2,
        vk_ic: &vk_ic,
    };
    let mut verifier = match Groth16Verifier::<N>::new(
        &bytes.proof_a,
        &bytes.proof_b,
        &bytes.proof_c,
        public_inputs,
        &groth_vk,
    ) {
        Ok(v) => v,
        Err(_) => return false,
    };
    verifier.verify().is_ok()
}
