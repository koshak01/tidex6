//! Проба: заставляем CT-крипто-стек скомпилироваться под wasm32.
//! ElGamal (curve25519 encrypt) + тип из proof-generation (тянет Bulletproofs,
//! merlin, curve25519-dalek). Если этот крейт собирается для wasm32 — CT-пруфы
//! в браузере feasible.

use solana_zk_sdk::encryption::elgamal::ElGamalKeypair;
use spl_token_confidential_transfer_proof_generation::transfer::TransferProofData;

/// Прогоняет реальную ElGamal-операцию (curve25519) + ссылается на
/// proof-generation тип, чтобы весь стек попал в сборку.
pub fn probe() -> usize {
    let kp = ElGamalKeypair::new_rand();
    let ct = kp.pubkey().encrypt(42u64);
    let _force_proof_gen = std::mem::size_of::<TransferProofData>();
    ct.to_bytes().len()
}
