//! Rust-native самопроверка церемониального zkey (Путь A) — используется
//! координатором вклада на сервере (без Node).
//!
//! `selftest_zkey` читает snarkjs zkey нашим парсером, строит валидный
//! withdraw-witness, прувит с `CircomReduction` и верифицирует. Если проходит —
//! zkey функционально корректен (задаёт рабочий Groth16-setup нашей схемы),
//! и возвращается его `VerifyingKey` (для сравнения delta / извлечения VK).

use std::fs;
use std::io::{Read, Seek};
use std::path::PathBuf;

use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use thiserror::Error;

use crate::circom_qap::CircomReduction;
use crate::solana_bytes::Groth16SolanaBytes;
use crate::withdraw::{WithdrawCircuit, WITHDRAW_TREE_DEPTH};
use crate::zkey::{read_zkey_pk, ZkeyError};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

const DEPTH: usize = WITHDRAW_TREE_DEPTH;

#[derive(Error, Debug)]
pub enum SelftestError {
    #[error("zkey parse: {0}")]
    Zkey(#[from] ZkeyError),
    #[error("core: {0}")]
    Core(String),
    #[error("prove: {0}")]
    Prove(String),
    #[error("verify: {0}")]
    Verify(String),
    #[error("proof rejected — zkey does not encode a working withdraw setup")]
    Rejected,
}

/// Прочитать zkey + доказать, что он задаёт рабочий Groth16-setup нашей схемы.
/// Возвращает `VerifyingKey` при успехе.
///
/// `seed` фиксирует RNG прувера — это ЛИШЬ функциональный self-test (не
/// production-proof), zero-knowledge здесь не требуется.
pub fn selftest_zkey<R: Read + Seek>(reader: &mut R, seed: u64) -> Result<VerifyingKey<Bn254>, SelftestError> {
    let pk = read_zkey_pk(reader)?;
    selftest_pk(&pk, seed)
}

/// Как [`selftest_zkey`], но принимает уже распарсенный `ProvingKey` (например,
/// после MPC-вклада, когда pk в памяти, а не в zkey-байтах).
pub fn selftest_pk(
    pk: &ark_groth16::ProvingKey<Bn254>,
    seed: u64,
) -> Result<VerifyingKey<Bn254>, SelftestError> {
    // Валидный depth-20 withdraw-witness.
    let secret = Secret::random().map_err(|e| SelftestError::Core(e.to_string()))?;
    let nullifier = Nullifier::random().map_err(|e| SelftestError::Core(e.to_string()))?;
    let commitment =
        Commitment::derive(&secret, &nullifier).map_err(|e| SelftestError::Core(e.to_string()))?;
    let nullifier_hash = nullifier
        .derive_hash()
        .map_err(|e| SelftestError::Core(e.to_string()))?;
    let mut tree = MerkleTree::new(DEPTH).map_err(|e| SelftestError::Core(e.to_string()))?;
    tree.insert(commitment).map_err(|e| SelftestError::Core(e.to_string()))?;
    let merkle_proof = tree.proof(0).map_err(|e| SelftestError::Core(e.to_string()))?;
    let merkle_root = tree.root();

    let recipient_bytes = [0x11u8; 32];
    let relayer_bytes = [0x42u8; 32];

    let secret_fr = Fr::from_be_bytes_mod_order(secret.as_bytes());
    let nullifier_fr = Fr::from_be_bytes_mod_order(nullifier.as_bytes());
    let merkle_root_fr = Fr::from_be_bytes_mod_order(merkle_root.as_bytes());
    let nullifier_hash_fr = Fr::from_be_bytes_mod_order(nullifier_hash.as_bytes());
    let recipient_fr = Fr::from_be_bytes_mod_order(&recipient_bytes);
    let relayer_fr = Fr::from_be_bytes_mod_order(&relayer_bytes);
    let fee_fr = Fr::from(0u64);

    let mut siblings = [Fr::from(0u64); DEPTH];
    for (slot, sib) in siblings.iter_mut().zip(merkle_proof.siblings.iter()) {
        *slot = Fr::from_be_bytes_mod_order(sib.as_bytes());
    }
    let mut path_indices = [false; DEPTH];
    for (i, bit) in path_indices.iter_mut().enumerate() {
        *bit = (merkle_proof.leaf_index >> i) & 1 == 1;
    }

    let circuit = WithdrawCircuit::<DEPTH> {
        secret: Some(secret_fr),
        nullifier: Some(nullifier_fr),
        path_siblings: Some(siblings),
        path_indices: Some(path_indices),
        merkle_root: Some(merkle_root_fr),
        nullifier_hash: Some(nullifier_hash_fr),
        recipient: Some(recipient_fr),
        relayer_address: Some(relayer_fr),
        relayer_fee: Some(fee_fr),
    };

    let mut rng = StdRng::seed_from_u64(seed);
    let proof = Groth16::<Bn254, CircomReduction>::prove(&pk, circuit, &mut rng)
        .map_err(|e| SelftestError::Prove(e.to_string()))?;

    let public = [merkle_root_fr, nullifier_hash_fr, recipient_fr, relayer_fr, fee_fr];
    let ok = Groth16::<Bn254>::verify(&pk.vk, &public, &proof)
        .map_err(|e| SelftestError::Verify(e.to_string()))?;
    if !ok {
        return Err(SelftestError::Rejected);
    }
    Ok(pk.vk.clone())
}

// ──────────────────────────────────────────────────────────────────────────
// VK → withdraw_vk.rs rendering (shared by gen_withdraw_vk + ceremony extract)
// ──────────────────────────────────────────────────────────────────────────

/// Отрендерить исходник `programs/tidex6-verifier/src/withdraw_vk.rs` из
/// solana-байтов VK. `header` — верхний doc-комментарий файла (у dev-генератора
/// и у церемонии он разный: single-contributor vs multi-party). Вывод байт-
/// детерминирован от входа — любой, кто скачал финальный `CeremonyState`,
/// воспроизводит идентичный файл.
pub fn render_vk_source(bytes: &Groth16SolanaBytes, header: &str) -> String {
    let nr_public = bytes.vk_ic.len() - 1;

    let mut out = String::new();
    out.push_str(header);
    out.push_str("\nuse groth16_solana::groth16::Groth16Verifyingkey;\n\n");

    out.push_str(&format!(
        "/// Number of public inputs the withdraw circuit exposes.\n\
         pub const WITHDRAW_NR_PUBLIC_INPUTS: usize = {nr_public};\n\n"
    ));

    out.push_str(&format!(
        "#[allow(clippy::type_complexity)]\n\
         static WITHDRAW_VK_IC: [[u8; 64]; {}] = [\n",
        bytes.vk_ic.len()
    ));
    for point in &bytes.vk_ic {
        out.push_str(&render_byte_array(point));
        out.push_str(",\n");
    }
    out.push_str("];\n\n");

    out.push_str("static WITHDRAW_VK_ALPHA_G1: [u8; 64] = ");
    out.push_str(&render_byte_array(&bytes.vk_alpha_g1));
    out.push_str(";\n\n");

    out.push_str("static WITHDRAW_VK_BETA_G2: [u8; 128] = ");
    out.push_str(&render_byte_array(&bytes.vk_beta_g2));
    out.push_str(";\n\n");

    out.push_str("static WITHDRAW_VK_GAMMA_G2: [u8; 128] = ");
    out.push_str(&render_byte_array(&bytes.vk_gamma_g2));
    out.push_str(";\n\n");

    out.push_str("static WITHDRAW_VK_DELTA_G2: [u8; 128] = ");
    out.push_str(&render_byte_array(&bytes.vk_delta_g2));
    out.push_str(";\n\n");

    out.push_str(
        "/// The hardcoded `WithdrawCircuit<20>` verifying key. Loaded\n\
         /// by `tidex6-verifier` at link time and used by every\n\
         /// `withdraw` instruction. Regenerate via the ceremony VK-extract\n\
         /// tool (`ceremony_extract_vk`) or `gen_withdraw_vk` (dev).\n\
         pub const WITHDRAW_VERIFYING_KEY: Groth16Verifyingkey = Groth16Verifyingkey {\n",
    );
    out.push_str(&format!("    nr_pubinputs: {nr_public},\n"));
    out.push_str("    vk_alpha_g1: WITHDRAW_VK_ALPHA_G1,\n");
    out.push_str("    vk_beta_g2:  WITHDRAW_VK_BETA_G2,\n");
    out.push_str("    vk_gamme_g2: WITHDRAW_VK_GAMMA_G2,\n");
    out.push_str("    vk_delta_g2: WITHDRAW_VK_DELTA_G2,\n");
    out.push_str("    vk_ic:       &WITHDRAW_VK_IC,\n");
    out.push_str("};\n");

    out
}

/// Отрендерить байты как Rust-массив-литерал, перенос каждые 12 байт.
fn render_byte_array(bytes: &[u8]) -> String {
    let mut out = String::from("[\n");
    for (i, byte) in bytes.iter().enumerate() {
        if i % 12 == 0 {
            out.push_str("    ");
        }
        out.push_str(&format!("0x{byte:02x}, "));
        if i % 12 == 11 {
            out.push('\n');
        }
    }
    if bytes.len() % 12 != 0 {
        out.push('\n');
    }
    out.push(']');
    out
}

/// Найти корень workspace (папка с `[workspace]` в Cargo.toml), поднимаясь от
/// `CARGO_MANIFEST_DIR` — чтобы VK-генераторы работали из любого cwd.
pub fn find_workspace_root() -> PathBuf {
    let start = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut current = start.clone();
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.exists() {
            let text = fs::read_to_string(&candidate).unwrap_or_default();
            if text.contains("[workspace]") {
                return current;
            }
        }
        match current.parent() {
            Some(parent) => current = parent.to_path_buf(),
            None => panic!(
                "could not find workspace root starting from {}",
                start.display()
            ),
        }
    }
}
