//! Импорт церемониального Groth16 VK/proof из snarkjs JSON обратно в arkworks —
//! закрывает петлю ceremony → on-chain верификатор (Путь A).
//!
//! Берёт `vk.json` + `proof.json` + `public.json` (экспорт snarkjs после
//! `zkey contribute`), конвертирует точки (decimal, affine) в arkworks
//! `VerifyingKey`/`Proof`, верифицирует НАШИМ путём (arkworks Groth16) и
//! прогоняет `groth16_to_solana_bytes` — тот самый байт-layout, что ест
//! on-chain `groth16-solana` верификатор. Если verify проходит —
//! церемониальный VK готов драйвить наш верификатор.
//!
//! Запуск: cargo run -p tidex6-circuits --bin import_vk
//! Выход:  crates/tidex6-circuits/artifacts/withdraw_vk_ceremony.json (solana байты)

use std::str::FromStr;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_groth16::{Proof, VerifyingKey};
use serde_json::Value;
use tidex6_circuits::solana_bytes::groth16_to_solana_bytes;
use tidex6_circuits::withdraw::{prepare_verifying_key, verify_withdraw_proof};

fn main() {
    let dir = format!("{}/work/rust/tidex6/_ceremony", std::env::var("HOME").unwrap());
    let vk_json: Value = read_json(&format!("{dir}/vk.json"));
    let proof_json: Value = read_json(&format!("{dir}/proof.json"));
    let public_json: Value = read_json(&format!("{dir}/public.json"));

    // ── VK ─────────────────────────────────────────────────────────────
    let ic: Vec<G1Affine> = vk_json["IC"]
        .as_array()
        .expect("IC")
        .iter()
        .map(g1)
        .collect();
    println!("VK: nPublic={}, IC points={}", vk_json["nPublic"], ic.len());

    let vk = VerifyingKey::<Bn254> {
        alpha_g1: g1(&vk_json["vk_alpha_1"]),
        beta_g2: g2(&vk_json["vk_beta_2"]),
        gamma_g2: g2(&vk_json["vk_gamma_2"]),
        delta_g2: g2(&vk_json["vk_delta_2"]),
        gamma_abc_g1: ic,
    };

    // ── Proof ──────────────────────────────────────────────────────────
    let proof = Proof::<Bn254> {
        a: g1(&proof_json["pi_a"]),
        b: g2(&proof_json["pi_b"]),
        c: g1(&proof_json["pi_c"]),
    };

    // ── Public inputs (5) ──────────────────────────────────────────────
    let publics: Vec<Fr> = public_json
        .as_array()
        .expect("public array")
        .iter()
        .map(|v| Fr::from_str(v.as_str().unwrap()).expect("Fr"))
        .collect();
    assert_eq!(publics.len(), 5, "expected 5 public inputs");
    let public_arr: [Fr; 5] = [publics[0], publics[1], publics[2], publics[3], publics[4]];

    // ── ГЕЙТ: верификация НАШИМ путём (arkworks) ───────────────────────
    let pvk = prepare_verifying_key(&vk);
    let ok = verify_withdraw_proof(&pvk, &proof, &public_arr).expect("verify");
    println!("arkworks verify (ceremony vk + ceremony proof): {}", if ok { "OK" } else { "FAIL" });
    assert!(ok, "ceremony proof must verify under arkworks with the converted VK");

    // ── groth16-solana байты VK (для on-chain верификатора) ────────────
    let sb = groth16_to_solana_bytes(&proof, &vk).expect("solana bytes");
    println!("solana VK: alpha_g1={}B beta_g2={}B gamma_g2={}B delta_g2={}B ic={}×64B",
        sb.vk_alpha_g1.len(), sb.vk_beta_g2.len(), sb.vk_gamma_g2.len(),
        sb.vk_delta_g2.len(), sb.vk_ic.len());

    // Сохранить VK-байты как JSON (hex) — источник для верификатора.
    let out = serde_json::json!({
        "vk_alpha_g1": hex(&sb.vk_alpha_g1),
        "vk_beta_g2": hex(&sb.vk_beta_g2),
        "vk_gamma_g2": hex(&sb.vk_gamma_g2),
        "vk_delta_g2": hex(&sb.vk_delta_g2),
        "vk_ic": sb.vk_ic.iter().map(|p| hex(p)).collect::<Vec<_>>(),
        "nr_pubinputs": sb.vk_ic.len(),
    });
    let path = format!("{dir}/../crates/tidex6-circuits/artifacts/withdraw_vk_ceremony.json");
    std::fs::write(&path, serde_json::to_string_pretty(&out).unwrap()).expect("write vk");
    println!("wrote {path}");
    println!("\nПЕТЛЯ ЗАКРЫТА: церемониальный VK верифицирует наш proof и конвертируется в solana-байты.");
}

fn read_json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect(path)).expect("parse json")
}

fn fq(v: &Value) -> Fq {
    Fq::from_str(v.as_str().expect("fq str")).expect("Fq parse")
}

/// snarkjs G1: [x, y, "1"] (decimal, affine).
fn g1(v: &Value) -> G1Affine {
    let a = v.as_array().expect("g1 array");
    G1Affine::new_unchecked(fq(&a[0]), fq(&a[1]))
}

/// snarkjs G2: [[x_c0, x_c1], [y_c0, y_c1], ["1","0"]]. Fq2 = c0 + c1·u.
fn g2(v: &Value) -> G2Affine {
    let a = v.as_array().expect("g2 array");
    let x = a[0].as_array().expect("g2 x");
    let y = a[1].as_array().expect("g2 y");
    G2Affine::new_unchecked(
        Fq2::new(fq(&x[0]), fq(&x[1])),
        Fq2::new(fq(&y[0]), fq(&y[1])),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
