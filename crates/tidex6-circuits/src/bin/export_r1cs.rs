//! Экспорт R1CS нашего `WithdrawCircuit<20>` в circom/iden3 `.r1cs` формат —
//! мост arkworks → snarkjs для церемонии (Путь A). Дальше snarkjs делает
//! `zkey new` (с ptau) → `contribute`, а финальный zkey импортируем обратно.
//!
//! Формат .r1cs (iden3 binfileutils, v1): magic "r1cs" + version + nSections,
//! затем секции Header / Constraints / Wire2Label.
//!
//! Запуск: cargo run -p tidex6-circuits --bin export_r1cs
//! Выход:  crates/tidex6-circuits/artifacts/withdraw.r1cs

use std::io::Write;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use tidex6_circuits::withdraw::{WithdrawCircuit, WITHDRAW_TREE_DEPTH};

fn main() {
    // Shape-схема (все входы None) в Setup-режиме → матрицы без witness.
    let circuit = WithdrawCircuit::<WITHDRAW_TREE_DEPTH> {
        secret: None,
        nullifier: None,
        path_siblings: None,
        path_indices: None,
        merkle_root: None,
        nullifier_hash: None,
        recipient: None,
        relayer_address: None,
        relayer_fee: None,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .expect("generate_constraints");
    cs.finalize();
    let m = cs.to_matrices().expect("to_matrices");

    let n_instance = m.num_instance_variables; // включает wire 0 = ONE
    let n_witness = m.num_witness_variables;
    let n_wires = (n_instance + n_witness) as u32;
    let n_pub_in = (n_instance - 1) as u32; // публичные входы (без ONE)
    let n_prv_in = n_witness as u32;
    let n_constraints = m.num_constraints as u32;

    println!("constraints: {n_constraints}");
    println!("wires:       {n_wires} (public {n_pub_in}, private {n_prv_in})");

    // ── Header (section 1) ────────────────────────────────────────────
    let mut header = Vec::new();
    header.extend_from_slice(&32u32.to_le_bytes()); // fieldSize
    let mut prime = Fr::MODULUS.to_bytes_le();
    prime.resize(32, 0);
    header.extend_from_slice(&prime); // prime (LE)
    header.extend_from_slice(&n_wires.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // nPubOut
    header.extend_from_slice(&n_pub_in.to_le_bytes());
    header.extend_from_slice(&n_prv_in.to_le_bytes());
    header.extend_from_slice(&(n_wires as u64).to_le_bytes()); // nLabels
    header.extend_from_slice(&n_constraints.to_le_bytes());

    // ── Constraints (section 2) ───────────────────────────────────────
    let mut constraints = Vec::new();
    for i in 0..m.num_constraints {
        write_lc(&mut constraints, &m.a[i]);
        write_lc(&mut constraints, &m.b[i]);
        write_lc(&mut constraints, &m.c[i]);
    }

    // ── Wire2Label map (section 3) ────────────────────────────────────
    let mut wire2label = Vec::new();
    for w in 0..n_wires as u64 {
        wire2label.extend_from_slice(&w.to_le_bytes());
    }

    // ── Собрать файл ──────────────────────────────────────────────────
    let mut out = Vec::new();
    out.extend_from_slice(b"r1cs");
    out.extend_from_slice(&1u32.to_le_bytes()); // version
    out.extend_from_slice(&3u32.to_le_bytes()); // nSections
    write_section(&mut out, 1, &header);
    write_section(&mut out, 2, &constraints);
    write_section(&mut out, 3, &wire2label);

    let home = std::env::var("HOME").unwrap();
    let path =
        format!("{home}/work/rust/tidex6/crates/tidex6-circuits/artifacts/withdraw.r1cs");
    let mut f = std::fs::File::create(&path).expect("create r1cs");
    f.write_all(&out).expect("write r1cs");
    println!("wrote {} ({} bytes)", path, out.len());
}

/// Линейная комбинация: nTerms + [(wireIdx u32, coeff 32-byte LE)].
fn write_lc(buf: &mut Vec<u8>, lc: &[(Fr, usize)]) {
    buf.extend_from_slice(&(lc.len() as u32).to_le_bytes());
    for (coeff, idx) in lc {
        buf.extend_from_slice(&(*idx as u32).to_le_bytes());
        let mut c = coeff.into_bigint().to_bytes_le();
        c.resize(32, 0);
        buf.extend_from_slice(&c);
    }
}

/// Секция: type (u32) + size (u64) + data.
fn write_section(out: &mut Vec<u8>, section_type: u32, data: &[u8]) {
    out.extend_from_slice(&section_type.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
}
