//! Emit `contracts/src/PoseidonT3.sol` and `stylus/common/src/poseidon_consts.rs`
//! from the offchain Poseidon constants.
//!
//! The EVM pool must hash Merkle parents exactly as the Solana pool, the
//! circuit and the offchain client do. This writes the Solidity library and
//! prints a test vector so the Solidity side can be checked against Rust.
//!
//! Usage:
//!
//! ```text
//! cargo run --bin export_solidity_poseidon --release
//! ```

use std::fs;

use tidex6_circuits::ceremony::find_workspace_root;
use tidex6_circuits::evm_poseidon::{render_poseidon_t3, render_stylus_poseidon_consts};

fn main() {
    let source = render_poseidon_t3();

    let out_dir = find_workspace_root().join("contracts/src");
    fs::create_dir_all(&out_dir).expect("create contracts/src");
    let out_path = out_dir.join("PoseidonT3.sol");
    fs::write(&out_path, source.as_bytes()).expect("write PoseidonT3.sol");
    println!("wrote {} ({} bytes)", out_path.display(), source.len());

    // Same constants for the Stylus contracts, as Rust.
    let stylus_source = render_stylus_poseidon_consts();
    let stylus_dir = find_workspace_root().join("stylus/common/src");
    fs::create_dir_all(&stylus_dir).expect("create stylus/common/src");
    let stylus_path = stylus_dir.join("poseidon_consts.rs");
    fs::write(&stylus_path, stylus_source.as_bytes()).expect("write poseidon_consts.rs");
    println!(
        "wrote {} ({} bytes)",
        stylus_path.display(),
        stylus_source.len()
    );

    // Reference vector: the Solidity library must reproduce this exactly.
    let left = [0u8; 32];
    let mut right = [0u8; 32];
    right[31] = 1;
    let digest = tidex6_core::poseidon::hash_pair(&left, &right).expect("hash_pair");

    println!("\nreference vector (Rust, tidex6_core::poseidon::hash_pair):");
    println!("  left  = 0");
    println!("  right = 1");
    println!("  hash  = 0x{}", hex(&digest));
    println!("  hash  = {}", to_decimal(&digest));
}

/// Lowercase hex of a 32-byte digest.
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decimal string of a big-endian 32-byte value.
fn to_decimal(bytes: &[u8; 32]) -> String {
    let mut work = bytes.to_vec();
    let mut digits: Vec<u8> = Vec::new();
    while work.iter().any(|b| *b != 0) {
        let mut remainder = 0u16;
        for byte in work.iter_mut() {
            let current = (remainder << 8) | u16::from(*byte);
            *byte = (current / 10) as u8;
            remainder = current % 10;
        }
        digits.push(remainder as u8);
    }
    if digits.is_empty() {
        return "0".into();
    }
    digits.iter().rev().map(|d| (b'0' + d) as char).collect()
}
