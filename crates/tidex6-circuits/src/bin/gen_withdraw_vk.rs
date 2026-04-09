//! Generator for the production withdraw-circuit verifying key.
//!
//! Runs a single-contributor Groth16 Phase-2 setup for
//! `WithdrawCircuit<20>` with a fixed RNG seed, then writes:
//!
//! 1. `programs/tidex6-verifier/src/withdraw_vk.rs` — the
//!    `Groth16Verifyingkey` constant hardcoded into the onchain
//!    verifier program. The onchain verifier loads this once at
//!    link time and reuses it for every withdraw instruction.
//!
//! 2. `crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin` —
//!    the serialized `ProvingKey<Bn254>` used by the offchain
//!    prover (client, CLI, tests). Large (tens of MB) but only
//!    needed on the prover side, never onchain.
//!
//! **DEVELOPMENT ONLY.** Single-contributor means the toxic waste
//! existed on one machine (the machine running this binary).
//! Before mainnet, replace this with a multi-party Phase-2
//! ceremony. See `docs/release/security.md` section 1.4.
//!
//! Usage:
//!
//! ```text
//! cargo run --bin gen_withdraw_vk --release
//! ```

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use ark_serialize::CanonicalSerialize;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::withdraw::{WITHDRAW_TREE_DEPTH, setup_withdraw_circuit};

/// Fixed seed so regenerating the VK on a different machine
/// produces bit-identical output. Any change to the seed, the
/// circuit, the arkworks version, or the toolchain invalidates the
/// VK and requires a full redeploy of `tidex6-verifier`.
const SETUP_SEED: u64 = 0x7715_ef25_d061_3517;

fn main() {
    let workspace_root = find_workspace_root();
    let verifier_output_path = workspace_root.join("programs/tidex6-verifier/src/withdraw_vk.rs");
    let pk_output_path = workspace_root.join(
        "crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin",
    );

    println!("Generating WithdrawCircuit<{WITHDRAW_TREE_DEPTH}> verifying key...");
    println!("  seed            = 0x{SETUP_SEED:016x}");
    println!("  vk output       = {}", verifier_output_path.display());
    println!("  pk output       = {}", pk_output_path.display());

    let mut rng = StdRng::seed_from_u64(SETUP_SEED);
    let (pk, vk) = setup_withdraw_circuit::<WITHDRAW_TREE_DEPTH, _>(&mut rng)
        .expect("setup_withdraw_circuit must succeed");

    // ── Convert VK to groth16-solana byte layout ─────────────────
    // We need a dummy `Proof<Bn254>` to reuse `groth16_to_solana_bytes`,
    // but we only care about the VK portion of the output. Build a
    // proof that is never verified by synthesising an obvious
    // witness — wait, no: we can just call the helper and discard
    // the proof fields. Instead of fabricating a proof, split the
    // helper: serialize VK fields manually via the same helpers.
    // Simplest path: reuse the same module via a proof from
    // `test_proof_placeholder`. But there is no public placeholder,
    // so we import the conversion directly.
    //
    // `groth16_to_solana_bytes` takes a proof argument to negate
    // `proof_a`. We only need VK fields, so we synthesise a proof
    // from the VK itself just to satisfy the type — the proof
    // bytes in the returned struct are discarded.
    let dummy_proof = ark_groth16::Proof::<ark_bn254::Bn254> {
        a: vk.alpha_g1,
        b: vk.beta_g2,
        c: vk.alpha_g1,
    };
    let bytes: Groth16SolanaBytes =
        groth16_to_solana_bytes(&dummy_proof, &vk).expect("groth16_to_solana_bytes");

    println!("  vk_ic length    = {}", bytes.vk_ic.len());
    println!("  nr_public_input = {}", bytes.vk_ic.len() - 1);

    // ── Emit the verifier .rs file ───────────────────────────────
    let source = render_vk_rust_source(&bytes);
    if let Some(parent) = verifier_output_path.parent() {
        fs::create_dir_all(parent).expect("create verifier src dir");
    }
    fs::write(&verifier_output_path, source).expect("write verifier vk file");
    println!("Wrote {}", verifier_output_path.display());

    // ── Serialize the proving key to an artifact file ────────────
    let mut pk_bytes: Vec<u8> = Vec::new();
    pk.serialize_uncompressed(&mut pk_bytes)
        .expect("serialize proving key");
    if let Some(parent) = pk_output_path.parent() {
        fs::create_dir_all(parent).expect("create artifacts dir");
    }
    let mut file = fs::File::create(&pk_output_path).expect("create pk file");
    file.write_all(&pk_bytes).expect("write pk bytes");
    println!(
        "Wrote {} ({} bytes)",
        pk_output_path.display(),
        pk_bytes.len()
    );

    println!("Done.");
}

/// Render the `withdraw_vk.rs` source file as a UTF-8 string.
fn render_vk_rust_source(bytes: &Groth16SolanaBytes) -> String {
    let nr_public = bytes.vk_ic.len() - 1;

    let mut out = String::new();
    out.push_str(HEADER_COMMENT);
    out.push_str("\nuse groth16_solana::groth16::Groth16Verifyingkey;\n\n");

    out.push_str(&format!(
        "/// Number of public inputs the withdraw circuit exposes.\n\
         pub const WITHDRAW_NR_PUBLIC_INPUTS: usize = {nr_public};\n\n"
    ));

    // VK IC as a sized static array.
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

    // Individual G1/G2 fields.
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

    // The Groth16Verifyingkey constant itself.
    out.push_str(
        "/// The hardcoded `WithdrawCircuit<20>` verifying key. Loaded\n\
         /// by `tidex6-verifier` at link time and used by every\n\
         /// `withdraw` instruction. Regenerate with\n\
         /// `cargo run --bin gen_withdraw_vk --release`.\n\
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

const HEADER_COMMENT: &str = r#"//! Hardcoded verifying key for the production `WithdrawCircuit<20>`.
//!
//! **DO NOT EDIT BY HAND.** This file is generated by
//! `crates/tidex6-circuits/src/bin/gen_withdraw_vk.rs` with a
//! fixed RNG seed. Regenerate with:
//!
//! ```text
//! cargo run --bin gen_withdraw_vk --release
//! ```
//!
//! **DEVELOPMENT ONLY.** Single-contributor trusted setup. Before
//! mainnet replace with a multi-party Phase-2 ceremony; see
//! `docs/release/security.md` section 1.4.
"#;

/// Render a byte slice as a Rust array literal, wrapping every 12
/// bytes to keep the generated file readable.
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

/// Walk up from `CARGO_MANIFEST_DIR` until we find the workspace
/// root (the directory that contains `Cargo.toml` with `[workspace]`).
/// This keeps the generator runnable regardless of where cargo
/// invokes it from.
fn find_workspace_root() -> PathBuf {
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
