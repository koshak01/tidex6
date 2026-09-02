//! Export the hidden-amount withdraw circuit as a circom/iden3 `.r1cs` —
//! the arkworks → snarkjs bridge for the ceremony genesis.
//!
//! Why a separate exporter instead of a flag on `tidex6-circuits/export_r1cs`:
//! the two circuits differ in shape (8 public inputs vs 5, the amount inside
//! the commitment, a 64-bit range check), and the ceremony genesis is derived
//! from the R1CS of exactly the circuit whose key will later be baked into the
//! program. Mixing them up means collecting twenty contributions towards a key
//! that no program accepts.
//!
//! Next: `snarkjs groth16 setup withdraw.r1cs pot<k>.ptau withdraw_0000.zkey`
//! in a sandbox (node is not installed on the host), then the zkey feeds
//! `ceremony_bootstrap`.
//!
//! `.r1cs` layout (iden3 binfileutils, v1): magic "r1cs" + version + nSections,
//! then Header / Constraints / Wire2Label — byte-for-byte the same as the
//! older exporter, so snarkjs reads both identically.
//!
//! Run:    cargo run -p tidex6-confidential --bin export_r1cs
//! Output: crates/tidex6-confidential/artifacts/withdraw.r1cs

use std::io::Write;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use tidex6_confidential::withdraw::WithdrawCircuit;

fn main() {
    // Shape-only circuit (every input None) in Setup mode → matrices without a witness.
    let circuit = WithdrawCircuit {
        amount: None,
        secret: None,
        nullifier: None,
        path_siblings: None,
        path_indices: None,
        merkle_root: None,
        nullifier_hash: None,
        recipient_hi: None,
        recipient_lo: None,
        relayer_hi: None,
        relayer_lo: None,
        relayer_fee: None,
        amount_public: None,
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .expect("generate_constraints");
    cs.finalize();
    let m = cs.to_matrices().expect("to_matrices");

    let n_instance = m.num_instance_variables; // includes wire 0 = ONE
    let n_witness = m.num_witness_variables;
    let n_wires = (n_instance + n_witness) as u32;
    let n_pub_in = (n_instance - 1) as u32; // public inputs (without ONE)
    let n_prv_in = n_witness as u32;
    let n_constraints = m.num_constraints as u32;
    println!("constraints: {n_constraints}");
    println!("wires:       {n_wires} (public {n_pub_in}, private {n_prv_in})");
    // ptau power — the smallest power of two at or above the constraint count.
    // Printed here so nobody has to work it out by hand before running snarkjs.
    let pow = 32 - (n_constraints.max(1) - 1).leading_zeros();
    println!(
        "ptau power:  {pow} (2^{pow} = {} >= {n_constraints})",
        1u64 << pow
    );

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

    // ── Assemble the file ─────────────────────────────────────────────
    let mut out = Vec::new();
    out.extend_from_slice(b"r1cs");
    out.extend_from_slice(&1u32.to_le_bytes()); // version
    out.extend_from_slice(&3u32.to_le_bytes()); // nSections
    write_section(&mut out, 1, &header);
    write_section(&mut out, 2, &constraints);
    write_section(&mut out, 3, &wire2label);

    // Path relative to the crate manifest, not to $HOME: the older exporter
    // wrote to `~/work/rust/tidex6/...` and silently failed on any machine
    // where the tree lives elsewhere.
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/artifacts/withdraw.r1cs");
    let mut f = std::fs::File::create(path).expect("create r1cs");
    f.write_all(&out).expect("write r1cs");
    println!("wrote {} ({} bytes)", path, out.len());
}

/// Linear combination: nTerms + [(wireIdx u32, coeff 32-byte LE)].
fn write_lc(buf: &mut Vec<u8>, lc: &[(Fr, usize)]) {
    buf.extend_from_slice(&(lc.len() as u32).to_le_bytes());
    for (coeff, idx) in lc {
        buf.extend_from_slice(&(*idx as u32).to_le_bytes());
        let mut c = coeff.into_bigint().to_bytes_le();
        c.resize(32, 0);
        buf.extend_from_slice(&c);
    }
}

/// Section: type (u32) + size (u64) + data.
fn write_section(out: &mut Vec<u8>, section_type: u32, data: &[u8]) {
    out.extend_from_slice(&section_type.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(data);
}
