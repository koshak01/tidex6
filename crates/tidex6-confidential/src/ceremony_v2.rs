//! Self-test of ceremony keys for the v2 circuits (ADR-022).
//!
//! v2 keys come only from a ceremony state — the snarkjs genesis while the
//! stand runs on testnets, the finalized state after the public ceremony. Both
//! use the snarkjs layout, so the one prover every client calls
//! (`prove_ceremony`) matches the key from the first testnet to mainnet. A key
//! made by the arkworks setup has a different layout and rejects those proofs;
//! the v2 modules therefore offer no such setup.
//!
//! Each self-test builds a real note at a non-zero position (the nullifier
//! depends on it), proves with the key and verifies against the key's own VK.

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_snark::SNARK;
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use tidex6_circuits::solana_bytes::Groth16SolanaBytes;
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::Commitment;

use crate::bytes::fr_to_be_bytes;
use crate::ceremony::SelftestError;
use crate::note_v2;
use crate::transfer_v2::{self, TransferV2Witness};
use crate::withdraw::POOL_TREE_DEPTH;
use crate::withdraw_v2::{self, WithdrawV2Witness};

/// A note of the self-test: leaf at position 1 of a fresh tree.
struct PlacedNote {
    sk_spend: Fr,
    rho: Fr,
    aux: Fr,
    amount: u64,
    siblings: [Fr; POOL_TREE_DEPTH],
    indices: [bool; POOL_TREE_DEPTH],
    root: Fr,
}

/// Put a v2 note owned by `sk_spend` at position 1, after a filler leaf.
fn place_note(sk_spend: Fr, amount: u64) -> Result<PlacedNote, SelftestError> {
    let core_err = |e: &dyn std::fmt::Display| SelftestError::Core(e.to_string());
    let rho = Fr::from(0x5e1f_7e57u64);
    let aux = Fr::from(0u64);
    let core = note_v2::core(note_v2::owner_pk(sk_spend), rho, aux);
    let leaf = note_v2::leaf(note_v2::body(core, amount), Fr::from(0u64));

    let mut tree = MerkleTree::new(POOL_TREE_DEPTH).map_err(|e| core_err(&e))?;
    tree.insert(Commitment::from_bytes(fr_to_be_bytes(Fr::from(7u64))))
        .map_err(|e| core_err(&e))?;
    tree.insert(Commitment::from_bytes(fr_to_be_bytes(leaf)))
        .map_err(|e| core_err(&e))?;
    let path = tree.proof(1).map_err(|e| core_err(&e))?;
    Ok(PlacedNote {
        sk_spend,
        rho,
        aux,
        amount,
        siblings: std::array::from_fn(|i| fr_from_be(path.siblings[i].as_bytes())),
        indices: std::array::from_fn(|i| (1u64 >> i) & 1 == 1),
        root: fr_from_be(tree.root().as_bytes()),
    })
}

fn fr_from_be(bytes: &[u8]) -> Fr {
    use ark_ff::PrimeField;
    Fr::from_be_bytes_mod_order(bytes)
}

/// Prove and verify a v2 withdraw with `pk`; returns its VK.
pub fn selftest_withdraw_v2(
    pk: &ProvingKey<Bn254>,
    seed: u64,
) -> Result<VerifyingKey<Bn254>, SelftestError> {
    let note = place_note(Fr::from(0xa11ce_u64), 1_250_000)?;
    let witness = WithdrawV2Witness {
        sk_spend: note.sk_spend,
        rho: note.rho,
        aux: note.aux,
        amount: note.amount,
        refund: Fr::from(0u64),
        path_siblings: note.siblings,
        path_indices: note.indices,
        merkle_root: note.root,
        recipient: [0x11; 32],
        relayer: [0x42; 32],
        relayer_fee: 0,
    };
    let mut rng = StdRng::seed_from_u64(seed);
    let (proof, public) = withdraw_v2::prove_ceremony(pk, &witness, &mut rng)
        .map_err(|e| SelftestError::Prove(e.to_string()))?;
    check(pk, &public, &proof)
}

/// Prove and verify a v2 in-pool transfer (1 → 3) with `pk`; returns its VK.
pub fn selftest_transfer_v2(
    pk: &ProvingKey<Bn254>,
    seed: u64,
) -> Result<VerifyingKey<Bn254>, SelftestError> {
    let floor = 100_000;
    let amount_pay = 20_000_000;
    let amount_fee = transfer_v2::fee_for(amount_pay, floor);
    let amount_change = 5_000_000;
    let note = place_note(Fr::from(0xb0b_u64), amount_pay + amount_fee + amount_change)?;
    let recipient_core = note_v2::core(
        note_v2::owner_pk(Fr::from(0xca401_u64)),
        Fr::from(3u64),
        Fr::from(0u64),
    );
    let witness = TransferV2Witness {
        sk_spend: note.sk_spend,
        rho_in: note.rho,
        aux_in: note.aux,
        amount_in: note.amount,
        refund_in: Fr::from(0u64),
        path_siblings: note.siblings,
        path_indices: note.indices,
        core_pay: recipient_core,
        amount_pay,
        rho_change: Fr::from(4u64),
        aux_change: Fr::from(0u64),
        amount_change,
        rho_fee: Fr::from(5u64),
        amount_fee,
        merkle_root: note.root,
        treasury_pk: note_v2::owner_pk(Fr::from(0x7e_a5_u64)),
        fee_floor: floor,
    };
    let mut rng = StdRng::seed_from_u64(seed);
    let (proof, public) = transfer_v2::prove_ceremony(pk, &witness, &mut rng)
        .map_err(|e| SelftestError::Prove(e.to_string()))?;
    check(pk, &public, &proof)
}

fn check(
    pk: &ProvingKey<Bn254>,
    public: &[Fr],
    proof: &ark_groth16::Proof<Bn254>,
) -> Result<VerifyingKey<Bn254>, SelftestError> {
    let ok = Groth16::<Bn254>::verify(&pk.vk, public, proof)
        .map_err(|e| SelftestError::Verify(e.to_string()))?;
    if !ok {
        return Err(SelftestError::Rejected);
    }
    Ok(pk.vk.clone())
}

/// `<name>_vk.rs` for an on-chain Solana program: a `Groth16Verifyingkey`
/// constant named `<prefix>_VERIFYING_KEY` in the `groth16-solana` layout.
pub fn render_program_vk(prefix: &str, header: &str, bytes: &Groth16SolanaBytes) -> String {
    let nr_public = bytes.vk_ic.len() - 1;
    let mut out = String::from(header);
    out.push_str("\nuse groth16_solana::groth16::Groth16Verifyingkey;\n\n");
    out.push_str(&format!(
        "pub const {prefix}_NR_PUBLIC_INPUTS: usize = {nr_public};\n\n\
         #[allow(clippy::type_complexity)]\n\
         static {prefix}_VK_IC: [[u8; 64]; {}] = [\n",
        bytes.vk_ic.len()
    ));
    for point in &bytes.vk_ic {
        out.push_str(&render_byte_array(point));
        out.push_str(",\n");
    }
    out.push_str("];\n\n");
    for (label, len, data) in [
        ("ALPHA_G1", 64, &bytes.vk_alpha_g1[..]),
        ("BETA_G2", 128, &bytes.vk_beta_g2[..]),
        ("GAMMA_G2", 128, &bytes.vk_gamma_g2[..]),
        ("DELTA_G2", 128, &bytes.vk_delta_g2[..]),
    ] {
        out.push_str(&format!("static {prefix}_VK_{label}: [u8; {len}] = "));
        out.push_str(&render_byte_array(data));
        out.push_str(";\n\n");
    }
    out.push_str(&format!(
        "pub const {prefix}_VERIFYING_KEY: Groth16Verifyingkey = Groth16Verifyingkey {{\n\
         \x20   nr_pubinputs: {nr_public},\n\
         \x20   vk_alpha_g1: {prefix}_VK_ALPHA_G1,\n\
         \x20   vk_beta_g2: {prefix}_VK_BETA_G2,\n\
         \x20   vk_gamme_g2: {prefix}_VK_GAMMA_G2,\n\
         \x20   vk_delta_g2: {prefix}_VK_DELTA_G2,\n\
         \x20   vk_ic: &{prefix}_VK_IC,\n\
         }};\n"
    ));
    out
}

fn render_byte_array(bytes: &[u8]) -> String {
    let mut out = String::from("[\n");
    for chunk in bytes.chunks(12) {
        out.push_str("    ");
        for b in chunk {
            out.push_str(&format!("0x{b:02x}, "));
        }
        out.push('\n');
    }
    out.push(']');
    out
}
