//! Offline: что раздувает RSS на пути collect/prove.
//!
//! Не ходит в сеть. Грузит production PK (depth 20), строит валидный
//! witness на однолистовом дереве, гоняет `prove_withdraw`, на каждом
//! шаге печатает RSS через `ps` (без unsafe).
//!
//! ```text
//! cargo run --release -p tidex6-wusdc-cli --bin prove_rss
//! ```

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result};
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::thread_rng;
use tidex6_circuits::withdraw::{
    WITHDRAW_TREE_DEPTH, WithdrawWitness, prove_withdraw, relayer_fee_bytes_from_u64,
};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

fn rss_kb() -> u64 {
    let pid = std::process::id().to_string();
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok();
    out.and_then(|o| {
        String::from_utf8_lossy(&o.stdout)
            .trim()
            .parse::<u64>()
            .ok()
    })
    .unwrap_or(0)
}

fn mark(label: &str, t0: Instant, prev_rss: &mut u64) {
    let rss = rss_kb();
    let delta = rss as i64 - *prev_rss as i64;
    eprintln!(
        "prove_rss: step={label:28} elapsed_ms={:>6} rss_kb={:>8} delta_rss_kb={:>+8}",
        t0.elapsed().as_millis(),
        rss,
        delta
    );
    *prev_rss = rss;
}

fn main() -> Result<()> {
    let t0 = Instant::now();
    let mut prev = rss_kb();
    mark("process_start", t0, &mut prev);

    let home = std::env::var("HOME").context("$HOME")?;
    let pk_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("{home}/.tidex6-local/withdraw_pk_depth20.bin")));

    // ── 1. Merkle + valid witness (same shape as production) ─────────
    mark("witness_build_start", t0, &mut prev);
    let secret = Secret::random().context("secret")?;
    let nullifier = Nullifier::random().context("nullifier")?;
    let commitment = Commitment::derive(&secret, &nullifier).context("commitment")?;
    let mut tree = MerkleTree::new(WITHDRAW_TREE_DEPTH).context("tree")?;
    tree.insert(commitment).context("insert")?;
    let proof = tree.proof(0).context("merkle proof")?;
    let root = tree.root();
    let nullifier_hash = nullifier.derive_hash().context("nullifier hash")?;

    let sibling_bytes: Vec<[u8; 32]> = proof
        .siblings
        .iter()
        .map(|c| *c.as_bytes())
        .collect();
    assert_eq!(sibling_bytes.len(), WITHDRAW_TREE_DEPTH);
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] =
        std::array::from_fn(|i| &sibling_bytes[i]);
    let mut path_indices = [false; WITHDRAW_TREE_DEPTH];
    for (i, bit) in path_indices.iter_mut().enumerate() {
        *bit = (proof.leaf_index >> i) & 1 == 1;
    }
    let recipient = [0x11u8; 32];
    let relayer_fee = relayer_fee_bytes_from_u64(0);
    mark("witness_build_ok", t0, &mut prev);

    // ── 2. Read PK file ──────────────────────────────────────────────
    mark("pk_read_start", t0, &mut prev);
    let key_bytes = std::fs::read(&pk_path)
        .with_context(|| format!("read {}", pk_path.display()))?;
    eprintln!(
        "prove_rss: meta pk_path={} file_bytes={}",
        pk_path.display(),
        key_bytes.len()
    );
    mark("pk_read_ok", t0, &mut prev);

    // ── 3. Deserialize ProvingKey (uncompressed, unchecked) ──────────
    mark("pk_deser_start", t0, &mut prev);
    let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&key_bytes[..])
        .context("deserialize PK")?;
    drop(key_bytes);
    mark("pk_deser_ok", t0, &mut prev);

    // Rough structural sizes (counts only — cheap).
    eprintln!(
        "prove_rss: meta pk.vk.gamma_abc_g1.len={} pk.a_query.len={} \
         pk.b_g1_query.len={} pk.b_g2_query.len={} pk.h_query.len={} pk.l_query.len={}",
        pk.vk.gamma_abc_g1.len(),
        pk.a_query.len(),
        pk.b_g1_query.len(),
        pk.b_g2_query.len(),
        pk.h_query.len(),
        pk.l_query.len(),
    );

    // ── 4. prove_withdraw = R1CS synthesis + Groth16 MSM ─────────────
    let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
        secret: secret.as_bytes(),
        nullifier: nullifier.as_bytes(),
        path_siblings: sibling_refs,
        path_indices,
        merkle_root: root.as_bytes(),
        nullifier_hash: nullifier_hash.as_bytes(),
        recipient: &recipient,
        relayer_address: &recipient,
        relayer_fee: &relayer_fee,
    };
    mark("prove_withdraw_start", t0, &mut prev);
    let mut rng = thread_rng();
    let (proof, _pi) = prove_withdraw::<WITHDRAW_TREE_DEPTH, _>(&pk, witness, &mut rng)
        .context("prove_withdraw")?;
    mark("prove_withdraw_ok", t0, &mut prev);
    drop(proof);

    mark("pk_still_held", t0, &mut prev);
    drop(pk);
    mark("pk_dropped", t0, &mut prev);

    eprintln!(
        "prove_rss: DONE total_ms={} peak tracked via deltas above",
        t0.elapsed().as_millis()
    );
    Ok(())
}
