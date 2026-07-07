//! Проверка hand-rolled withdraw: полный путь (история пула → дерево → Groth16
//! proof → сырой `build_withdraw_ix`) + simulateTransaction. По уже потраченной
//! ноте симуляция дойдёт до nullifier (`already in use`) ИЛИ проверки proof —
//! это подтверждает, что дискриминатор/аргументы/аккаунты/proof декодировались
//! верно. Без коммита/комиссий.
//!
//! Запуск: cargo run --manifest-path crates/tidex6-ct-lab/Cargo.toml \
//!   --bin verify_withdraw -- <note.json>

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::thread_rng;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, Keypair};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_transaction::Transaction;
use tidex6_circuits::solana_bytes::{groth16_to_solana_bytes, Groth16SolanaBytes};
use tidex6_circuits::withdraw::{
    prove_withdraw, relayer_fee_bytes_from_u64, WithdrawWitness, WITHDRAW_TREE_DEPTH,
};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

use tidex6_ct_lab::pool;

#[tokio::main]
async fn main() -> Result<()> {
    let note_path = std::env::args()
        .nth(1)
        .context("укажи ноту: verify_withdraw -- <note.json>")?;
    let (json_rpc_url, keypair_path) = load_cli_config()?;
    let payer = read_keypair_file(&keypair_path).map_err(|e| anyhow!("keypair: {e}"))?;
    let rpc = Arc::new(RpcClient::new_with_commitment(
        json_rpc_url,
        CommitmentConfig::confirmed(),
    ));

    // Нота.
    let note = std::fs::read_to_string(&note_path).context("нота")?;
    let secret = Secret::from_bytes(parse_hex(&note, "secret")?);
    let nullifier = Nullifier::from_bytes(parse_hex(&note, "nullifier")?);
    let commitment = Commitment::derive(&secret, &nullifier).context("commitment")?;
    let nullifier_hash = nullifier.derive_hash().context("nh")?;
    let nh_bytes = nullifier_hash.to_bytes();

    // История пула → дерево → лист (unified fetch, без anchor-индексера).
    println!("реконструирую дерево пула…");
    let history = pool::fetch_deposit_history(&rpc).await.context("история")?;
    let mut tree = MerkleTree::new(WITHDRAW_TREE_DEPTH).context("tree")?;
    let mut my_leaf = None;
    for (leaf, commit) in &history {
        let (idx, _) = tree.insert(Commitment::from_bytes(*commit)).context("insert")?;
        if *commit == commitment.to_bytes() {
            my_leaf = Some(idx);
        }
        let _ = leaf;
    }
    let leaf_index = my_leaf.ok_or_else(|| anyhow!("commitment не в истории пула"))?;
    println!("депозитов: {}, наш лист: {leaf_index}", history.len());
    let proof = tree.proof(leaf_index).context("proof")?;
    let merkle_root = proof.root.to_bytes();
    let siblings: Vec<[u8; 32]> = proof.siblings.iter().map(|c| c.to_bytes()).collect();
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] = std::array::from_fn(|i| &siblings[i]);
    let mut path_indices = [false; WITHDRAW_TREE_DEPTH];
    for (i, bit) in path_indices.iter_mut().enumerate() {
        *bit = (leaf_index >> i) & 1 == 1;
    }

    // Свежий получатель (для binding в proof).
    let recipient = Keypair::new();
    let recipient_bytes = recipient.pubkey().to_bytes();
    let relayer_fee_bytes = relayer_fee_bytes_from_u64(0);

    // Groth16 proof.
    let home = std::env::var("HOME").context("нет $HOME")?;
    let pk_path =
        format!("{home}/work/rust/tidex6/crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin");
    let pk = ProvingKey::deserialize_uncompressed(&std::fs::read(&pk_path).context("pk")?[..])
        .context("deserialize pk")?;
    let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
        secret: secret.as_bytes(),
        nullifier: nullifier.as_bytes(),
        path_siblings: sibling_refs,
        path_indices,
        merkle_root: &merkle_root,
        nullifier_hash: &nh_bytes,
        recipient: &recipient_bytes,
        relayer_address: &recipient_bytes,
        relayer_fee: &relayer_fee_bytes,
    };
    println!("строю Groth16-доказательство…");
    let (groth_proof, _pi) =
        prove_withdraw::<WITHDRAW_TREE_DEPTH, _>(&pk, witness, &mut thread_rng()).context("prove")?;
    let Groth16SolanaBytes {
        proof_a,
        proof_b,
        proof_c,
        ..
    } = groth16_to_solana_bytes(&groth_proof, &pk.vk).context("solana bytes")?;

    // Hand-rolled withdraw ix + симуляция.
    let ix = pool::build_withdraw_ix(
        &payer.pubkey(),
        &recipient.pubkey(),
        &recipient.pubkey(),
        proof_a,
        proof_b,
        proof_c,
        merkle_root,
        nh_bytes,
        0,
    );
    println!(
        "\nwithdraw ix: accounts={}, data_len={}, диск={}",
        ix.accounts.len(),
        ix.data.len(),
        hex(&ix.data[..8])
    );
    let blockhash = rpc.get_latest_blockhash().await.context("blockhash")?;
    let tx =
        Transaction::new_signed_with_payer(&[ix], Some(&payer.pubkey()), &[&payer], blockhash);

    println!("симулирую…");
    let sim = rpc.simulate_transaction(&tx).await.context("simulate")?;
    match &sim.value.err {
        None => println!("\n✅ СИМУЛЯЦИЯ УСПЕШНА — hand-rolled withdraw принят (proof верифицирован)."),
        Some(e) => println!("\nСИМУЛЯЦИЯ ОТКЛОНЕНА: {e:?}\n(если 'already in use' на nullifier — формат+proof ОК, нота просто потрачена)"),
    }
    if let Some(logs) = &sim.value.logs {
        println!("--- program logs ---");
        for l in logs {
            println!("  {l}");
        }
    }
    Ok(())
}

fn parse_hex(note: &str, field: &str) -> Result<[u8; 32]> {
    let needle = format!("\"{field}\": \"");
    let start = note.find(&needle).ok_or_else(|| anyhow!("нет {field}"))? + needle.len();
    let end = note[start..].find('"').ok_or_else(|| anyhow!("{field} не закрыто"))? + start;
    let hex_str = &note[start..end];
    if hex_str.len() != 64 {
        return Err(anyhow!("{field}: 64 hex"));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16).map_err(|_| anyhow!("hex"))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 0x0f) as usize] as char);
    }
    out
}

fn load_cli_config() -> Result<(String, String)> {
    let home = std::env::var("HOME").context("нет $HOME")?;
    let raw = std::fs::read_to_string(format!("{home}/.config/solana/cli/config.yml"))
        .context("config.yml")?;
    let field = |name: &str| -> Result<String> {
        raw.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .map(|v| v.trim().to_owned())
            .with_context(|| format!("нет {name}"))
    };
    Ok((field("json_rpc_url")?, field("keypair_path")?))
}
