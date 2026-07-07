//! Оркестрация пул-операций (deposit/withdraw) как lib-функции на hand-rolled
//! ядре `pool::*` — БЕЗ anchor-client. Это то, что раньше делали бины
//! wusdc-cli, теперь — переиспользуемые функции для unified-сервиса.
//!
//! Файлы в ~/.tidex6-wusdc (0600/0700): нота (secret+nullifier+amount),
//! ключ получателя, payout-запрос — как spend-material.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::thread_rng;
use solana_keypair::{read_keypair_file, Keypair};
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use tidex6_circuits::solana_bytes::{groth16_to_solana_bytes, Groth16SolanaBytes};
use tidex6_circuits::withdraw::{
    prove_withdraw, relayer_fee_bytes_from_u64, WithdrawWitness, WITHDRAW_TREE_DEPTH,
};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

use crate::pool;

const MEMO_LEN: u32 = 32;
const REVOKE_WINDOW: i64 = 600;
const DENOM_DEFAULT: u64 = 2_000_000;

/// Безопасно резолвит имя файла под ~/.tidex6-wusdc: берёт только basename
/// (Path::file_name не даёт `/` и `..`), требует `<prefix><hex>.json`, склеивает
/// с фиксированной базой. Защита от path-traversal во входных путях по IPC.
pub fn safe_tidex6_file(input: &str, prefix: &str) -> Result<String> {
    let name = std::path::Path::new(input)
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("плохое имя файла"))?;
    let inner = name
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(".json"))
        .ok_or_else(|| anyhow!("ожидается {prefix}<hex>.json"))?;
    if inner.is_empty() || !inner.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("ожидается {prefix}<hex>.json"));
    }
    Ok(format!("{}/{name}", tidex6_dir()?))
}

fn tidex6_dir() -> Result<String> {
    let home = std::env::var("HOME").context("нет $HOME")?;
    let dir = format!("{home}/.tidex6-wusdc");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .context("создать ~/.tidex6-wusdc")?;
    Ok(dir)
}

/// deposit: генерит ноту (secret,nullifier,amount), кладёт commitment в дерево
/// через hand-rolled инструкцию. Возвращает (sig, путь-ноты, commitment-hex).
pub async fn deposit(
    rpc: &RpcClient,
    payer: &Keypair,
    amount_micro: u64,
) -> Result<(String, String, String)> {
    let secret = Secret::random().context("secret")?;
    let nullifier = Nullifier::random().context("nullifier")?;
    let commitment = Commitment::derive(&secret, &nullifier).context("commitment")?;
    let commitment_bytes = commitment.to_bytes();

    let ix = pool::build_deposit_ix(
        &payer.pubkey(),
        commitment_bytes,
        MEMO_LEN,
        REVOKE_WINDOW,
        &[0u8; MEMO_LEN as usize],
    );
    let sig = pool::send_ix(rpc, payer, ix).await.context("deposit send")?;

    let dir = tidex6_dir()?;
    let note_path = format!("{dir}/note-{}.json", hex(&commitment_bytes[..8]));
    let note_json = format!(
        "{{\n  \"secret\": \"{}\",\n  \"nullifier\": \"{}\",\n  \"commitment\": \"{}\",\n  \"amount\": {}\n}}\n",
        hex(secret.as_bytes()),
        hex(nullifier.as_bytes()),
        hex(&commitment_bytes),
        amount_micro
    );
    write_owner_only(&note_path, note_json.as_bytes()).context("сохранить ноту")?;
    Ok((sig, note_path, hex(&commitment_bytes)))
}

/// Депозит из БРАУЗЕРА: `commitment` и ML-KEM-конверт сгенерены в табе (WASM),
/// сюда приходят готовыми — сервер ноту НЕ генерит и НЕ хранит (self-custody
/// пользователя). Кладёт commitment в дерево + конверт в memo-PDA (deposit +
/// append_memo чанками, оператор=depositor подписывает). Возвращает
/// (sig-депозита, commitment-hex). Обёртку wUSDC (ct::wrap) делает вызывающий.
pub async fn deposit_browser(
    rpc: &RpcClient,
    payer: &Keypair,
    commitment: [u8; 32],
    envelope: &[u8],
    revoke_window: i64,
) -> Result<(String, String)> {
    // Кусок memo ≤ 800 Б: с фикс-частью deposit-ix + аккаунтами + подписью
    // укладываемся в лимит транзакции (~1232 Б).
    const MEMO_CHUNK: usize = 800;
    let total_len = envelope.len() as u32;
    let first = &envelope[..envelope.len().min(MEMO_CHUNK)];
    let ix = pool::build_deposit_ix(&payer.pubkey(), commitment, total_len, revoke_window, first);
    let sig = pool::send_ix(rpc, payer, ix).await.context("deposit send")?;

    let mut offset = first.len();
    while offset < envelope.len() {
        let end = (offset + MEMO_CHUNK).min(envelope.len());
        let ix =
            pool::build_append_memo_ix(&payer.pubkey(), commitment, offset as u32, &envelope[offset..end]);
        pool::send_ix(rpc, payer, ix)
            .await
            .context("append_memo send")?;
        offset = end;
    }
    Ok((sig, hex(&commitment)))
}

/// withdraw: реконструирует дерево из истории, строит Groth16-доказательство,
/// шлёт hand-rolled withdraw, сохраняет ключ получателя + payout-запрос.
/// Возвращает (sig, recipient-pubkey, payout-путь, amount_micro).
pub async fn withdraw(
    rpc: &RpcClient,
    payer: &Keypair,
    note_path: &str,
) -> Result<(String, String, String, u64)> {
    // Ограничиваем вход до note-<hex>.json под базой (path-traversal защита).
    let note_path = safe_tidex6_file(note_path, "note-")?;
    let note = std::fs::read_to_string(&note_path).context("нота не прочитана")?;
    let secret = Secret::from_bytes(parse_hex_field(&note, "secret")?);
    let nullifier = Nullifier::from_bytes(parse_hex_field(&note, "nullifier")?);
    let commitment = Commitment::derive(&secret, &nullifier).context("commitment")?;
    let nullifier_hash = nullifier.derive_hash().context("nh")?;
    let nh_bytes = nullifier_hash.to_bytes();
    let amount_micro = parse_amount_field(&note).unwrap_or(DENOM_DEFAULT);

    // Дерево из on-chain истории пула.
    let history = pool::fetch_deposit_history(rpc).await.context("история")?;
    let mut tree = MerkleTree::new(WITHDRAW_TREE_DEPTH).context("tree")?;
    let mut my_leaf = None;
    for (_leaf, commit) in &history {
        let (idx, _) = tree
            .insert(Commitment::from_bytes(*commit))
            .context("insert")?;
        if *commit == commitment.to_bytes() {
            my_leaf = Some(idx);
        }
    }
    let leaf_index = my_leaf.ok_or_else(|| anyhow!("commitment ноты не в истории пула"))?;
    let proof = tree.proof(leaf_index).context("proof")?;
    let merkle_root = proof.root.to_bytes();
    let siblings: Vec<[u8; 32]> = proof.siblings.iter().map(|c| c.to_bytes()).collect();
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] = std::array::from_fn(|i| &siblings[i]);
    let mut path_indices = [false; WITHDRAW_TREE_DEPTH];
    for (i, bit) in path_indices.iter_mut().enumerate() {
        *bit = (leaf_index >> i) & 1 == 1;
    }

    // Свежий получатель (идемпотентно по ноте).
    let nh_hex8 = hex(&nh_bytes[..8]);
    let (recipient, _recipient_path) = load_or_create_recipient(&nh_hex8)?;
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
    let (groth_proof, _pi) =
        prove_withdraw::<WITHDRAW_TREE_DEPTH, _>(&pk, witness, &mut thread_rng()).context("prove")?;
    let Groth16SolanaBytes {
        proof_a,
        proof_b,
        proof_c,
        ..
    } = groth16_to_solana_bytes(&groth_proof, &pk.vk).context("solana bytes")?;

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
    let sig = pool::send_ix(rpc, payer, ix).await.context("withdraw send")?;

    // Payout-запрос (recipient, amount).
    let dir = tidex6_dir()?;
    let payout_path = format!("{dir}/payout-{nh_hex8}.json");
    let payout_json = format!(
        "{{\n  \"recipient\": \"{}\",\n  \"amount\": {amount_micro}\n}}\n",
        recipient.pubkey()
    );
    write_owner_only_trunc(&payout_path, payout_json.as_bytes()).context("payout")?;

    Ok((sig, recipient.pubkey().to_string(), payout_path, amount_micro))
}

/// Путь Меркла для браузерного withdraw: реконструирует дерево из on-chain
/// истории пула и возвращает `(root_hex, siblings_concat_hex, indices)` для
/// commitment. Доказательство строит браузер (WASM), сумму двигает сервер.
pub async fn merkle_path_for(
    rpc: &RpcClient,
    commitment: [u8; 32],
) -> Result<(String, String, Vec<u8>)> {
    let history = pool::fetch_deposit_history(rpc).await.context("история пула")?;
    let mut tree = MerkleTree::new(WITHDRAW_TREE_DEPTH).context("tree")?;
    let mut my_leaf = None;
    for (_leaf, commit) in &history {
        let (idx, _) = tree
            .insert(Commitment::from_bytes(*commit))
            .context("insert")?;
        if *commit == commitment {
            my_leaf = Some(idx);
        }
    }
    let leaf_index = my_leaf.ok_or_else(|| anyhow!("commitment не в истории пула"))?;
    let proof = tree.proof(leaf_index).context("proof")?;
    let root = hex(&proof.root.to_bytes());
    let mut siblings = Vec::with_capacity(WITHDRAW_TREE_DEPTH * 32);
    for s in &proof.siblings {
        siblings.extend_from_slice(&s.to_bytes());
    }
    let indices: Vec<u8> = (0..WITHDRAW_TREE_DEPTH)
        .map(|i| ((leaf_index >> i) & 1) as u8)
        .collect();
    Ok((root, hex(&siblings), indices))
}

/// Браузерный withdraw: доказательство построено в табе (WASM), сюда приходят
/// байты Groth16 + публичные входы. Сервер шлёт withdraw-ix в пул (пруф +
/// nullifier), обёртку суммы (cashout) делает вызывающий. relayer=recipient,
/// fee=0 (direct-режим) — оператор платит только комиссию сети.
#[allow(clippy::too_many_arguments)]
pub async fn withdraw_browser(
    rpc: &RpcClient,
    payer: &Keypair,
    recipient: &solana_pubkey::Pubkey,
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: [u8; 32],
    nullifier_hash: [u8; 32],
) -> Result<String> {
    let ix = pool::build_withdraw_ix(
        &payer.pubkey(),
        recipient,
        recipient,
        proof_a,
        proof_b,
        proof_c,
        merkle_root,
        nullifier_hash,
        0,
    );
    pool::send_ix(rpc, payer, ix).await.context("withdraw send")
}

/// Читает keypair получателя, создавая при отсутствии (идемпотентно по ноте).
fn load_or_create_recipient(nh_hex8: &str) -> Result<(Keypair, String)> {
    let dir = tidex6_dir()?;
    let path = format!("{dir}/recipient-{nh_hex8}.json");
    if std::path::Path::new(&path).exists() {
        let kp = read_keypair_file(&path).map_err(|e| anyhow!("recipient: {e}"))?;
        return Ok((kp, path));
    }
    let recipient = Keypair::new();
    let bytes = recipient.to_bytes();
    let mut s = String::from("[");
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&b.to_string());
    }
    s.push(']');
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .context("recipient 0600")?;
    f.write_all(s.as_bytes()).context("write recipient")?;
    Ok((recipient, path))
}

/// Атомарно 0600 (create_new) — для spend-material без окна umask.
fn write_owner_only(path: &str, data: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context("create_new 0600")?;
    f.write_all(data)?;
    Ok(())
}

/// 0600 с truncate (payout можно перезаписывать).
fn write_owner_only_trunc(path: &str, data: &[u8]) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .context("0600 trunc")?;
    f.write_all(data)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).ok();
    Ok(())
}

fn parse_hex_field(note: &str, field: &str) -> Result<[u8; 32]> {
    let needle = format!("\"{field}\": \"");
    let start = note.find(&needle).ok_or_else(|| anyhow!("нет {field}"))? + needle.len();
    let end = note[start..]
        .find('"')
        .ok_or_else(|| anyhow!("{field} не закрыто"))?
        + start;
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

fn parse_amount_field(note: &str) -> Option<u64> {
    let needle = "\"amount\": ";
    let start = note.find(needle)? + needle.len();
    let rest = &note[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
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

/// Открыть nonblocking RPC-клиент из ~/.config/solana/cli/config.yml.
pub fn rpc_from_config() -> Result<(Arc<RpcClient>, Keypair)> {
    use solana_commitment_config::CommitmentConfig;
    let home = std::env::var("HOME").context("нет $HOME")?;
    let raw = std::fs::read_to_string(format!("{home}/.config/solana/cli/config.yml"))
        .context("config.yml")?;
    let field = |name: &str| -> Result<String> {
        raw.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .map(|v| v.trim().to_owned())
            .with_context(|| format!("нет {name}"))
    };
    let rpc = Arc::new(RpcClient::new_with_commitment(
        field("json_rpc_url")?,
        CommitmentConfig::confirmed(),
    ));
    let payer = read_keypair_file(field("keypair_path")?).map_err(|e| anyhow!("keypair: {e}"))?;
    Ok((rpc, payer))
}

/// RPC + оператор-кошелёк для КОНКРЕТНОЙ сети — для двух живых бэкендов
/// (devnet + mainnet одновременно, каждый свой кошелёк/RPC/сокет).
///
/// RPC: `rpc_override` (напр. Helius) или registry `default_rpc`.
/// Кошелёк: `~/.tidex6-wusdc/keypair-{moniker}.json`; если файла нет —
/// fallback на solana CLI keypair (одиночный режим).
pub fn rpc_for_network(
    net: tidex6_core::network::Network,
    rpc_override: Option<&str>,
) -> Result<(Arc<RpcClient>, Keypair)> {
    use solana_commitment_config::CommitmentConfig;
    let home = std::env::var("HOME").context("нет $HOME")?;
    let moniker = net.info().moniker;
    let rpc_url = rpc_override
        .map(str::to_string)
        .unwrap_or_else(|| net.info().default_rpc.to_string());
    let rpc = Arc::new(RpcClient::new_with_commitment(
        rpc_url,
        CommitmentConfig::confirmed(),
    ));
    let kp_path = format!("{home}/.tidex6-wusdc/keypair-{moniker}.json");
    let payer = if std::path::Path::new(&kp_path).exists() {
        read_keypair_file(&kp_path).map_err(|e| anyhow!("keypair {kp_path}: {e}"))?
    } else {
        let (_, p) = rpc_from_config()?;
        p
    };
    Ok((rpc, payer))
}
