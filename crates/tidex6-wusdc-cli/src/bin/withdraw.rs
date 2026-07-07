//! withdraw из verify-only wUSDC-пула по ноте — вывод на свежий адрес.
//!
//! Groth16-слой (связь). Строит доказательство «нота в дереве», пул проверяет
//! его on-chain, гасит nullifier и эмитит WithdrawApproved — для релеера,
//! который переводит wUSDC получателю. На цепи НЕТ связи между deposit и этим
//! withdraw: recipient — свежий адрес, доказательство не раскрывает, какую
//! ноту тратим.
//!
//! Запуск: cargo run -p tidex6-wusdc-cli --bin withdraw -- <note-file>

use std::rc::Rc;

use anchor_client::{Client, Cluster, CommitmentConfig, Signer};
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result, anyhow};
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::thread_rng;
use solana_keypair::{Keypair, read_keypair_file};
use tidex6_circuits::solana_bytes::{Groth16SolanaBytes, groth16_to_solana_bytes};
use tidex6_circuits::withdraw::{
    WITHDRAW_TREE_DEPTH, WithdrawWitness, prove_withdraw, relayer_fee_bytes_from_u64,
};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};
use tidex6_wusdc_pool::accounts as wp_accounts;
use tidex6_wusdc_pool::instruction as wp_instruction;

fn main() -> Result<()> {
    let note_path = std::env::args()
        .nth(1)
        .context("укажи файл ноты: cargo run --bin withdraw -- <note.json>")?;
    let (rpc, ws, keypair_path) = load_cli_config()?;
    let payer = Rc::new(read_keypair_file(&keypair_path).map_err(|e| anyhow!("keypair: {e}"))?);
    let program_id: Pubkey = tidex6_wusdc_pool::ID;

    // Нота.
    let note = std::fs::read_to_string(&note_path).context("нота не прочитана")?;
    let secret = Secret::from_bytes(parse_hex_field(&note, "secret")?);
    let nullifier = Nullifier::from_bytes(parse_hex_field(&note, "nullifier")?);
    let commitment = Commitment::derive(&secret, &nullifier).context("commitment")?;
    let nullifier_hash = nullifier.derive_hash().context("nullifier_hash")?;
    // Сумма выплаты — из ноты (записана deposit'ом). Старые ноты без поля → дефолт.
    let amount_micro = parse_amount_field(&note).unwrap_or(DENOM_WUSDC);

    // Merkle-путь: реконструируем ПОЛНОЕ дерево пула из on-chain истории
    // депозитов (реплей логов `tidex6-wpool-deposit`). Одно-листовое дерево
    // неверно, как только в пуле больше одного депозита — корень не совпал бы
    // ни с одним в ring-buffer пула (MerkleRootNotRecent). Индексер даёт
    // дерево, чей корень = текущий on-chain корень.
    let (pool_pda, _) = Pubkey::find_program_address(&[b"wusdc-pool"], &program_id);
    println!("реконструирую дерево пула из on-chain истории…");
    let indexer = tidex6_indexer::PoolIndexer::new(rpc.clone(), pool_pda)
        .with_deposit_prefix("tidex6-wpool-deposit:");
    let history = indexer
        .fetch_deposit_history()
        .context("история депозитов пула")?;
    if history.is_empty() {
        return Err(anyhow!("пул пуст — нет депозитов для вывода"));
    }
    let mut tree = MerkleTree::new(WITHDRAW_TREE_DEPTH).context("tree")?;
    let mut my_leaf: Option<u64> = None;
    for rec in &history {
        let (idx, _root) = tree.insert(rec.commitment).context("insert")?;
        if rec.commitment == commitment {
            my_leaf = Some(idx);
        }
    }
    let leaf_index =
        my_leaf.ok_or_else(|| anyhow!("commitment ноты не найден в истории пула"))?;
    println!("депозитов в пуле: {}, наш лист: {leaf_index}", history.len());
    let proof = tree.proof(leaf_index).context("proof")?;
    let merkle_root = proof.root.to_bytes();
    let sibling_arrays: Vec<[u8; 32]> = proof.siblings.iter().map(|c| c.to_bytes()).collect();
    if sibling_arrays.len() != WITHDRAW_TREE_DEPTH {
        return Err(anyhow!("siblings {} != depth", sibling_arrays.len()));
    }
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] =
        std::array::from_fn(|i| &sibling_arrays[i]);
    let mut path_indices = [false; WITHDRAW_TREE_DEPTH];
    for (i, bit) in path_indices.iter_mut().enumerate() {
        *bit = (leaf_index >> i) & 1 == 1;
    }

    // Получатель — свежий адрес. Ключ СОХРАНЯЕМ (0600): именно этим адресом
    // релеер выплатит wUSDC (CT-transfer), и им же потом делается unwrap.
    // Идемпотентно: если файл уже есть (напр. прошлый withdraw упал после
    // сохранения ключа, но до on-chain) — переиспользуем тот же ключ, а не
    // падаем на create_new. Retry по той же ноте → тот же получатель.
    let nh_hex8 = {
        let nh = nullifier_hash.to_bytes();
        hex(&nh[..8])
    };
    let (recipient, recipient_path) =
        load_or_create_recipient(&nh_hex8).context("ключ получателя")?;
    let recipient_bytes = recipient.pubkey().to_bytes();
    let relayer_bytes = recipient_bytes; // self-relay, fee=0
    let relayer_fee_bytes = relayer_fee_bytes_from_u64(0);

    println!("нота:       {note_path}");
    println!("commitment: {}", hex(&commitment.to_bytes()));
    println!(
        "получатель: {} (свежий, ключ: {recipient_path})",
        recipient.pubkey()
    );

    // Groth16-proof.
    let home = std::env::var("HOME").context("нет $HOME")?;
    let pk_path =
        format!("{home}/work/rust/tidex6/crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin");
    let pk_bytes = std::fs::read(&pk_path).context("proving key не прочитан")?;
    let pk = ProvingKey::deserialize_uncompressed(&pk_bytes[..]).context("deserialize pk")?;

    let nh_bytes = nullifier_hash.to_bytes();
    let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
        secret: secret.as_bytes(),
        nullifier: nullifier.as_bytes(),
        path_siblings: sibling_refs,
        path_indices,
        merkle_root: &merkle_root,
        nullifier_hash: &nh_bytes,
        recipient: &recipient_bytes,
        relayer_address: &relayer_bytes,
        relayer_fee: &relayer_fee_bytes,
    };
    // ZK-блайндинг r,s Groth16 ДОЛЖЕН быть из OS-энтропии (CSPRNG), иначе
    // теряется zero-knowledge — фикс-сид сделал бы доказательство
    // предсказуемым. thread_rng — тот же паттерн, что в браузерном прувере.
    let mut rng = thread_rng();
    println!("\nстрою Groth16-доказательство…");
    let (groth_proof, _pi) =
        prove_withdraw::<WITHDRAW_TREE_DEPTH, _>(&pk, witness, &mut rng).context("prove")?;
    let Groth16SolanaBytes {
        proof_a,
        proof_b,
        proof_c,
        ..
    } = groth16_to_solana_bytes(&groth_proof, &pk.vk).context("solana bytes")?;

    // On-chain withdraw (verify + событие; актив не двигает).
    let client = Client::new_with_options(
        Cluster::Custom(rpc, ws),
        payer.clone(),
        CommitmentConfig::confirmed(),
    );
    let program = client.program(program_id)?;
    let (nullifier_pda, _) = Pubkey::find_program_address(&[b"nullifier", &nh_bytes], &program_id);

    println!("отправляю withdraw (verify + WithdrawApproved)…");
    let sig = program
        .request()
        .accounts(wp_accounts::Withdraw {
            pool: pool_pda,
            nullifier: nullifier_pda,
            recipient: recipient.pubkey(),
            relayer: recipient.pubkey(),
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(wp_instruction::Withdraw {
            proof_a,
            proof_b,
            proof_c,
            merkle_root,
            nullifier_hash: nh_bytes,
            relayer_fee: 0,
        })
        .send()
        .context("withdraw не подтвердился")?;

    // Payout-запрос для релеера-мувера (общая папка ~/.tidex6-wusdc).
    // Несёт только (recipient, amount) — ту же информацию, что мувер и так
    // увидел бы из on-chain события. Депозитора здесь нет: связь скрыта
    // Groth16-слоем, мувер её не знает.
    let payout_path =
        write_payout_request(&recipient.pubkey().to_string(), &nh_hex8, amount_micro)
            .context("payout-запрос")?;

    println!("\n═══ WITHDRAW ПОДТВЕРЖДЁН ═══");
    println!("tx:       {sig}");
    println!("Solscan:  https://solscan.io/tx/{sig}");
    println!("получатель (свежий): {}", recipient.pubkey());
    println!("payout:   {payout_path} ({} wUSDC)", amount_micro as f64 / 1e6);
    println!("\nСвязь разорвана: на цепи не видно, что этот withdraw — из того депозита.");
    println!("Дальше: configure_recipient → mover выплатит wUSDC получателю.");
    Ok(())
}

/// Дефолт для нот без поля amount (старый формат) — 2 wUSDC.
const DENOM_WUSDC: u64 = 2_000_000;

/// Читает `"amount": <micro>` из ноты. None если поля нет (старая нота).
fn parse_amount_field(note: &str) -> Option<u64> {
    let needle = "\"amount\": ";
    let start = note.find(needle)? + needle.len();
    let rest = &note[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Пишет payout-запрос для мувера: ~/.tidex6-wusdc/payout-<nh8>.json.
/// amount_micro — сумма выплаты (micro-wUSDC), взятая из ноты депозита.
fn write_payout_request(recipient: &str, nh_hex8: &str, amount_micro: u64) -> Result<String> {
    use std::io::Write as _;
    use std::os::unix::fs::DirBuilderExt;
    let home = std::env::var("HOME").context("нет $HOME")?;
    let dir = format!("{home}/.tidex6-wusdc");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .context("создать ~/.tidex6-wusdc")?;
    use std::os::unix::fs::OpenOptionsExt;
    let path = format!("{dir}/payout-{nh_hex8}.json");
    let json = format!("{{\n  \"recipient\": \"{recipient}\",\n  \"amount\": {amount_micro}\n}}\n");
    // 0600 для единообразия (секретов нет — recipient публичен, amount константа,
    // но defense-in-depth и консистентность с остальными файлами папки).
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .context("создать payout-запрос (0600)")?;
    f.write_all(json.as_bytes()).context("записать payout")?;
    Ok(path)
}

/// Возвращает keypair получателя из ~/.tidex6-wusdc/recipient-<nh8>.json,
/// создавая его при отсутствии. Идемпотентно по ноте: повтор withdraw по той
/// же ноте даёт тот же адрес выплаты.
///
/// Ключ — spend-material для выплаты wUSDC и unwrap; файл 0600, dir 0700.
/// Новый пишется атомарно (create_new + mode) — без окна с umask-правами.
/// Формат = JSON-массив 64 байт (secret+public), как ждёт read_keypair_file.
fn load_or_create_recipient(nh_hex8: &str) -> Result<(Keypair, String)> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let home = std::env::var("HOME").context("нет $HOME")?;
    let dir = format!("{home}/.tidex6-wusdc");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .context("создать ~/.tidex6-wusdc")?;
    let path = format!("{dir}/recipient-{nh_hex8}.json");

    // Уже есть (напр. прошлый withdraw упал после сохранения) — переиспользуем.
    if std::path::Path::new(&path).exists() {
        let recipient = read_keypair_file(&path).map_err(|e| anyhow!("recipient: {e}"))?;
        return Ok((recipient, path));
    }

    let recipient = Keypair::new();
    let bytes = recipient.to_bytes();
    let json = {
        let mut s = String::from("[");
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&b.to_string());
        }
        s.push(']');
        s
    };
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .context("создать recipient-файл (0600)")?;
    f.write_all(json.as_bytes()).context("записать recipient")?;
    Ok((recipient, path))
}

fn parse_hex_field(json: &str, field: &str) -> Result<[u8; 32]> {
    let needle = format!("\"{field}\": \"");
    let start = json
        .find(&needle)
        .ok_or_else(|| anyhow!("нет поля {field}"))?
        + needle.len();
    let end = json[start..]
        .find('"')
        .ok_or_else(|| anyhow!("{field} не закрыто"))?
        + start;
    let hex_str = &json[start..end];
    if hex_str.len() != 64 {
        return Err(anyhow!("{field}: ожидается 64 hex-символа"));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow!("{field}: не hex"))?;
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

fn load_cli_config() -> Result<(String, String, String)> {
    let home = std::env::var("HOME").context("нет $HOME")?;
    let raw = std::fs::read_to_string(format!("{home}/.config/solana/cli/config.yml"))
        .context("не прочитан ~/.config/solana/cli/config.yml")?;
    let field = |name: &str| -> Result<String> {
        raw.lines()
            .find_map(|line| line.strip_prefix(&format!("{name}: ")))
            .map(|v| v.trim().to_owned())
            .with_context(|| format!("нет поля {name}"))
    };
    let rpc = field("json_rpc_url")?;
    let ws = field("websocket_url")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| rpc.replacen("https", "wss", 1));
    Ok((rpc, ws, field("keypair_path")?))
}
