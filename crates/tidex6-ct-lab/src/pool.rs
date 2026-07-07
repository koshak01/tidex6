//! Hand-rolled клиент пула (verify-only wUSDC-pool) БЕЗ anchor-client.
//!
//! Anchor-инструкция = дискриминатор (`sha256("global:<метод>")[..8]`) + borsh
//! аргументов + метаданные аккаунтов в порядке `#[derive(Accounts)]`. Всё это
//! собирается вручную на solana-крейтах версии spl-token-client — без monolith
//! `solana-sdk`, поэтому уживается с CT-частью в одном процессе и wasm-дружелюбно.
//! Байты те же, что слал anchor-client → задеплоенная программа принимает.

use std::str::FromStr;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use solana_commitment_config::CommitmentConfig;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_rpc_client::rpc_client::GetConfirmedSignaturesForAddress2Config;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::{
    option_serializer::OptionSerializer, UiTransactionEncoding,
};

const SYSTEM_PROGRAM_ID: &str = "11111111111111111111111111111111";

/// Anchor-дискриминатор инструкции: первые 8 байт `sha256("global:<name>")`.
fn discriminator(name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(format!("global:{name}").as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Anchor-дискриминатор аккаунта: первые 8 байт `sha256("account:<Name>")`.
fn account_discriminator(name: &str) -> [u8; 8] {
    let mut hasher = Sha256::new();
    hasher.update(format!("account:{name}").as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Публичная запись memo-аккаунта пула — то, что видно на цепи БЕЗ расшифровки
/// (конверт `data` расшифровывается в браузере ключом ML-KEM). Сумма НЕ здесь —
/// она внутри конверта (hidden-amount).
pub struct MemoRecord {
    pub commitment: [u8; 32],
    pub depositor: Pubkey,
    pub created_ts: i64,
    pub revoke_window: i64,
    pub is_finalized: bool,
    pub data: Vec<u8>,
}

/// Все memo-аккаунты пула: getProgramAccounts + фильтр по дискриминатору
/// MemoAccount в коде (устойчиво к версиям RPC-фильтров). Отдаёт публичные
/// байты конверта — расшифровка в браузере.
pub async fn fetch_memo_accounts(rpc: &RpcClient) -> Result<Vec<MemoRecord>> {
    let accounts = rpc
        .get_program_accounts(&program_id())
        .await
        .context("getProgramAccounts (memo scan)")?;
    let disc = account_discriminator("MemoAccount");
    let mut out = Vec::new();
    for (_pubkey, acc) in accounts {
        if let Some(rec) = parse_memo_account(&acc.data, &disc) {
            out.push(rec);
        }
    }
    Ok(out)
}

/// Парсит байты MemoAccount (после проверки дискриминатора). Layout:
/// disc(8) commitment(32) depositor(32) created_ts(8) revoke_window(8)
/// total_len(4) written_len(4) bump(1) is_finalized(1) data_len(4) data(N).
fn parse_memo_account(data: &[u8], disc: &[u8; 8]) -> Option<MemoRecord> {
    const HEAD: usize = 8 + 32 + 32 + 8 + 8 + 4 + 4 + 1 + 1 + 4;
    if data.len() < HEAD || &data[..8] != disc {
        return None;
    }
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&data[8..40]);
    let depositor = Pubkey::try_from(&data[40..72]).ok()?;
    let created_ts = i64::from_le_bytes(data[72..80].try_into().ok()?);
    let revoke_window = i64::from_le_bytes(data[80..88].try_into().ok()?);
    let is_finalized = data[97] != 0;
    let data_len = u32::from_le_bytes(data[98..102].try_into().ok()?) as usize;
    let payload = data.get(HEAD..HEAD + data_len)?.to_vec();
    Some(MemoRecord {
        commitment,
        depositor,
        created_ts,
        revoke_window,
        is_finalized,
        data: payload,
    })
}

/// Пул-программа — из единого реестра по активным сети+активу
/// (config.network/asset). wUSDT-пул — другой program-id, PDA изолированы.
fn program_id() -> Pubkey {
    let net = crate::config::active_network();
    let asset = crate::config::active_asset();
    // Config-оверрайд пула per-окружение, иначе дефолт реестра.
    crate::config::mint_pool(net, asset)
        .or_else(|| net.asset(asset).and_then(|a| a.pool_program).map(str::to_string))
        .expect("pool program (config override or registry)")
        .parse()
        .expect("pool program id")
}

fn system_program() -> Pubkey {
    SYSTEM_PROGRAM_ID.parse().expect("system program id")
}

/// PDA пула: seeds `[b"wusdc-pool"]`.
pub fn pool_pda() -> Pubkey {
    Pubkey::find_program_address(&[b"wusdc-pool"], &program_id()).0
}

/// PDA memo-аккаунта депозита: seeds `[b"memo", commitment]`.
pub fn memo_pda(commitment: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"memo", commitment], &program_id()).0
}

/// PDA nullifier-записи: seeds `[b"nullifier", nullifier_hash]`.
pub fn nullifier_pda(nullifier_hash: &[u8; 32]) -> Pubkey {
    Pubkey::find_program_address(&[b"nullifier", nullifier_hash], &program_id()).0
}

/// Инструкция `deposit(commitment, memo_total_len, revoke_window, memo_chunk)`.
/// Аккаунты (порядок Deposit): pool(w), memo(w,init), payer(s,w), system.
/// Инструкция `init_pool(mint)` — создаёт PoolState PDA. Аккаунты (порядок
/// InitPool): pool(w,init), payer(s,w), system.
pub fn build_init_pool_ix(payer: &Pubkey, mint: &Pubkey) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&discriminator("init_pool"));
    // borsh(Pubkey) = сырые 32 байта.
    data.extend_from_slice(mint.as_ref());

    let accounts = vec![
        AccountMeta::new(pool_pda(), false),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(system_program(), false),
    ];
    Instruction {
        program_id: program_id(),
        accounts,
        data,
    }
}

pub fn build_deposit_ix(
    payer: &Pubkey,
    commitment: [u8; 32],
    memo_total_len: u32,
    revoke_window: i64,
    memo_chunk: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 4 + 8 + 4 + memo_chunk.len());
    data.extend_from_slice(&discriminator("deposit"));
    data.extend_from_slice(&commitment);
    data.extend_from_slice(&memo_total_len.to_le_bytes());
    data.extend_from_slice(&revoke_window.to_le_bytes());
    data.extend_from_slice(&(memo_chunk.len() as u32).to_le_bytes());
    data.extend_from_slice(memo_chunk);

    let accounts = vec![
        AccountMeta::new(pool_pda(), false),
        AccountMeta::new(memo_pda(&commitment), false),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(system_program(), false),
    ];
    Instruction {
        program_id: program_id(),
        accounts,
        data,
    }
}

/// Инструкция `append_memo(commitment, offset, chunk)` — дописывает следующий
/// кусок ML-KEM конверта в memo-PDA. depositor(=payer) подписывает (has_one).
/// Аккаунты (порядок AppendMemo): memo(w), depositor(s).
pub fn build_append_memo_ix(
    depositor: &Pubkey,
    commitment: [u8; 32],
    offset: u32,
    chunk: &[u8],
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 32 + 4 + 4 + chunk.len());
    data.extend_from_slice(&discriminator("append_memo"));
    data.extend_from_slice(&commitment);
    data.extend_from_slice(&offset.to_le_bytes());
    data.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    data.extend_from_slice(chunk);

    let accounts = vec![
        AccountMeta::new(memo_pda(&commitment), false),
        AccountMeta::new(*depositor, true),
    ];
    Instruction {
        program_id: program_id(),
        accounts,
        data,
    }
}

/// Инструкция `withdraw(proof_a, proof_b, proof_c, merkle_root, nullifier_hash, relayer_fee)`.
/// Аккаунты (порядок Withdraw): pool(r), nullifier(w,init), recipient(r),
/// relayer(r), payer(s,w), system.
#[allow(clippy::too_many_arguments)]
pub fn build_withdraw_ix(
    payer: &Pubkey,
    recipient: &Pubkey,
    relayer: &Pubkey,
    proof_a: [u8; 64],
    proof_b: [u8; 128],
    proof_c: [u8; 64],
    merkle_root: [u8; 32],
    nullifier_hash: [u8; 32],
    relayer_fee: u64,
) -> Instruction {
    let mut data = Vec::with_capacity(8 + 64 + 128 + 64 + 32 + 32 + 8);
    data.extend_from_slice(&discriminator("withdraw"));
    data.extend_from_slice(&proof_a);
    data.extend_from_slice(&proof_b);
    data.extend_from_slice(&proof_c);
    data.extend_from_slice(&merkle_root);
    data.extend_from_slice(&nullifier_hash);
    data.extend_from_slice(&relayer_fee.to_le_bytes());

    let accounts = vec![
        AccountMeta::new_readonly(pool_pda(), false),
        AccountMeta::new(nullifier_pda(&nullifier_hash), false),
        AccountMeta::new_readonly(*recipient, false),
        AccountMeta::new_readonly(*relayer, false),
        AccountMeta::new(*payer, true),
        AccountMeta::new_readonly(system_program(), false),
    ];
    Instruction {
        program_id: program_id(),
        accounts,
        data,
    }
}

/// Реплеит on-chain историю пула → `(leaf_index, commitment)` по возрастанию
/// листа. Замена anchor-индексера: парсит `tidex6-wpool-deposit:<leaf>:<commit>:<root>`
/// из логов транзакций пула. Дерево, собранное вставкой в этом порядке, даёт
/// корень = текущий on-chain корень (он в ring-buffer пула).
pub async fn fetch_deposit_history(rpc: &RpcClient) -> Result<Vec<(u64, [u8; 32])>> {
    let pool = pool_pda();
    let mut records: Vec<(u64, [u8; 32])> = Vec::new();
    let mut before: Option<Signature> = None;

    loop {
        let cfg = GetConfirmedSignaturesForAddress2Config {
            before,
            until: None,
            limit: Some(1000),
            commitment: Some(CommitmentConfig::confirmed()),
        };
        let page = rpc
            .get_signatures_for_address_with_config(&pool, cfg)
            .await
            .context("get_signatures_for_address")?;
        if page.is_empty() {
            break;
        }
        let oldest = page.last().map(|e| e.signature.clone());
        for entry in &page {
            if entry.err.is_some() {
                continue;
            }
            let sig = Signature::from_str(&entry.signature).context("signature parse")?;
            if let Some(rec) = fetch_and_parse_deposit(rpc, &sig).await? {
                records.push(rec);
            }
        }
        let page_len = page.len();
        match oldest {
            Some(s) => before = Some(Signature::from_str(&s).context("before parse")?),
            None => break,
        }
        if page_len < 1000 {
            break;
        }
    }

    records.sort_by_key(|(leaf, _)| *leaf);
    records.dedup_by_key(|(leaf, _)| *leaf);
    Ok(records)
}

async fn fetch_and_parse_deposit(
    rpc: &RpcClient,
    sig: &Signature,
) -> Result<Option<(u64, [u8; 32])>> {
    let cfg = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };
    let tx = rpc
        .get_transaction_with_config(sig, cfg)
        .await
        .context("get_transaction")?;
    let Some(meta) = tx.transaction.meta.as_ref() else {
        return Ok(None);
    };
    let logs = match &meta.log_messages {
        OptionSerializer::Some(logs) => logs,
        _ => return Ok(None),
    };
    Ok(parse_deposit_log(logs))
}

/// Парсит `Program log: tidex6-wpool-deposit:<leaf>:<commitment_hex>:<root_hex>`.
fn parse_deposit_log(logs: &[String]) -> Option<(u64, [u8; 32])> {
    const PREFIX: &str = "Program log: tidex6-wpool-deposit:";
    for line in logs {
        let Some(payload) = line.strip_prefix(PREFIX) else {
            continue;
        };
        let parts: Vec<&str> = payload.split(':').collect();
        if parts.len() < 2 {
            continue;
        }
        let leaf = parts[0].trim().parse::<u64>().ok()?;
        let commitment = hex32(parts[1].trim())?;
        return Some((leaf, commitment));
    }
    None
}

/// Декодирует ровно 64 hex-символа в [u8;32].
fn hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Собирает, подписывает payer'ом и отправляет одну инструкцию; ждёт confirmed.
pub async fn send_ix(rpc: &RpcClient, payer: &Keypair, ix: Instruction) -> Result<String> {
    let blockhash = rpc
        .get_latest_blockhash()
        .await
        .context("latest blockhash")?;
    let tx = Transaction::new_signed_with_payer(
        &[ix],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    let sig = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .context("send transaction")?;
    Ok(sig.to_string())
}
