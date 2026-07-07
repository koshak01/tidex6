//! deposit в verify-only wUSDC-пул: генерит ноту, кладёт commitment в дерево.
//!
//! Groth16-слой (связь). Отдельно от этого пользователь конфиденциально
//! переводит wUSDC в pool-CT-account (ct-lab) — это слой суммы. Здесь только
//! commitment = Poseidon(secret, nullifier) → дерево + memo-аккаунт (ADR-014).
//! Нота (secret, nullifier, amount) сохраняется в ~/.tidex6-wusdc/note-*.json —
//! из неё потом withdraw на свежий адрес (связь разорвана). Сумма (в micro-USDC)
//! кладётся в ноту, чтобы payout совпал с депозитом. В commitment суммы нет
//! (ADR-001) — в custodial-MVP её задаёт оператор, криптопривязки нет.
//!
//! Запуск: cargo run -p tidex6-wusdc-cli --bin deposit -- <amount-USDC>  (дефолт 2)

use std::rc::Rc;

use anchor_client::{Client, Cluster, CommitmentConfig, Signer};
use anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result};
use solana_keypair::read_keypair_file;
use tidex6_core::types::{Commitment, Nullifier, Secret};
use tidex6_wusdc_pool::accounts as wp_accounts;
use tidex6_wusdc_pool::instruction as wp_instruction;

/// Минимальный memo-заглушка для теста связи (реальный ML-KEM конверт —
/// в браузерном flow). Просто чтобы memo-аккаунт создался.
const MEMO_LEN: u32 = 32;
const REVOKE_WINDOW: i64 = 600; // 10 минут

fn main() -> Result<()> {
    let (rpc, ws, keypair_path) = load_cli_config()?;
    let payer =
        Rc::new(read_keypair_file(&keypair_path).map_err(|e| anyhow::anyhow!("keypair: {e}"))?);
    let program_id: Pubkey = tidex6_wusdc_pool::ID;

    // Сумма депозита (micro-USDC) — из первого аргумента, дефолт 2.
    let amount_micro = amount_arg_to_micro();

    // ── Нота ─────────────────────────────────────────────────────────
    let secret = Secret::random().context("secret")?;
    let nullifier = Nullifier::random().context("nullifier")?;
    let commitment = Commitment::derive(&secret, &nullifier).context("commitment")?;
    let commitment_bytes = commitment.to_bytes();

    println!("payer:      {}", payer.pubkey());
    println!("сумма:      {} USDC", amount_micro as f64 / 1e6);
    println!("commitment: {}", hex(&commitment_bytes));

    let client = Client::new_with_options(
        Cluster::Custom(rpc, ws),
        payer.clone(),
        CommitmentConfig::confirmed(),
    );
    let program = client.program(program_id)?;
    let (pool_pda, _) = Pubkey::find_program_address(&[b"wusdc-pool"], &program_id);
    let (memo_pda, _) = Pubkey::find_program_address(&[b"memo", &commitment_bytes], &program_id);

    println!("\nкладу commitment в дерево пула…");
    let sig = program
        .request()
        .accounts(wp_accounts::Deposit {
            pool: pool_pda,
            memo: memo_pda,
            payer: payer.pubkey(),
            system_program: anchor_lang::system_program::ID,
        })
        .args(wp_instruction::Deposit {
            commitment: commitment_bytes,
            memo_total_len: MEMO_LEN,
            revoke_window: REVOKE_WINDOW,
            memo_chunk: vec![0u8; MEMO_LEN as usize],
        })
        .send()
        .context("deposit не подтвердился")?;

    // ── Сохранить ноту ───────────────────────────────────────────────
    let home = std::env::var("HOME").context("нет $HOME")?;
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let dir = format!("{home}/.tidex6-wusdc");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .context("создать ~/.tidex6-wusdc")?;
    let note_path = format!("{dir}/note-{}.json", hex(&commitment_bytes[..8]));
    let note_json = format!(
        "{{\n  \"secret\": \"{}\",\n  \"nullifier\": \"{}\",\n  \"commitment\": \"{}\",\n  \"amount\": {}\n}}\n",
        hex(secret.as_bytes()),
        hex(nullifier.as_bytes()),
        hex(&commitment_bytes),
        amount_micro
    );
    // Owner-only (0600): secret/nullifier — spend-material, как приватный ключ.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&note_path)
        .context("создать файл ноты (0600)")?;
    f.write_all(note_json.as_bytes()).context("записать ноту")?;

    println!("\n═══ DEPOSIT ГОТОВ ═══");
    println!("tx:      {sig}");
    println!("Solscan: https://solscan.io/tx/{sig}");
    println!("нота:    {note_path}");
    println!("\nТеперь withdraw по этой ноте выведет на свежий адрес — связь разорвана.");
    Ok(())
}

/// Первый аргумент — сумма в USDC ("1", "0.5"); в micro-единицы (1e6). Дефолт 2.
fn amount_arg_to_micro() -> u64 {
    std::env::args()
        .nth(1)
        .as_deref()
        .and_then(parse_decimal_micro)
        .unwrap_or(2_000_000)
}

/// "1" → 1_000_000, "0.5" → 500_000. Без f64. None если не число.
fn parse_decimal_micro(s: &str) -> Option<u64> {
    let s = s.trim();
    let (int_part, frac_part) = s.split_once('.').unwrap_or((s, ""));
    if !int_part.chars().all(|c| c.is_ascii_digit())
        || !frac_part.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let int: u64 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().ok()?
    };
    let mut frac_padded = frac_part.to_string();
    while frac_padded.len() < 6 {
        frac_padded.push('0');
    }
    let frac: u64 = frac_padded.get(..6)?.parse().ok()?;
    int.checked_mul(1_000_000)?.checked_add(frac)
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
