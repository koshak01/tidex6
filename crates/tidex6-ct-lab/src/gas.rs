//! Автономный газ оператора: комиссия платежа меняется на SOL через Jupiter.
//!
//! Оператор платит газ за каждый депозит. Пока его SOL ниже порога
//! (`GasKeeper::target_lamports`), комиссия очередного платежа не запечатывается
//! в казну, а остаётся открытым USDC на счёте оператора и тут же меняется на
//! SOL. Порог достигнут — комиссии снова уходят в казну приватной нотой.
//!
//! Транзакцию обмена собирает Jupiter, а подписывает ключ оператора — тот же,
//! что держит право выпуска обёрточного токена. Поэтому присланная транзакция
//! проверяется ДО подписи: только ожидаемые программы и инструкции, одна
//! подпись, оплата — оператором, приоритетная комиссия под потолком.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::nonblocking::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

use crate::config::GasKeeper;

/// Обёрнутый SOL: выход обмена, Jupiter разворачивает его в SOL сам.
const WSOL_MINT: &str = "So11111111111111111111111111111111111111112";

const COMPUTE_BUDGET: Pubkey =
    Pubkey::from_str_const("ComputeBudget111111111111111111111111111111");
const ASSOCIATED_TOKEN: Pubkey =
    Pubkey::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
const SPL_TOKEN: Pubkey = Pubkey::from_str_const("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
const JUPITER_V6: Pubkey = Pubkey::from_str_const("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");

/// Потолок приоритетной комиссии, который просим у Jupiter и проверяем сами.
const MAX_PRIORITY_LAMPORTS: u64 = 100_000;

/// Нужен ли оператору газ: SOL ниже порога сторожа.
///
/// # Возвращает
/// * `Result<bool>` — `true`, если комиссию этого платежа стоит обменять на SOL
pub async fn is_gas_low(rpc: &RpcClient, payer: &Keypair, keeper: &GasKeeper) -> Result<bool> {
    let balance = rpc
        .get_balance(&payer.pubkey())
        .await
        .context("баланс SOL оператора")?;
    Ok(balance < keeper.target_lamports)
}

/// Меняет `amount_micro` токена `input_mint` со счёта оператора на SOL.
///
/// 1. Котировка Jupiter с проскальзыванием `keeper.slippage_bps`.
/// 2. Jupiter собирает транзакцию под ключ оператора.
/// 3. Транзакция проверяется (`check_swap_tx`) и только потом подписывается.
///
/// # Параметры
/// * `input_mint` — открытый USDC/USDT, в котором удержана комиссия
/// * `amount_micro` — сколько менять, в минимальных единицах токена
///
/// # Возвращает
/// * `Result<(String, u64)>` — подпись транзакции и котировка в лампортах
pub async fn swap_to_sol(
    rpc: &RpcClient,
    payer: &Keypair,
    keeper: &GasKeeper,
    input_mint: &str,
    amount_micro: u64,
) -> Result<(String, u64)> {
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(20))
        .build()
        .context("http-клиент")?;
    let quote = fetch_quote(&http, keeper, input_mint, amount_micro).await?;
    let out_lamports: u64 = quote["outAmount"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| anyhow!("котировка Jupiter без outAmount"))?;
    let unsigned = fetch_swap_tx(&http, keeper, &quote, &payer.pubkey()).await?;
    check_swap_tx(&unsigned, &payer.pubkey())?;
    let signed = VersionedTransaction::try_new(unsigned.message, &[payer])
        .map_err(|e| anyhow!("подпись обмена: {e}"))?;
    let sig = rpc
        .send_and_confirm_transaction(&signed)
        .await
        .context("отправка обмена")?;
    Ok((sig.to_string(), out_lamports))
}

/// Котировка Jupiter: `amount_micro` входного токена в SOL, точный вход.
async fn fetch_quote(
    http: &reqwest::Client,
    keeper: &GasKeeper,
    input_mint: &str,
    amount_micro: u64,
) -> Result<serde_json::Value> {
    let url = format!(
        "{}/quote?inputMint={input_mint}&outputMint={WSOL_MINT}&amount={amount_micro}\
         &slippageBps={}&restrictIntermediateTokens=true",
        keeper.jupiter_url.trim_end_matches('/'),
        keeper.slippage_bps
    );
    let response = http.get(&url).send().await.context("котировка Jupiter")?;
    if !response.status().is_success() {
        bail!("котировка Jupiter: HTTP {}", response.status());
    }
    let body = response.bytes().await.context("тело котировки")?;
    serde_json::from_slice(&body).context("котировка Jupiter не JSON")
}

/// Jupiter собирает неподписанную транзакцию обмена по котировке.
async fn fetch_swap_tx(
    http: &reqwest::Client,
    keeper: &GasKeeper,
    quote: &serde_json::Value,
    operator: &Pubkey,
) -> Result<VersionedTransaction> {
    let request = serde_json::json!({
        "quoteResponse": quote,
        "userPublicKey": operator.to_string(),
        "wrapAndUnwrapSol": true,
        "dynamicComputeUnitLimit": true,
        "prioritizationFeeLamports": {
            "priorityLevelWithMaxLamports": {
                "maxLamports": MAX_PRIORITY_LAMPORTS,
                "priorityLevel": "medium"
            }
        }
    });
    let url = format!("{}/swap", keeper.jupiter_url.trim_end_matches('/'));
    let response = http
        .post(&url)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(&request)?)
        .send()
        .await
        .context("сборка обмена в Jupiter")?;
    if !response.status().is_success() {
        bail!("сборка обмена: HTTP {}", response.status());
    }
    let body: serde_json::Value =
        serde_json::from_slice(&response.bytes().await.context("тело обмена")?)
            .context("ответ обмена не JSON")?;
    let encoded = body["swapTransaction"]
        .as_str()
        .ok_or_else(|| anyhow!("ответ Jupiter без swapTransaction"))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("swapTransaction не base64")?;
    bincode::deserialize(&raw).context("swapTransaction не разбирается")
}

/// Проверка транзакции Jupiter до подписи ключом оператора.
///
/// Разрешено ровно то, из чего Jupiter собирает обмен в SOL:
/// бюджет вычислений, создание своего ATA, маршрут Jupiter и закрытие
/// временного счёта обёрнутого SOL в пользу оператора. Любая другая программа
/// (System, Token-2022, чужие) — отказ: ключ оператора держит право выпуска
/// обёрточного токена, и подписывать непроверенное им нельзя.
fn check_swap_tx(tx: &VersionedTransaction, operator: &Pubkey) -> Result<()> {
    let message = &tx.message;
    let keys = message.static_account_keys();
    if keys.first() != Some(operator) {
        bail!("обмен оплачивает не оператор");
    }
    if message.header().num_required_signatures != 1 {
        bail!("обмен требует чужих подписей");
    }
    let mut unit_limit: u64 = 0;
    let mut unit_price: u64 = 0;
    for instruction in message.instructions() {
        let program = keys
            .get(instruction.program_id_index as usize)
            .ok_or_else(|| anyhow!("программа вне списка ключей"))?;
        let data = instruction.data.as_slice();
        if *program == COMPUTE_BUDGET {
            match data {
                [2, rest @ ..] if rest.len() == 4 => {
                    unit_limit = u32::from_le_bytes(rest.try_into()?) as u64;
                }
                [3, rest @ ..] if rest.len() == 8 => {
                    unit_price = u64::from_le_bytes(rest.try_into()?);
                }
                _ => bail!("неожиданная инструкция бюджета вычислений"),
            }
        } else if *program == ASSOCIATED_TOKEN && data == [1] || *program == JUPITER_V6 {
        } else if *program == SPL_TOKEN && data == [9] {
            let destination = instruction
                .accounts
                .get(1)
                .and_then(|index| keys.get(*index as usize));
            if destination != Some(operator) {
                bail!("закрытие счёта не в пользу оператора");
            }
        } else {
            bail!("инструкция вне белого списка: программа {program}");
        }
    }
    let priority_lamports = unit_limit.saturating_mul(unit_price) / 1_000_000;
    if priority_lamports > MAX_PRIORITY_LAMPORTS {
        bail!("приоритетная комиссия {priority_lamports} выше потолка");
    }
    Ok(())
}
