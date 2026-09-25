//! Разговор с EVM-узлом и подпись транзакций своим ключом.
//!
//! Блокирующий, как весь `tidex6-client`: вызывающий (MCP) и так держит
//! тяжёлую работу в отдельном потоке ОС. Вызовов немного, и все они ручные —
//! `eth_call`, `eth_sendRawTransaction`, квитанция. Калдата собирается руками,
//! как у страницы: так видно байт в байт, что уходит в пул.

use std::time::{Duration, Instant};

use alloy::consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy::eips::eip2718::Encodable2718;
use alloy::primitives::{Bytes, TxKind, U256};
use alloy::signers::SignerSync;
use anyhow::{Context, Result, bail};

/// Ключ EVM и адрес — те типы, которыми пользуются вызывающие (MCP): им не
/// нужна своя зависимость на alloy ради двух имён.
pub use alloy::primitives::Address;
pub use alloy::signers::local::PrivateKeySigner;
use serde_json::{Value, json};

/// Сколько ждать квитанцию. Arbitrum и Arc отвечают за секунды; три минуты —
/// запас на перегруженный тестнет, а не норма.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(180);
const RECEIPT_POLL: Duration = Duration::from_secs(2);

/// Узел одной цепи.
pub struct Node {
    url: String,
    http: reqwest::blocking::Client,
}

impl Node {
    pub fn new(url: &str) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            // Без таймаута первый сетевой сбой вешает агента навсегда.
            .timeout(Duration::from_secs(60))
            .build()
            .context("http client")?;
        Ok(Self {
            url: url.to_string(),
            http,
        })
    }

    /// Один вызов JSON-RPC. Ответ с `error` — ошибка с текстом узла.
    pub fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let reply: Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .with_context(|| format!("{method}: {} did not answer", self.url))?
            .json()
            .with_context(|| format!("{method}: unreadable answer"))?;
        if let Some(error) = reply.get("error") {
            bail!("{method}: {error}");
        }
        Ok(reply.get("result").cloned().unwrap_or(Value::Null))
    }

    /// `eth_call` на последнем блоке; ответ — байты.
    pub fn eth_call(&self, to: &str, data: &[u8]) -> Result<Vec<u8>> {
        let out = self.call(
            "eth_call",
            json!([{ "to": to, "data": format!("0x{}", hex::encode(data)) }, "latest"]),
        )?;
        decode_hex(&out)
    }

    /// Число из шестнадцатеричной строки ответа.
    pub fn quantity(&self, method: &str, params: Value) -> Result<u128> {
        let out = self.call(method, params)?;
        let text = out.as_str().context("expected a hex quantity")?;
        u128::from_str_radix(text.trim_start_matches("0x"), 16).context("hex quantity")
    }

    /// Логи по фильтру — как их отдаёт `eth_getLogs`.
    pub fn logs(&self, filter: Value) -> Result<Vec<Value>> {
        match self.call("eth_getLogs", json!([filter]))? {
            Value::Array(items) => Ok(items),
            other => bail!("eth_getLogs: expected a list, got {other}"),
        }
    }
}

/// Один вызов контракта от нашего кошелька.
pub struct Call<'a> {
    pub to: &'a str,
    pub data: Vec<u8>,
}

/// Подписать вызов своим ключом, отправить и дождаться квитанции.
///
/// Газ оценивает узел, плюс запас в пятую часть: оценка делается на текущем
/// состоянии, а к включению в блок дерево пула может подрасти на лист.
/// Откатившаяся транзакция — ошибка с её хешем: газ за неё уже заплачен, и
/// человек должен это увидеть, а не «не вышло».
///
/// # Возвращает
/// * `Result<String>` — хеш включённой транзакции `0x…`
pub fn send_call(
    node: &Node,
    signer: &PrivateKeySigner,
    chain_id: u64,
    call: &Call,
) -> Result<String> {
    let from = format!("{:#x}", signer.address());
    let to: Address = call.to.parse().context("contract address")?;
    let data = format!("0x{}", hex::encode(&call.data));
    let gas = node
        .quantity(
            "eth_estimateGas",
            json!([{ "from": from, "to": call.to, "data": data }]),
        )
        .context("the node refused the call before it was sent — nothing was spent")?;
    let nonce = node.quantity("eth_getTransactionCount", json!([from, "pending"]))?;
    let (max_fee, priority) = fees(node)?;
    let tx = TxEip1559 {
        chain_id,
        nonce: u64::try_from(nonce).context("nonce")?,
        gas_limit: u64::try_from(gas + gas / 5).context("gas")?,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: priority,
        to: TxKind::Call(to),
        value: U256::ZERO,
        input: Bytes::from(call.data.clone()),
        access_list: Default::default(),
    };
    let signature = signer
        .sign_hash_sync(&tx.signature_hash())
        .context("sign the transaction")?;
    let raw = TxEnvelope::from(tx.into_signed(signature)).encoded_2718();
    let hash = node.call(
        "eth_sendRawTransaction",
        json!([format!("0x{}", hex::encode(raw))]),
    )?;
    let hash = hash.as_str().context("no transaction hash")?.to_string();
    wait_receipt(node, &hash)?;
    Ok(hash)
}

/// Плата за газ: базовая плата последнего блока вдвое плюс чаевые узла.
fn fees(node: &Node) -> Result<(u128, u128)> {
    let block = node.call("eth_getBlockByNumber", json!(["latest", false]))?;
    let base = block
        .get("baseFeePerGas")
        .and_then(Value::as_str)
        .map(|v| u128::from_str_radix(v.trim_start_matches("0x"), 16))
        .transpose()
        .context("baseFeePerGas")?
        .unwrap_or(0);
    // Не у каждого узла есть `eth_maxPriorityFeePerGas`; ноль чаевых на
    // L2 — нормальная ставка.
    let priority = node
        .quantity("eth_maxPriorityFeePerGas", json!([]))
        .unwrap_or(0);
    Ok((base * 2 + priority, priority))
}

fn wait_receipt(node: &Node, hash: &str) -> Result<()> {
    let started = Instant::now();
    loop {
        let receipt = node.call("eth_getTransactionReceipt", json!([hash]))?;
        if let Some(status) = receipt.get("status").and_then(Value::as_str) {
            if status == "0x1" {
                return Ok(());
            }
            bail!("transaction {hash} was mined but reverted; its gas is spent");
        }
        if started.elapsed() > RECEIPT_TIMEOUT {
            bail!(
                "transaction {hash} was sent but not mined within {} s — check it in the explorer before sending again",
                RECEIPT_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(RECEIPT_POLL);
    }
}

fn decode_hex(value: &Value) -> Result<Vec<u8>> {
    let text = value.as_str().context("expected hex bytes")?;
    hex::decode(text.trim_start_matches("0x")).context("hex bytes")
}

/// Разобрать ключ EVM из файла: `0x…` или голый hex, с переводом строки или
/// без. Сам ключ в ошибку не попадает.
pub fn signer_from_file(path: &std::path::Path) -> Result<PrivateKeySigner> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("no EVM key at {}", path.display()))?;
    raw.trim()
        .parse::<PrivateKeySigner>()
        .map_err(|_| anyhow::anyhow!("{}: not an EVM private key", path.display()))
}
