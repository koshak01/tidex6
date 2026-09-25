//! Платёж в пул со скрытой суммой своим ключом — то, что делает страница
//! отправки, только без кошелька в браузере.
//!
//! 1. ключ получателя берётся из реестра читателей этой цепи — между людьми
//!    ходит только адрес кошелька;
//! 2. запечатываются две ноты: платёж получателю и 1% комиссии казне;
//! 3. `approve` ровно на сумму платежа с комиссией, если разрешения не хватает;
//! 4. пул с `depositWithFee` принимает обе ноты одним вызовом, прежний — двумя.
//!
//! Сервис при этом не нужен вовсе: подпись своя, газ свой, пул принимает
//! депозит от любого. Что видно на цепи: кошелёк отправителя, общая сумма и
//! два commitment'а. Получатель, назначение и деление на платёж и комиссию
//! скрыты в конвертах.

use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result, bail};
use serde_json::json;
use tidex6_core::envelope::ReaderAddress;

use super::note::{SealedNote, fee_micro, seal_note};
use super::pools::EvmPool;
use super::rpc::{Call, Node, send_call};

/// Публичный адрес казны (`mlkem_pk ‖ x25519_pk`): ей запечатывается каждая
/// нота комиссии. Тот же, что у страницы (`EVM_FEE_TREASURY_HEX`) и в
/// `fee_treasury_evm` релеера — расхождение делит комиссии между двумя казнами.
pub const FEE_TREASURY_HEX: &str = include_str!("fee_treasury.hex");

const SEL_APPROVE: [u8; 4] = [0x09, 0x5e, 0xa7, 0xb3];
const SEL_ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];
const SEL_BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
/// `deposit(uint256,uint256,bytes)` — пул со скрытой суммой.
const SEL_DEPOSIT: [u8; 4] = [0xaa, 0x0b, 0x7d, 0xb7];
/// `depositWithFee(uint256,uint256,bytes,uint256,uint256,bytes)`.
const SEL_DEPOSIT_WITH_FEE: [u8; 4] = [0x2d, 0x2c, 0x16, 0x76];
/// `readerOf(address)` → `(bytes32 keyHash, uint256 version, uint256 publishedAt)`.
const SEL_READER_OF: [u8; 4] = [0x7d, 0xd5, 0xe9, 0x36];
/// `matchesPublished(address,bytes)` → `bool`.
const SEL_MATCHES_PUBLISHED: [u8; 4] = [0x47, 0x8b, 0xca, 0x76];
/// Событие публикации ключа: `(uint8 version, bytes reader)`, кошелёк — topic 1.
const READER_TOPIC: &str = "0xd12367693aa39a08dfee4900a4173fa2e695c4d2650b525866a0798a0f0eb36b";
/// ML-KEM-768 (1184) плюс x25519 (32).
const READER_LEN: usize = 1216;

/// Чем кончился платёж.
#[derive(Debug)]
pub struct EvmPayment {
    /// Транзакции по порядку: `approve` (если был), депозит(ы).
    pub transactions: Vec<String>,
    /// Commitment платежа — единственное, что увидит наблюдатель о получателе.
    pub commitment_hex: String,
    pub amount_micro: u64,
    pub fee_micro: u64,
}

/// Адрес читателя, опубликованный кошельком в реестре этой цепи.
///
/// # Возвращает
/// * `Ok(None)` — кошелёк ключа не публиковал, платить ему пока нельзя
/// * `Ok(Some(_))` — ключ, подтверждённый самим контрактом: узел может
///   ошибаться или лгать, а контракт сверяет хеш ключа сам
pub fn lookup_reader(pool: &EvmPool, wallet: &str) -> Result<Option<ReaderAddress>> {
    let node = Node::new(pool.read_url)?;
    let wallet_word = address_word(wallet)?;
    let meta = node.eth_call(pool.registry, &[&SEL_READER_OF[..], &wallet_word].concat())?;
    if meta.len() < 96 || meta[..32].iter().all(|b| *b == 0) {
        return Ok(None);
    }
    let published_at = u64::from_be_bytes(meta[88..96].try_into().context("block")?);
    let Some(reader) = reader_from_logs(&node, pool, &wallet_word, published_at)? else {
        return Ok(None);
    };
    let check = [
        &SEL_MATCHES_PUBLISHED[..],
        &wallet_word,
        &word_u128(64),
        &encode_bytes(&reader),
    ]
    .concat();
    let answer = node.eth_call(pool.registry, &check)?;
    if answer.last() != Some(&1) {
        return Ok(None);
    }
    ReaderAddress::from_bytes(&reader)
        .map(Some)
        .context("the published key does not parse")
}

/// Байты ключа из события публикации: блок известен точно, спрашивается
/// ровно он — запрос по всей истории упирается в пределы узла и выглядит как
/// «ключа нет».
fn reader_from_logs(
    node: &Node,
    pool: &EvmPool,
    wallet_word: &[u8; 32],
    block: u64,
) -> Result<Option<Vec<u8>>> {
    let block_hex = format!("{block:#x}");
    let logs = node.logs(json!({
        "address": pool.registry,
        "fromBlock": block_hex,
        "toBlock": block_hex,
        "topics": [READER_TOPIC, format!("0x{}", hex::encode(wallet_word))],
    }))?;
    let Some(last) = logs.last() else {
        return Ok(None);
    };
    let data = hex::decode(
        last.get("data")
            .and_then(|v| v.as_str())
            .context("log data")?
            .trim_start_matches("0x"),
    )?;
    // (uint8 version, bytes reader): версия, смещение, длина, байты.
    if data.len() < 96 + READER_LEN {
        return Ok(None);
    }
    let len = usize::try_from(u64::from_be_bytes(data[88..96].try_into()?))?;
    if len != READER_LEN {
        return Ok(None);
    }
    Ok(Some(data[96..96 + READER_LEN].to_vec()))
}

/// `publishReader(uint8,bytes)`.
const SEL_PUBLISH_READER: [u8; 4] = [0x10, 0x6c, 0x9a, 0x44];
/// Версия личности, которую публикует и страница (`IDENTITY_VERSION`).
const IDENTITY_VERSION: u128 = 2;

/// Опубликовать свой адрес читателя в реестре цепи — после этого кошельку
/// можно платить по его адресу `0x…`.
///
/// Уже опубликованный тот же ключ повторно не пишется: запись стоит газа, а
/// контракт сам сверяет хеш ключа.
///
/// # Возвращает
/// * `Ok(None)` — ключ уже опубликован, транзакции не было
/// * `Ok(Some(hash))` — хеш транзакции публикации
pub fn publish_reader(
    pool: &EvmPool,
    signer: &PrivateKeySigner,
    reader: &ReaderAddress,
) -> Result<Option<String>> {
    let me = format!("{:#x}", signer.address());
    let reader_bytes = reader.to_bytes();
    let read = Node::new(pool.read_url)?;
    let check = [
        &SEL_MATCHES_PUBLISHED[..],
        &address_word(&me)?,
        &word_u128(64),
        &encode_bytes(&reader_bytes),
    ]
    .concat();
    if read.eth_call(pool.registry, &check)?.last() == Some(&1) {
        return Ok(None);
    }
    let data = [
        &SEL_PUBLISH_READER[..],
        &word_u128(IDENTITY_VERSION),
        &word_u128(64),
        &encode_bytes(&reader_bytes),
    ]
    .concat();
    let call = Call {
        to: pool.registry,
        data,
    };
    let send = Node::new(pool.send_url)?;
    send_call(&send, signer, pool.chain_id, &call).map(Some)
}

/// Заплатить получателю в пул.
///
/// # Параметры
/// * `pool` — пул, в который идёт платёж; прежняя версия пула — отказ
/// * `signer` — ключ отправителя; с него списывается сумма и газ
/// * `recipient` — адрес читателя получателя (см. [`lookup_reader`])
/// * `auditors` — кому раскрыть сумму и назначение
/// * `amount_micro` — сколько получит адресат; комиссия сверху
/// * `memo` — назначение
///
/// Баланс проверяется до первой подписи: нехватка, найденная после
/// `approve`, — это потраченный газ без платежа.
pub fn pay(
    pool: &EvmPool,
    signer: &PrivateKeySigner,
    recipient: &ReaderAddress,
    auditors: &[ReaderAddress],
    amount_micro: u64,
    memo: &str,
) -> Result<EvmPayment> {
    if pool.is_withdraw_only {
        bail!("{} is an earlier pool kept for withdrawals only", pool.name);
    }
    if amount_micro == 0 {
        bail!("the amount must be greater than zero");
    }
    let fee = fee_micro(amount_micro);
    let units = pool.base_units_per_micro();
    let payment = seal_note(recipient, auditors, amount_micro, units, memo)?;
    let fee_note = seal_note(&treasury()?, &[], fee, units, "fee")?;
    let total = u128::from(payment.amount) + u128::from(fee_note.amount);

    let read = Node::new(pool.read_url)?;
    let send = Node::new(pool.send_url)?;
    let me = format!("{:#x}", signer.address());
    ensure_balance(&read, pool, &me, total)?;

    let mut transactions = Vec::new();
    if allowance(&read, pool, &me)? < total {
        transactions.push(send_call(
            &send,
            signer,
            pool.chain_id,
            &approve(pool, total)?,
        )?);
    }
    for call in deposits(pool, &payment, &fee_note) {
        transactions.push(send_call(&send, signer, pool.chain_id, &call)?);
    }
    Ok(EvmPayment {
        transactions,
        commitment_hex: hex::encode(payment.commitment),
        amount_micro,
        fee_micro: fee,
    })
}

fn treasury() -> Result<ReaderAddress> {
    let bytes = hex::decode(FEE_TREASURY_HEX.trim()).context("treasury address hex")?;
    ReaderAddress::from_bytes(&bytes).context("treasury address")
}

fn ensure_balance(node: &Node, pool: &EvmPool, me: &str, total: u128) -> Result<()> {
    let data = [&SEL_BALANCE_OF[..], &address_word(me)?].concat();
    let balance = word_to_u128(&node.eth_call(pool.token, &data)?)?;
    if balance < total {
        bail!(
            "not enough {} on {}: have {} base units, the payment with its fee is {} — nothing was sent",
            pool.token_symbol,
            pool.name,
            balance,
            total
        );
    }
    Ok(())
}

fn allowance(node: &Node, pool: &EvmPool, me: &str) -> Result<u128> {
    let data = [
        &SEL_ALLOWANCE[..],
        &address_word(me)?,
        &address_word(pool.hidden_pool)?,
    ]
    .concat();
    word_to_u128(&node.eth_call(pool.token, &data)?)
}

/// Разрешение ровно на этот платёж — никогда не бессрочное.
fn approve(pool: &EvmPool, total: u128) -> Result<Call<'static>> {
    let data = [
        &SEL_APPROVE[..],
        &address_word(pool.hidden_pool)?,
        &word_u128(total),
    ]
    .concat();
    Ok(Call {
        to: pool.token,
        data,
    })
}

/// Депозит(ы): один вызов с обеими нотами, где пул это умеет, иначе два.
fn deposits(pool: &EvmPool, payment: &SealedNote, fee: &SealedNote) -> Vec<Call<'static>> {
    if pool.has_deposit_with_fee {
        let first = encode_bytes(&payment.envelope);
        let second = encode_bytes(&fee.envelope);
        let data = [
            &SEL_DEPOSIT_WITH_FEE[..],
            &word_u128(u128::from(payment.amount)),
            &payment.commitment,
            &word_u128(192),
            &word_u128(u128::from(fee.amount)),
            &fee.commitment,
            &word_u128(192 + first.len() as u128),
            &first,
            &second,
        ]
        .concat();
        return vec![Call {
            to: pool.hidden_pool,
            data,
        }];
    }
    [payment, fee]
        .into_iter()
        .map(|note| Call {
            to: pool.hidden_pool,
            data: [
                &SEL_DEPOSIT[..],
                &word_u128(u128::from(note.amount)),
                &note.commitment,
                &word_u128(96),
                &encode_bytes(&note.envelope),
            ]
            .concat(),
        })
        .collect()
}

/// ABI `bytes` в хвосте: длина словом и данные, дополненные до 32 байт.
fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let padded = data.len().div_ceil(32) * 32;
    let mut out = word_u128(data.len() as u128).to_vec();
    out.extend_from_slice(data);
    out.resize(32 + padded, 0);
    out
}

fn word_u128(value: u128) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[16..].copy_from_slice(&value.to_be_bytes());
    word
}

fn word_to_u128(bytes: &[u8]) -> Result<u128> {
    if bytes.len() < 32 || bytes[..16].iter().any(|b| *b != 0) {
        bail!("the token answered a value that is not a 128-bit amount");
    }
    Ok(u128::from_be_bytes(bytes[16..32].try_into()?))
}

/// Адрес `0x…` как 32-байтное слово ABI.
pub(crate) fn address_word(address: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(address.trim().trim_start_matches("0x"))
        .with_context(|| format!("{address} is not an EVM address"))?;
    let bytes: [u8; 20] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{address} is not an EVM address"))?;
    Ok(super::note::address_word(bytes))
}
