//! Поиск своих платежей в цепочке — целиком на своей машине.
//!
//! Оператор здесь не участвует и участвовать не может: конверты лежат в
//! открытых аккаунтах пула, их читает кто угодно, а открыть их может только
//! тот, кому они адресованы.
//!
//! **Забираем все конверты — и это защита, а не расточительность.** Спросив у
//! ноды «мои платежи», мы бы сообщили ей, кто мы такие, и вся приватность
//! кончилась бы на этом запросе. Спрашивая все, мы не сообщаем ничего.
//!
//! **Расшифровывать при этом каждый не приходится.** В каждом слоте лежит
//! однобайтовый view-tag с эфемерным X25519-ключом (ADR-014 + roadmap A4):
//! читатель считает один scalar-mult, сравнивает байт и отбрасывает ~255 слотов
//! из 256, не притрагиваясь к ML-KEM. Это существенно, потому что у ML-KEM
//! дешёвого «моё ли это» нет вовсе — там нужна полная декапсуляция, и наивный
//! скан ста тысяч конвертов занял бы сотни секунд.
//!
//! Фильтрация живёт внутри `tidex6_core::envelope`, здесь её повторять не надо
//! — и не следует: два места, считающие тег по-своему, однажды разойдутся.

use anchor_client::anchor_lang::prelude::Pubkey;
use anyhow::{Context, Result};
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcProgramAccountsConfig;
use solana_rpc_client_api::filter::{Memcmp, RpcFilterType};

use super::local::LocalIdentity;

/// Платёж, найденный своим ключом.
#[derive(Debug)]
pub struct FoundPayment {
    /// Хеш, под которым платёж лежит в дереве.
    pub commitment: [u8; 32],
    /// Сумма в микро-единицах — до расшифровки её не знал никто.
    pub amount_micro: u64,
    /// Назначение, как его написал отправитель.
    pub memo: String,
    /// Кто оплатил ренту за аккаунт конверта.
    ///
    /// **Не отправитель платежа.** В нашем потоке аккаунт открывает оператор,
    /// и принимать это поле за «от кого пришло» — ошибка, которая выглядит
    /// правдоподобно. Оставлено как техническая деталь, а не как атрибуция.
    pub rent_payer: Pubkey,
    /// До какого момента отправитель может вернуть платёж себе.
    pub revoke_deadline_unix: i64,
}

/// Что мы нашли и чем открывали.
#[derive(Debug)]
pub struct ScanReport {
    /// Сколько конвертов лежит в пуле всего.
    pub envelopes_seen: usize,
    /// Сколько открылось нашим ключом.
    pub payments: Vec<FoundPayment>,
}

/// Роль, в которой читаем.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadAs {
    /// Получатель: открывается материал траты — платёж можно забрать.
    Recipient,
    /// Аудитор: открывается сумма и назначение, материала траты там нет.
    ///
    /// Это разделение живёт в шифротексте, а не в правиле, которое кто-то
    /// обещает соблюдать.
    Auditor,
}

/// Найти в пуле платежи, адресованные этой личности.
///
/// # Параметры
/// * `rpc` — узел Solana
/// * `pool_program` — программа пула (у каждого актива своя)
/// * `identity` — чей ключ пробуем
/// * `role` — читаем как получатель или как аудитор
///
/// # Возвращает
/// * `ScanReport` — сколько конвертов просмотрено и что из них открылось
pub fn scan(
    rpc: &RpcClient,
    pool_program: &Pubkey,
    identity: &LocalIdentity,
    role: ReadAs,
) -> Result<ScanReport> {
    // Дискриминатор anchor-аккаунта: первые 8 байт. Без этого фильтра в выдачу
    // попадёт и сам пул, и всё остальное, что программа когда-либо создала.
    let discriminator = anchor_discriminator("MemoAccount");
    let config = RpcProgramAccountsConfig {
        filters: Some(vec![RpcFilterType::Memcmp(Memcmp::new_raw_bytes(
            0,
            discriminator.to_vec(),
        ))]),
        // base64 задаём явно: по умолчанию узел отдаёт base58, а он на
        // многокилобайтовых конвертах и медленнее, и местами обрезается.
        account_config: solana_rpc_client_api::config::RpcAccountInfoConfig {
            encoding: Some(
                solana_account_decoder_client_types::UiAccountEncoding::Base64,
            ),
            ..Default::default()
        },
        ..Default::default()
    };

    let accounts = rpc
        .get_program_ui_accounts_with_config(pool_program, config)
        .context("read the envelopes from the pool")?;

    let mut payments = Vec::new();
    for (_address, account) in &accounts {
        let Some(raw) = account.data.decode() else {
            continue;
        };
        let Some(memo) = MemoAccountView::parse(&raw) else {
            // Аккаунт нужного типа, но нечитаемой формы — пропускаем молча.
            // Это не наша ошибка и не повод обрывать скан: одна кривая запись
            // не должна прятать от человека остальные его платежи.
            continue;
        };
        // Конверт дописывается кусками; пока не дописан — открывать нечего.
        if !memo.is_finalized {
            continue;
        }

        let found = match role {
            ReadAs::Recipient => identity.open_as_recipient(&memo.data).map(|view| FoundPayment {
                commitment: memo.commitment,
                amount_micro: view.denomination,
                memo: String::from_utf8_lossy(&view.memo).into_owned(),
                rent_payer: memo.depositor,
                revoke_deadline_unix: memo.created_ts + memo.revoke_window,
            }),
            ReadAs::Auditor => identity.open_as_auditor(&memo.data).map(|view| FoundPayment {
                commitment: memo.commitment,
                amount_micro: view.denomination,
                memo: String::from_utf8_lossy(&view.memo).into_owned(),
                rent_payer: memo.depositor,
                revoke_deadline_unix: memo.created_ts + memo.revoke_window,
            }),
        };

        if let Some(payment) = found {
            payments.push(payment);
        }
    }

    Ok(ScanReport {
        envelopes_seen: accounts.len(),
        payments,
    })
}

/// Разобранный аккаунт конверта.
///
/// Разбираем руками, а не через anchor-клиент: тому нужен `Program`, а значит
/// подписант и полный клиент ради операции, которая ничего не подписывает.
/// Чтение чужих публичных данных не должно требовать ключа.
struct MemoAccountView {
    commitment: [u8; 32],
    depositor: Pubkey,
    created_ts: i64,
    revoke_window: i64,
    is_finalized: bool,
    data: Vec<u8>,
}

impl MemoAccountView {
    fn parse(raw: &[u8]) -> Option<Self> {
        // 8 дискриминатор | 32 commitment | 32 depositor | 8 created_ts
        // | 8 revoke_window | 4 total_len | 4 written_len | 1 bump
        // | 1 is_finalized | 4 длина вектора | данные
        let mut at = 8usize;
        let commitment: [u8; 32] = raw.get(at..at + 32)?.try_into().ok()?;
        at += 32;
        let depositor = Pubkey::new_from_array(raw.get(at..at + 32)?.try_into().ok()?);
        at += 32;
        let created_ts = i64::from_le_bytes(raw.get(at..at + 8)?.try_into().ok()?);
        at += 8;
        let revoke_window = i64::from_le_bytes(raw.get(at..at + 8)?.try_into().ok()?);
        at += 8 + 4 + 4 + 1; // total_len, written_len, bump — здесь не нужны
        let is_finalized = *raw.get(at)? != 0;
        at += 1;
        let len = u32::from_le_bytes(raw.get(at..at + 4)?.try_into().ok()?) as usize;
        at += 4;
        let data = raw.get(at..at + len)?.to_vec();

        Some(Self {
            commitment,
            depositor,
            created_ts,
            revoke_window,
            is_finalized,
            data,
        })
    }
}

/// Дискриминатор anchor-аккаунта: первые 8 байт `sha256("account:<Имя>")`.
fn anchor_discriminator(name: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(format!("account:{name}").as_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&hasher.finalize()[..8]);
    out
}
