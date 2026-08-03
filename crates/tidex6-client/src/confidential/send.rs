//! Отправка приватного платежа с локальным ключом — без браузера и без ссылки.
//!
//! Повторяет то, что делает вкладка отправителя, шаг в шаг:
//!
//! 1. спросить котировку — сколько всего списать и на чей счёт;
//! 2. запечатать ноту в ML-KEM-конверт (`super::note`);
//! 3. перевести оператору свои токены, привязав перевод к этому депозиту;
//! 4. отдать оператору commitment и конверт — он завернёт сумму и положит в пул.
//!
//! **Почему без оператора нельзя.** Заворачивание суммы в конфиденциальный
//! Token-2022 требует полномочий обёрточного минта, а они у оператора. Отсюда
//! честная граница локального режима: подпись своя, обёртка чужая. На чтении и
//! получении оператор не нужен вовсе — там агент автономен полностью.
//!
//! Что оператор при этом узнаёт: «кошелёк X заплатил столько-то, вот
//! commitment C». Связь отправителя с платежом ему известна. От публики она
//! скрыта, от него — нет, и писать об этом надо прямо, а не умалчивать.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tidex6_core::envelope::ReaderAddress;
use tidex6_core::network::{Asset, Network};

use super::limits::{DailySpend, Limits};

/// Котировка: во что обойдётся платёж и кому платить.
#[derive(Debug, Deserialize)]
pub struct Quote {
    /// Что получит адресат, в микро-единицах.
    pub amount: u64,
    /// Комиссия сервиса.
    pub fee: u64,
    /// Сколько списывается с отправителя: `amount + fee`.
    pub total: u64,
    /// Кому переводить — счёт оператора.
    pub operator: String,
    /// Минт настоящего токена (USDC / USDT), не обёртки.
    pub underlying_mint: String,
    /// Аудиторы пула, если пул регулируемый: их слоты добавляются к каждому
    /// платежу помимо того, кого назвал отправитель.
    #[serde(default)]
    pub pool_auditors: Vec<String>,
}

/// Чем кончилась отправка.
#[derive(Debug)]
pub struct SentPayment {
    /// Подпись перевода оператору.
    ///
    /// **Показывать её человеку как «ваш платёж» нельзя.** Это оплата услуги:
    /// в обозревателе видно отправителя, получателя-оператора и полную сумму с
    /// комиссией. Приватного в ней нет ничего, и не должно быть — приватен
    /// депозит, который идёт следом.
    pub payment_signature: String,
    /// Подпись депозита в пул — **вот это и есть платёж**.
    ///
    /// В обозревателе по ней видно ровно один хеш: ни отправителя, ни
    /// получателя, ни суммы. Её и показываем.
    pub deposit_signature: String,
    /// Commitment платежа — то единственное, что увидит наблюдатель.
    pub commitment_hex: String,
    /// Сколько списано всего.
    pub total_micro: u64,
}

/// Куда ходить за котировкой и депозитом.
pub struct PoolService {
    /// Например `https://tidex6.com`.
    pub base_url: String,
    http: reqwest::blocking::Client,
}

impl PoolService {
    pub fn new(base_url: impl Into<String>) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            // Таймаут обязателен: без него первый же сетевой сбой вешает агента
            // навсегда, и человек видит молчание вместо ошибки.
            .timeout(std::time::Duration::from_secs(180))
            .build()
            .context("http client")?;
        Ok(Self {
            base_url: base_url.into(),
            http,
        })
    }

    /// Спросить, во что обойдётся платёж.
    ///
    /// `wallet` спрашивающего обязателен: реестровый гейт стоит на каждом шаге
    /// службы, а не только на записи. Иначе даром отвечать на запросы мог бы
    /// кто угодно, а место в реестре стоит ренты за аккаунт на цепочке.
    pub fn quote(
        &self,
        amount_micro: u64,
        asset: Asset,
        network: Network,
        wallet: &str,
    ) -> Result<Quote> {
        let body = serde_json::json!({
            "step": "deposit_quote",
            "amount": micro_to_decimal(amount_micro),
            "asset": asset_slug(asset),
            "network": network_slug(network),
            "wallet": wallet,
        });
        let out = self.call(&body).context("quote")?;
        serde_json::from_str(&out).with_context(|| format!("the quote came back unreadable: {out}"))
    }

    /// Отдать оператору commitment и конверт: он завернёт сумму и положит в пул.
    // Аргументов много, и каждый — отдельное поле запроса службы. Сворачивать
    // их в структуру ради счётчика значит завести тип, существующий только
    // чтобы пройти проверку.
    #[allow(clippy::too_many_arguments)]
    fn deposit(
        &self,
        commitment_hex: &str,
        envelope_hex: &str,
        amount_micro: u64,
        asset: Asset,
        network: Network,
        wallet: &str,
        payment_signature: &str,
        revoke_window_secs: i64,
    ) -> Result<DepositResult> {
        let body = serde_json::json!({
            "step": "deposit_browser",
            "commitment": commitment_hex,
            "envelope": envelope_hex,
            "amount": micro_to_decimal(amount_micro),
            "asset": asset_slug(asset),
            "network": network_slug(network),
            "revoke_window": revoke_window_secs,
            "wallet": wallet,
            "payment_sig": payment_signature,
        });
        let out = self.call(&body).context("deposit")?;
        serde_json::from_str(&out)
            .with_context(|| format!("the deposit came back unreadable: {out}"))
    }

    /// Где нота лежит в дереве: индекс листа, соседи по пути и корень.
    ///
    /// Спрашивается у службы, а не считается здесь: полное дерево живёт у неё,
    /// и держать копию ради одной ноты значило бы перечитывать цепочку.
    pub fn merkle_path(
        &self,
        commitment_hex: &str,
        asset: Asset,
        network: Network,
        wallet: &str,
    ) -> Result<crate::confidential::collect::MerklePath> {
        let body = serde_json::json!({
            "step": "merkle_path",
            "commitment": commitment_hex,
            "asset": asset_slug(asset),
            "network": network_slug(network),
            "wallet": wallet,
        });
        let out = self.call(&body).context("merkle path")?;
        serde_json::from_str(&out)
            .with_context(|| format!("the tree path came back unreadable: {out}"))
    }

    /// Отдать готовое доказательство: транзакцию в верификатор шлёт служба.
    ///
    /// Секрет ноты сюда не попадает — только доказательство и публичные входы.
    /// Получатель связан доказательством: подменить его по дороге нельзя, эту
    /// проверку делает программа, а не наша вежливость.
    #[allow(clippy::too_many_arguments)]
    pub fn withdraw(
        &self,
        proof_a_hex: &str,
        proof_b_hex: &str,
        proof_c_hex: &str,
        merkle_root_hex: &str,
        nullifier_hash_hex: &str,
        recipient: &str,
        amount_micro: u64,
        asset: Asset,
        network: Network,
        wallet: &str,
    ) -> Result<String> {
        let body = serde_json::json!({
            "step": "withdraw_browser",
            "proof_a": proof_a_hex,
            "proof_b": proof_b_hex,
            "proof_c": proof_c_hex,
            "merkle_root": merkle_root_hex,
            "nullifier_hash": nullifier_hash_hex,
            "recipient": recipient,
            "amount": micro_to_decimal(amount_micro),
            "asset": asset_slug(asset),
            "network": network_slug(network),
            "wallet": wallet,
        });
        let out = self.call(&body).context("withdraw")?;
        // Ответ службы — объект с подписью; на всякий случай принимаем и голую
        // строку, чтобы смена формы ответа не роняла забор уже ушедших денег.
        #[derive(Deserialize)]
        struct WithdrawReply {
            #[serde(alias = "signature")]
            tx: String,
        }
        match serde_json::from_str::<WithdrawReply>(&out) {
            Ok(reply) => Ok(reply.tx),
            Err(_) => Ok(out.trim().to_string()),
        }
    }

    /// Один вызов службы. Отказ службы — это отказ, а не пустой ответ.
    fn call(&self, body: &serde_json::Value) -> Result<String> {
        #[derive(Deserialize)]
        struct Reply {
            ok: bool,
            #[serde(default)]
            output: String,
            // Other fields (error, step, …) intentionally ignored here.
            // On failure we return the full raw body_text, not a re-built message.
        }
        let url = format!("{}/api/deposit", self.base_url);
        let step = body
            .get("step")
            .and_then(|v| v.as_str())
            .unwrap_or("?");

        let response = self
            .http
            .post(&url)
            .json(body)
            .send()
            .context("the pool service is unreachable")?;

        // Тело читаем текстом и разбираем сами. `.json()` на не-JSON says
        // «expected value at line 1 column 1» и выбрасывает само тело — а
        // именно оно и содержит причину: страница ошибки nginx, редирект,
        // заглушка. Диагностика без того, что пришло, отправляет искать не там.
        let status = response.status();
        let body_text = response.text().context("could not read the reply")?;
        // 504 — обрыв обратного прокси, а не отказ службы: работа при этом
        // доводится до конца, и платёж доходит. Сказать «не прошло» было бы
        // враньём, за которое человек платит второй раз, поэтому говорим что
        // есть.
        //
        // Само по себе это не должно случаться: таймаут прокси поднят выше
        // времени депозита. Проверка остаётся на случай, когда сеть окажется
        // медленнее ожидаемого, — но если она срабатывает регулярно, чинить
        // надо не здесь, а причину.
        if status.as_u16() == 504 {
            bail!(
                "обратный прокси оборвал соединение (504) раньше, чем служба ответила. \
                 Депозит при этом запущен и, скорее всего, дойдёт: перевод оператору уже \
                 подтверждён. НЕ повторяйте платёж — проверьте `receive` через минуту."
            );
        }

        // Parse only to decide ok vs error. On failure we surface the **raw
        // wire body** — no rephrase, no substring "humanize". Industrial rule:
        // the operator must see exactly what the service returned.
        let reply: Reply = serde_json::from_str(&body_text).with_context(|| {
            format!(
                "pool service non-JSON (HTTP {status} step={step}): {body_text}"
            )
        })?;
        if !reply.ok {
            // Entire response as received. Do not rebuild message from fields.
            bail!(
                "pool service error step={step} http={status} raw={body_text}"
            );
        }
        Ok(reply.output)
    }
}

/// Результат депозита — то, что служба отдаёт структурой.
#[derive(Debug, Deserialize)]
struct DepositResult {
    /// Подпись транзакции депозита. **Не перевода оператору**: в переводе
    /// видно отправителя, получателя и полную сумму, и показывать его вместо
    /// депозита значит выдать прозрачную транзакцию за приватную.
    tx: String,
}

/// Отправить приватный платёж целиком: от котировки до записи в пул.
///
/// # Параметры
/// * `service` — служба пула
/// * `signer` — ключ отправителя; им подписывается перевод оператору
/// * `recipient` — адрес читателя получателя (из реестра на цепочке)
/// * `auditors` — кому раскрыть сумму и назначение помимо получателя
/// * `amount_micro` — сколько получит адресат
/// * `memo` — назначение платежа
/// * `rpc_url` — узел Solana для перевода оператору. Задаётся вызывающим, а не
///   зашивается: у оператора свой узел, у пользователя свой, и библиотека не
///   должна выбирать за них
/// * `limits` / `spend` — потолки; проверяются **до** первой транзакции
/// * `on_paid` — зовётся сразу после подтверждения перевода оператору, до
///   записи в пул. Это единственный момент, когда деньги уже списаны, а платёж
///   ещё не существует; вызывающему нужно уметь сказать об этом человеку, иначе
///   отказ на следующем шаге читается как «ничего не произошло»
///
/// # Возвращает
/// * `SentPayment` — подпись перевода и commitment
///
/// # Ошибки
/// Отказ лимита приходит раньше любой отправки: платёж, отклонённый после
/// перевода оператору, означал бы списанные деньги и ненаписанный депозит.
#[allow(clippy::too_many_arguments)]
pub fn send_payment(
    service: &PoolService,
    signer: &solana_keypair::Keypair,
    recipient: &ReaderAddress,
    auditors: &[ReaderAddress],
    amount_micro: u64,
    memo: &str,
    asset: Asset,
    network: Network,
    revoke_window_secs: i64,
    rpc_url: &str,
    limits: &Limits,
    spend: &mut DailySpend,
    on_paid: impl FnOnce(&str),
) -> Result<SentPayment> {
    use anchor_client::Signer as _;

    let now = std::time::SystemTime::now();
    // Проверка лимита — первым делом, до котировки и до любых денег. Отказ
    // после перевода оператору был бы худшим исходом: деньги ушли, депозита
    // нет, и виноват в этом отказ, который можно было выдать заранее.
    limits
        .check(asset, amount_micro, None, spend, now)
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let sender_wallet = signer.pubkey().to_string();
    let quote = service.quote(amount_micro, asset, network, &sender_wallet)?;

    // Пул может быть регулируемым: его аудиторы добавляются к тем, кого назвал
    // отправитель, а не заменяют их.
    let mut all_auditors = auditors.to_vec();
    for hex_key in &quote.pool_auditors {
        let bytes = hex_to_bytes(hex_key).context("pool auditor: not hex")?;
        all_auditors
            .push(ReaderAddress::from_bytes(&bytes).context("pool auditor: unreadable address")?);
    }

    let sealed = super::note::seal_payment(recipient, &all_auditors, amount_micro, memo)?;
    let commitment_hex = bytes_to_hex(&sealed.commitment.to_bytes());

    // Перевод привязывается к ЭТОМУ депозиту через memo = commitment. Подпись
    // станет публичной, но переиспользовать её для другого депозита нельзя:
    // memo не совпадёт. Это защита от того, чтобы чужой оплатой закрыли свой
    // депозит.
    let payment_signature = super::transfer::pay_operator(
        signer,
        &quote.operator,
        &quote.underlying_mint,
        quote.total,
        &commitment_hex,
        rpc_url,
    )?;
    on_paid(&payment_signature);

    let deposit_output = service.deposit(
        &commitment_hex,
        &bytes_to_hex(&sealed.envelope),
        amount_micro,
        asset,
        network,
        &sender_wallet,
        &payment_signature,
        revoke_window_secs,
    )?;

    // Расход записываем ПОСЛЕ успеха: неудавшийся платёж денег не потратил, и
    // съедать им дневной лимит значит наказывать за сбой сети.
    spend.record(now, amount_micro);

    Ok(SentPayment {
        payment_signature,
        deposit_signature: deposit_output.tx,
        commitment_hex,
        total_micro: quote.total,
    })
}

fn asset_slug(asset: Asset) -> &'static str {
    match asset {
        Asset::Wusdc => "wusdc",
        Asset::Wusdt => "wusdt",
        Asset::Sol => "sol",
    }
}

fn network_slug(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet-beta",
        Network::Devnet => "devnet",
    }
}

/// Микро-единицы в десятичную строку: служба принимает «1.5», а не 1500000.
fn micro_to_decimal(micro: u64) -> String {
    let whole = micro / 1_000_000;
    let frac = micro % 1_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    format!("{whole}.{frac:06}")
        .trim_end_matches('0')
        .to_string()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("hex of odd length");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("not hex"))
        .collect()
}
