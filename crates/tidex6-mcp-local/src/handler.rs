//! Инструменты локального сервера.
//!
//! Имена те же, что у размещённого (`mcp.tidex6.com`), и это сделано нарочно:
//! один и тот же `SKILL.md`, один и тот же промпт работают с обоими. Меняется
//! не словарь, а то, чем инструмент отвечает.
//!
//! | инструмент | размещённый | здесь |
//! |---|---|---|
//! | `payment_request` | отдаёт ссылку | **платит** и отдаёт подпись |
//! | `receive` | отдаёт ссылку | **находит** платежи и показывает их |
//! | `audit` | отдаёт ссылку | показывает раскрытое |
//!
//! Размещённый готовит, локальный делает. Разница ровно в том, у кого ключ.

use std::sync::{Arc, Mutex};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo};
use rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use solana_keypair::Keypair;
use solana_rpc_client::rpc_client::RpcClient;
use tidex6_client::confidential::{DailySpend, LocalIdentity, PoolService, ReadAs, scan};
use tidex6_core::envelope::ReaderAddress;
use tidex6_core::network::{Asset, Network};

use crate::config::Config;
use crate::jobs::{JobState, Jobs};

/// Сколько отправляем. Перечисление, а не число, и это защита, а не удобство:
/// пул работает фиксированными номиналами, поэтому «отправь 4999» невыразимо —
/// инъекции нечем это сказать.
#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AmountArg {
    #[serde(rename = "usdc0_1")]
    Usdc0_1,
    Usdc1,
    Usdc2,
    Usdc3,
    Usdc5,
    Usdc10,
    #[serde(rename = "usdt0_1")]
    Usdt0_1,
    Usdt1,
    Usdt2,
    Usdt3,
    Usdt5,
    Usdt10,
}

impl AmountArg {
    fn micro(self) -> u64 {
        match self {
            Self::Usdc0_1 | Self::Usdt0_1 => 100_000,
            Self::Usdc1 | Self::Usdt1 => 1_000_000,
            Self::Usdc2 | Self::Usdt2 => 2_000_000,
            Self::Usdc3 | Self::Usdt3 => 3_000_000,
            Self::Usdc5 | Self::Usdt5 => 5_000_000,
            Self::Usdc10 | Self::Usdt10 => 10_000_000,
        }
    }
    fn asset(self) -> Asset {
        match self {
            Self::Usdc0_1 | Self::Usdc1 | Self::Usdc2 | Self::Usdc3 | Self::Usdc5 | Self::Usdc10 => {
                Asset::Wusdc
            }
            _ => Asset::Wusdt,
        }
    }
    fn symbol(self) -> &'static str {
        match self.asset() {
            Asset::Wusdt => "USDT",
            _ => "USDC",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct PayReq {
    /// В какой сети. Спрашивается у человека, а не угадывается: mainnet — это
    /// настоящие деньги, и решение «в какой сети платить» принимает он.
    ///
    /// Этот сервер настроен ровно на одну сеть — ту, что в его конфиге, откуда
    /// он берёт ключ. Запрос про другую отклоняется вслух: молча уйти не в ту
    /// сеть значит сделать не то, о чём попросили, и не сказать об этом.
    pub network: NetworkArg,
    /// Кому платим — обычный адрес кошелька Solana.
    pub recipient: String,
    /// Сколько.
    pub amount: AmountArg,
    /// Назначение платежа. Видят получатель и аудитор, больше никто.
    #[serde(default)]
    pub memo: String,
    /// Кому раскрыть сумму и назначение. Пусто — никому.
    #[serde(default)]
    pub auditor: Option<String>,
}

/// Сеть. Перечисление, а не строка: «main», «Mainnet» и «mainnet-beta» должны
/// быть одним и тем же, а опечатка — отказом на входе, а не платежом не туда.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkArg {
    Mainnet,
    Devnet,
}

impl NetworkArg {
    fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Devnet => "devnet",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Empty {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StatusReq {
    /// Идентификатор, который вернул `payment_request`.
    pub job_id: String,
}

/// Состояние сервера: ключ, личность и счётчик расхода.
///
/// Расход в памяти процесса: перезапуск обнуляет дневной счётчик. Это честное
/// ограничение, и лучше знать о нём, чем считать, будто его нет. Постоянное
/// хранение — следующий шаг, и оно потребует места, куда писать, а значит ещё
/// одного файла с правами.
pub struct LocalTools {
    // Всё под `Arc`, потому что платёж уходит в фоновую задачу и переживает
    // вызов инструмента, который его начал.
    config: Arc<Config>,
    keypair: Arc<Keypair>,
    identity: Arc<LocalIdentity>,
    service: Arc<PoolService>,
    spend: Arc<Mutex<DailySpend>>,
    jobs: Jobs,
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

#[tool_router]
impl LocalTools {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let keypair = tidex6_client::confidential::load_keypair(&config.keypair_path)?;
        let identity = LocalIdentity::from_keypair(&keypair)?;
        let service = PoolService::new(config.pool_service.clone())?;
        Ok(Self {
            config: Arc::new(config),
            keypair: Arc::new(keypair),
            identity: Arc::new(identity),
            service: Arc::new(service),
            spend: Arc::new(Mutex::new(DailySpend::default())),
            jobs: Jobs::default(),
            tool_router: Self::tool_router(),
        })
    }

    /// Чей ключ у этого сервера.
    #[tool(
        description = "Report which Solana wallet this server signs with. Use it when the user asks who they are, which wallet is being used, or whether the right key is loaded. Unlike a hosted server, this one holds a key and can spend — within the caps in its config."
    )]
    async fn whoami(&self, Parameters(_): Parameters<Empty>) -> Result<CallToolResult, McpError> {
        let limits = self.config.limits();
        let text = format!(
            "This server signs with:\n\n{wallet}\n\n\
             It holds the key, so it pays without a browser and without a link. \
             What bounds it is not a promise but the code: at most {per_payment} per payment \
             and {per_day} per day, USDC and USDT only. A request over those is refused \
             before anything is sent.\n\n\
             Network: {network}.",
            wallet = self.identity.wallet,
            per_payment = micro_to_decimal(limits.per_payment),
            per_day = micro_to_decimal(limits.per_day),
            network = self.config.network,
        );
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Отправить платёж. Возвращается сразу, работа идёт своим ходом.
    #[tool(
        description = "Send a private stablecoin payment on Solana — the amount is hidden on-chain and so is the link between sender and recipient. This server signs with its own key: the payment is SENT, not prepared. It returns immediately with a job id while the work continues; report that it was accepted, then call payment_status to learn the outcome. Never say the payment completed until payment_status says so."
    )]
    async fn payment_request(
        &self,
        Parameters(req): Parameters<PayReq>,
    ) -> Result<CallToolResult, McpError> {
        let network = self
            .config
            .network()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        // Сеть из запроса должна совпадать с настроенной. Уйти в devnet, когда
        // просили mainnet, — худший вид молчаливого несоответствия: человек
        // уверен, что заплатил по-настоящему.
        let asked = match req.network {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Devnet => Network::Devnet,
        };
        if asked != network {
            return Err(McpError::invalid_params(
                format!(
                    "this server signs on {configured} only — it holds a {configured} key. \
                     A {asked} payment needs a server configured for {asked}.",
                    configured = self.config.network,
                    asked = req.network.name(),
                ),
                None,
            ));
        }

        // Всё, что проверяется дёшево, проверяется ДО того, как мы скажем
        // «принято». Отказ через двадцать секунд после «принято» — худший
        // порядок: человек уже ушёл заниматься другим делом.
        let recipient = self.reader_address(&req.recipient, "recipient")?;
        let auditors = match req.auditor.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(auditor) => vec![self.reader_address(auditor, "auditor")?],
            None => Vec::new(),
        };

        {
            // Предварительная проверка потолков: она ничего не записывает, а
            // отказать до перевода лучше, чем после.
            let mut spend = self
                .spend
                .lock()
                .map_err(|_| McpError::internal_error("spend counter poisoned", None))?;
            self.config
                .limits()
                .check(
                    req.amount.asset(),
                    req.amount.micro(),
                    None,
                    &mut spend,
                    std::time::SystemTime::now(),
                )
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        }

        let auditors_were_named = !auditors.is_empty();
        let id = self.jobs.start();

        // Дальше по ходу платежа каждый шаг пишет строку в лог. Не для отладки:
        // оператор смотрит на процесс на своей машине, и «работает или висит»
        // должно быть видно, не спрашивая агента. Сумм и назначения тут нет —
        // они в конверте, а лог живёт на диске оператора и в его терминале.
        tracing::info!(
            job = %id,
            amount = %micro_to_decimal(req.amount.micro()),
            asset = %req.amount.symbol(),
            to = %short_address(&req.recipient),
            auditor = auditors_were_named,
            "payment accepted; signing the transfer"
        );

        if let Some(n) = &self.config.notify {
            n.say(&format!(
                "Accepted: {amount} {symbol} → {to}{auditor}\n\
                 Signing the transfer. Nothing is confirmed yet.",
                amount = micro_to_decimal(req.amount.micro()),
                symbol = req.amount.symbol(),
                to = short_address(&req.recipient),
                auditor = if auditors_were_named {
                    " · auditor will read the amount and memo"
                } else {
                    ""
                },
            ));
        }

        // Дальше — фон. `spawn_blocking`, а не `spawn`: внутри синхронные HTTP
        // и RPC, и занимать ими асинхронный поток нельзя.
        let jobs = self.jobs.clone();
        let job_id = id.clone();
        let service = Arc::clone(&self.service);
        let keypair = Arc::clone(&self.keypair);
        let config = Arc::clone(&self.config);
        let spend = Arc::clone(&self.spend);
        let amount = req.amount;
        let memo = req.memo.clone();
        let notify = self.config.notify.clone();

        tokio::task::spawn_blocking(move || {
            let mut guard = match spend.lock() {
                Ok(g) => g,
                Err(_) => {
                    jobs.set(&job_id, JobState::Failed {
                        reason: "spend counter poisoned".to_string(),
                        funds_moved: false,
                    });
                    return;
                }
            };
            match tidex6_client::confidential::send_payment(
                &service,
                &keypair,
                &recipient,
                &auditors,
                amount.micro(),
                &memo,
                amount.asset(),
                network,
                config.revoke_window_secs,
                &config.rpc_url,
                &config.limits(),
                &mut guard,
                |signature| {
                    // Деньги ушли, платежа ещё нет. Спросив статус в эту
                    // секунду, человек должен увидеть именно это, а не «идёт».
                    jobs.set(&job_id, JobState::Paid {
                        signature: signature.to_string(),
                    });
                    tracing::info!(
                        job = %job_id,
                        signature = %signature,
                        "transfer confirmed; funds have left the wallet"
                    );
                    if let Some(n) = &notify {
                        n.say(&format!(
                            "Transfer confirmed — {value} {symbol} left the wallet.\n\
                             Writing the envelope to chain.",
                            value = micro_to_decimal(amount.micro()),
                            symbol = amount.symbol(),
                        ));
                    }
                },
            ) {
                Ok(sent) => {
                    if let Some(n) = &notify {
                        // Ссылка ведёт на ДЕПОЗИТ, и только на него. Перевод
                        // оператору публичен по устройству — в нём видно
                        // отправителя, получателя и полную сумму. Подставить
                        // его вместо депозита значит показать прозрачную
                        // транзакцию и назвать её приватной.
                        //
                        // Не нашли подпись депозита — ссылки нет. Так честнее:
                        // отсутствие ссылки человек заметит, а подмену — нет.
                        let link = if sent.deposit_signature.is_empty() {
                            String::new()
                        } else {
                            format!(
                                "https://solscan.io/tx/{sig}{cluster}\n",
                                sig = sent.deposit_signature,
                                cluster = if network == Network::Devnet {
                                    "?cluster=devnet"
                                } else {
                                    ""
                                },
                            )
                        };
                        n.say(&format!(
                            "Done. The payment is on chain.\n\
                             {link}\n\
                             Whether the recipient has collected it is something only they \
                             can see: the amount is encrypted and opens with a key their \
                             wallet alone can produce."
                        ));
                    }
                    tracing::info!(
                        job = %job_id,
                        deposit = %sent.deposit_signature,
                        commitment = %sent.commitment_hex,
                        "deposit written to chain; payment complete"
                    );
                    jobs.set(&job_id, JobState::Done {
                        signature: if sent.deposit_signature.is_empty() {
                            sent.payment_signature
                        } else {
                            sent.deposit_signature
                        },
                        commitment: sent.commitment_hex,
                        explorer_suffix: if network == Network::Devnet {
                            "?cluster=devnet".to_string()
                        } else {
                            String::new()
                        },
                    })
                }
                Err(e) => {
                    // Различить «не начали» и «деньги ушли» — единственное, что
                    // человеку по-настоящему нужно при отказе.
                    //
                    // Спрашиваем об этом состояние заявки, а не текст ошибки.
                    // `on_paid` ставит `Paid` ровно в секунду списания, и это
                    // факт; подстрока в сообщении — догадка, которая молча
                    // меняет ответ при любой правке формулировки. Здесь ценой
                    // такой догадки было бы «денег не тронули» человеку, у
                    // которого их уже списали.
                    let text = format!("{e:#}");
                    let funds_moved = matches!(jobs.get(&job_id), Some(JobState::Paid { .. }));
                    if let Some(n) = &notify {
                        n.say(&if funds_moved {
                            format!(
                                "Failed AFTER the funds left: {text}\n\n\
                                 The money has already gone — do not repeat this payment. \
                                 Check again in a minute: the deposit may well have landed."
                            )
                        } else {
                            format!("Not sent: {text}\n\nNo money moved.")
                        });
                    }
                    tracing::error!(
                        job = %job_id,
                        funds_moved,
                        "payment failed: {text}"
                    );
                    jobs.set(&job_id, JobState::Failed { reason: text, funds_moved });
                }
            }
        });

        let auditor_line = if auditors_were_named {
            "  ✓ Auditor resolved — they will read the amount and memo, and can never spend\n"
        } else {
            "  ✓ No auditor — nobody but the recipient can read this\n"
        };
        let text = format!(
            "  ✓ Recipient resolved in the on-chain registry\n\
             {auditor_line}\
               ✓ Caps checked — {amount} {symbol}\n\
               ✓ Accepted, job {id}\n\n\
             The transfer is being signed and the envelope written to chain — about half a \
             minute. Tell the user it was accepted and that nothing is confirmed yet, then \
             call `payment_status` with id `{id}`.",
            amount = micro_to_decimal(req.amount.micro()),
            symbol = req.amount.symbol(),
        );
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Чем кончилась работа.
    #[tool(
        description = "Check what became of a payment started by payment_request. Use it after sending, and whenever the user asks whether a payment went through. Until this reports it done, do not say the payment completed."
    )]
    async fn payment_status(
        &self,
        Parameters(req): Parameters<StatusReq>,
    ) -> Result<CallToolResult, McpError> {
        let text = match self.jobs.get(req.job_id.trim()) {
            Some(state) => state.describe(),
            None => "No such job. Either it was never started, or it finished over an hour \
                     ago and is no longer remembered — a completed payment is on chain \
                     regardless, and `receive` will find it."
                .to_string(),
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Найти платежи, адресованные нам.
    #[tool(
        description = "Find the private payments sent to this wallet. Unlike a hosted server, this one reads and decrypts locally — it returns the payments themselves, not a link. Use it when the user asks whether they have been paid or what arrived."
    )]
    async fn receive(&self, Parameters(_): Parameters<Empty>) -> Result<CallToolResult, McpError> {
        self.scan_and_report(ReadAs::Recipient).await
    }

    /// Прочитать раскрытое нам как аудитору.
    #[tool(
        description = "Read the payments whose senders disclosed them to this wallet as an auditor: amount and memo, never the ability to spend. Returns the entries themselves, decrypted locally. Use it when the user acts as an accountant or auditor."
    )]
    async fn audit(&self, Parameters(_): Parameters<Empty>) -> Result<CallToolResult, McpError> {
        self.scan_and_report(ReadAs::Auditor).await
    }
}

impl LocalTools {
    /// Работы, ещё не дошедшие до конца. Читается при остановке.
    pub fn jobs(&self) -> &Jobs {
        &self.jobs
    }

    /// Кошелёк, которым этот сервер подписывает. Печатается в лог при старте:
    /// оператор должен видеть, какой ключ поднялся, не спрашивая агента.
    pub fn wallet(&self) -> String {
        self.identity.wallet.to_string()
    }

    /// Общий скан для получателя и аудитора: отличается только ролью.
    async fn scan_and_report(&self, role: ReadAs) -> Result<CallToolResult, McpError> {
        let network = self
            .config
            .network()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let rpc = RpcClient::new(self.config.rpc_url.clone());

        tracing::info!(
            role = match role {
                ReadAs::Recipient => "recipient",
                ReadAs::Auditor => "auditor",
            },
            "scanning both pools with the local key"
        );

        let mut steps = Steps::new();
        // Ждущие своего — отдельно от уже забранных. Список платежей растёт и
        // никогда не убывает: он читается с цепочки, а из цепочки ничего не
        // удаляется. Показывать его целиком значит через месяц отвечать
        // простынёй, в которой то, что человеку нужно сделать сейчас, тонет
        // среди того, что он сделал в марте.
        let mut waiting: Vec<String> = Vec::new();
        let mut collected: Vec<String> = Vec::new();
        let mut unknown: Vec<String> = Vec::new();
        // Сколько всего пришло, по активу — для итога одной строкой.
        let mut totals: Vec<(&'static str, u64)> = Vec::new();
        let mut seen = 0usize;

        // Оба пула: у USDC и USDT свои программы, и человек не обязан помнить,
        // какой валютой ему заплатили.
        for asset in [Asset::Wusdc, Asset::Wusdt] {
            let Some(info) = network.asset(asset) else {
                continue;
            };
            let Some(program) = info.pool_program else {
                continue;
            };
            let program = program
                .parse()
                .map_err(|e| McpError::internal_error(format!("pool program: {e}"), None))?;

            let report = scan(&rpc, &program, &self.identity, role)
                .map_err(|e| McpError::internal_error(e.to_string(), None))?;
            seen += report.envelopes_seen;

            let symbol = info.symbol.trim_start_matches('w');
            let mut total = 0u64;
            for payment in report.payments {
                total += payment.amount_micro;
                let line = format!(
                    "  {amount} {symbol} — {memo}",
                    amount = micro_to_decimal(payment.amount_micro),
                    memo = if payment.memo.is_empty() {
                        "(no memo)"
                    } else {
                        &payment.memo
                    },
                );
                match payment.is_collected {
                    Some(false) => waiting.push(line),
                    Some(true) => collected.push(line),
                    // Аудитор нуллификатора не знает, и узел мог не ответить —
                    // в обоих случаях честный ответ «неизвестно», а не догадка.
                    None => unknown.push(line),
                }
            }
            if total > 0 {
                totals.push((symbol, total));
            }
        }

        let mine = waiting.len() + collected.len() + unknown.len();
        tracing::info!(
            envelopes = seen,
            mine,
            waiting = waiting.len(),
            collected = collected.len(),
            "scan finished; decrypted locally"
        );

        steps.done(
            "Fetching every envelope from both pools",
            &format!("{seen} on-chain"),
        );
        steps.done(
            "Filtering by view tag",
            "one scalar-mult each, ~255 of 256 discarded before any ML-KEM work",
        );
        steps.done(
            "Decrypting what is left with the local key",
            &format!("{mine} yours"),
        );

        let body = if mine == 0 {
            "Nothing addressed to this wallet.\n\nThat is a real answer, not a failure: \
             if a payment existed, this key would have opened it."
                .to_string()
        } else {
            let sum = totals
                .iter()
                .map(|(symbol, total)| format!("{} {symbol}", micro_to_decimal(*total)))
                .collect::<Vec<_>>()
                .join(" + ");
            let mut body = format!("{mine} payments addressed to you, {sum} in total.\n");

            // Сначала то, с чем можно что-то сделать. Заголовок пишем, только
            // когда есть с чем сравнивать: при единственной группе он
            // превращается в шум.
            let groups = [
                ("Waiting to be collected", &waiting),
                ("Already collected", &collected),
                ("Status unknown", &unknown),
            ];
            let non_empty = groups.iter().filter(|(_, g)| !g.is_empty()).count();
            for (title, group) in groups {
                if group.is_empty() {
                    continue;
                }
                // Длинный хвост сворачиваем: подробности нужны про свежее, а
                // «и ещё двадцать» — это уже количество, а не список.
                const SHOWN: usize = 8;
                if non_empty > 1 {
                    body.push_str(&format!("\n{title} ({}):\n", group.len()));
                } else {
                    body.push('\n');
                }
                for line in group.iter().take(SHOWN) {
                    body.push_str(line);
                    body.push('\n');
                }
                if group.len() > SHOWN {
                    body.push_str(&format!("  … and {} more\n", group.len() - SHOWN));
                }
            }
            body.trim_end().to_string()
        };

        Ok(CallToolResult::success(vec![ContentBlock::text(format!(
            "{}\n{body}",
            steps.render()
        ))]))
    }

    /// Адрес читателя из реестра на цепочке.
    ///
    /// Отказ здесь — штатный ответ, а не сбой: кошелёк, не включивший приватные
    /// платежи, запечатать нечем, и человеку нужно это сказать, а не пытаться
    /// ещё раз.
    fn reader_address(&self, wallet: &str, role: &str) -> Result<ReaderAddress, McpError> {
        let rpc = RpcClient::new(self.config.rpc_url.clone());
        let pubkey = wallet
            .parse()
            .map_err(|_| {
                McpError::invalid_params(format!("`{wallet}` is not a Solana address"), None)
            })?;
        tidex6_client::registry::lookup(&rpc, &pubkey)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map(|entry| entry.address)
            .ok_or_else(|| {
                McpError::invalid_params(
                    format!(
                        "the {role} wallet {wallet} has not enabled private payments yet — \
                         it takes one signature at https://tidex6.com/register/"
                    ),
                    None,
                )
            })
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for LocalTools {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` у rmcp `#[non_exhaustive]` — собираем из умолчаний и
        // правим нужное, а не литералом.
        let mut info = ServerInfo::default();
        info.instructions = Some(
                "tidex6, local mode. This server holds a Solana key and sends private \
                 stablecoin payments itself — no browser, no link, no human signature per \
                 payment. What bounds it is code, not a prompt: per-payment and daily caps \
                 and a two-asset allowlist, checked before anything is sent.\n\n\
                 It also finds payments addressed to this wallet and reads what was \
                 disclosed to it, decrypting locally. Nothing about that path leaves the \
                 machine.\n\n\
                 Never report a payment as delivered. You may say the transaction is \
                 confirmed on chain. Whether the recipient collected it is encrypted and \
                 unknowable — to you, to this server, to everyone but them."
                    .to_string(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}

/// Пошаговый отчёт для человека.
///
/// Пётр попросил их подробными, и это не украшение: в эти секунды агент тратит
/// чужие деньги, и человек имеет право видеть, за что именно платит, а не
/// полосу загрузки. Каждая строка — то, что действительно произошло.
struct Steps(Vec<String>);

impl Steps {
    fn new() -> Self {
        Self(Vec::new())
    }
    fn done(&mut self, what: &str, detail: &str) {
        self.0.push(format!("  ✓ {what} — {detail}"));
    }
    fn render(&self) -> String {
        if self.0.is_empty() {
            return String::new();
        }
        format!("{}\n", self.0.join("\n"))
    }
}

/// Адрес в виде, который читается в чате: начало, многоточие, конец.
///
/// Человек узнаёт адрес по краям, а середина — то, из-за чего сообщение
/// становится нечитаемым (и из-за чего фильтры утечек принимают адрес за
/// секрет).
fn short_address(address: &str) -> String {
    if address.len() < 16 {
        return address.to_string();
    }
    format!("{}…{}", &address[..8], &address[address.len() - 6..])
}

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
