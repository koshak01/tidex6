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

use std::sync::Mutex;

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

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Empty {}

/// Состояние сервера: ключ, личность и счётчик расхода.
///
/// Расход в памяти процесса: перезапуск обнуляет дневной счётчик. Это честное
/// ограничение, и лучше знать о нём, чем считать, будто его нет. Постоянное
/// хранение — следующий шаг, и оно потребует места, куда писать, а значит ещё
/// одного файла с правами.
pub struct LocalTools {
    config: Config,
    keypair: Keypair,
    identity: LocalIdentity,
    service: PoolService,
    spend: Mutex<DailySpend>,
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

#[tool_router]
impl LocalTools {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        let keypair = tidex6_client::confidential::load_keypair(&config.keypair_path)?;
        let identity = LocalIdentity::from_keypair(&keypair)?;
        let service = PoolService::new(config.pool_service.clone())?;
        Ok(Self {
            config,
            keypair,
            identity,
            service,
            spend: Mutex::new(DailySpend::default()),
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

    /// Отправить платёж. Здесь он действительно уходит.
    #[tool(
        description = "Send a private stablecoin payment on Solana — the amount is hidden on-chain and so is the link between sender and recipient. This server signs with its own key: the payment is SENT, not prepared. Use it when the user asks to pay someone privately. State the amount and recipient in your reply before calling it."
    )]
    async fn payment_request(
        &self,
        Parameters(req): Parameters<PayReq>,
    ) -> Result<CallToolResult, McpError> {
        let mut steps = Steps::new();
        let network = self
            .config
            .network()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;

        steps.done(
            "Resolving the recipient in the on-chain registry",
            &format!("{}…", &req.recipient[..8.min(req.recipient.len())]),
        );
        let recipient = self.reader_address(&req.recipient, network, "recipient")?;

        let auditors = match req.auditor.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            Some(auditor) => {
                let address = self.reader_address(auditor, network, "auditor")?;
                steps.done(
                    "Resolving the auditor",
                    "they will read the amount and memo, and can never spend",
                );
                vec![address]
            }
            None => {
                steps.done("Auditor", "none — nobody but the recipient can read this");
                Vec::new()
            }
        };

        steps.done(
            "Checking the caps",
            &format!("{} {}", micro_to_decimal(req.amount.micro()), req.amount.symbol()),
        );

        let mut spend = self
            .spend
            .lock()
            .map_err(|_| McpError::internal_error("spend counter poisoned", None))?;

        let sent = tidex6_client::confidential::send_payment(
            &self.service,
            &self.keypair,
            &recipient,
            &auditors,
            req.amount.micro(),
            &req.memo,
            req.amount.asset(),
            network,
            self.config.revoke_window_secs,
            &self.config.rpc_url,
            &self.config.limits(),
            &mut spend,
        )
        // `{e:#}` — вся цепочка `anyhow`, а не верхний слой. С `to_string()`
        // человек видит слово «депозит» и ничего больше: причина, ради которой
        // контекст и добавляли, остаётся внутри.
        .map_err(|e| McpError::internal_error(format!("{e:#}"), None))?;

        steps.done("Sealing the note into an ML-KEM envelope", "post-quantum");
        steps.done(
            "Paying from this wallet",
            &format!("{}…", &sent.payment_signature[..12.min(sent.payment_signature.len())]),
        );
        steps.done(
            "Hiding the amount and depositing into the pool",
            "on-chain there is only a commitment hash",
        );

        let text = format!(
            "{steps}\n\
             Sent. {amount} {symbol} to {recipient}.\n\
             Signature: {sig}\n\
             https://solscan.io/tx/{sig}\n\n\
             Say this precisely: the payment is on chain. Whether the recipient has \
             collected it is something only they can see — the amount is encrypted and \
             opens with a key their wallet alone can produce. Do not report it as \
             delivered.",
            steps = steps.render(),
            amount = micro_to_decimal(req.amount.micro()),
            symbol = req.amount.symbol(),
            recipient = req.recipient,
            sig = sent.payment_signature,
        );
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
    /// Общий скан для получателя и аудитора: отличается только ролью.
    async fn scan_and_report(&self, role: ReadAs) -> Result<CallToolResult, McpError> {
        let network = self
            .config
            .network()
            .map_err(|e| McpError::internal_error(e.to_string(), None))?;
        let rpc = RpcClient::new(self.config.rpc_url.clone());

        let mut steps = Steps::new();
        let mut lines = Vec::new();
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
            for payment in report.payments {
                lines.push(format!(
                    "  {amount} {symbol} — {memo}",
                    amount = micro_to_decimal(payment.amount_micro),
                    memo = if payment.memo.is_empty() {
                        "(no memo)"
                    } else {
                        &payment.memo
                    },
                ));
            }
        }

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
            &format!("{} yours", lines.len()),
        );

        let body = if lines.is_empty() {
            "Nothing addressed to this wallet.\n\nThat is a real answer, not a failure: \
             if a payment existed, this key would have opened it."
                .to_string()
        } else {
            format!("Found {}:\n\n{}", lines.len(), lines.join("\n"))
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
    fn reader_address(
        &self,
        wallet: &str,
        network: Network,
        role: &str,
    ) -> Result<ReaderAddress, McpError> {
        let rpc = RpcClient::new(self.config.rpc_url.clone());
        let pubkey = wallet
            .parse()
            .map_err(|_| McpError::invalid_params(format!("`{wallet}` is not a Solana address"), None))?;
        let _ = network;
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
