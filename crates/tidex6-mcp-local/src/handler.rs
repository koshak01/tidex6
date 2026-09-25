//! Tools = CLI surface. Library only. No dense TRACE.
//!
//! HARD_TIMEOUT: after HEAVY_TIMEOUT_SECS → process::exit(99).
//! Hang breadcrumb (circuits): stderr `withdraw_gc: merkle_L*`.

use std::sync::{Arc, Mutex};

use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, ServerCapabilities, ServerInfo};
use rmcp::{ErrorData as McpError, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use tidex6_client::confidential::{
    DailySpend, LocalIdentity, PoolService, ReadAs, collect_waiting, scan, send_payment,
};
use tidex6_client::evm;
use tidex6_client::pool_v2;
use tidex6_core::envelope::ReaderAddress;
use tidex6_core::network::{Asset, Network};
use uuid::Uuid;

use crate::config::Config;

/// Former dense TRACE — disabled. Hang site: circuit `withdraw_gc: merkle_L*`.
#[inline]
fn log(_tag: &str, _msg: &str) {}

/// Hard ceiling for heavy library work (scan + prove + service withdraw).
///
/// Past this we `process::exit(99)` so a runaway prove cannot thrash forever.
/// Do **not** use soft tokio cancel of `spawn_blocking` — see
/// `docs/SECURITY_NOTE_SPAWN_BLOCKING_PROVE.md`.
/// Hard ceiling for collect/send library work.
/// Target: healthy path ≈ CLI (≤~30s); allow ~CLI×3 headroom, not minutes.
pub const HEAVY_TIMEOUT_SECS: u64 = 120;

/// Public ceremony origin (same as hosted MCP default).
const CEREMONY_BASE: &str = "https://ceremony.tidex6.com";

/// Run library work on a dedicated OS thread (like CLI `main`), hard timeout.
async fn run_on_os_thread<T, F>(label: &'static str, f: F) -> Result<T, McpError>
where
    T: Send + 'static,
    F: FnOnce() -> anyhow::Result<T> + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name(format!("lib-{label}"))
        .spawn(move || {
            let _ = tx.send(f());
        })
        .map_err(|e| McpError::internal_error(format!("spawn {label}: {e}"), None))?;

    match tokio::time::timeout(std::time::Duration::from_secs(HEAVY_TIMEOUT_SECS), rx).await {
        Ok(Ok(inner)) => inner.map_err(|e| McpError::internal_error(format!("{e:#}"), None)),
        Ok(Err(_)) => Err(McpError::internal_error(
            format!("{label}: worker dropped"),
            None,
        )),
        Err(_) => {
            // Only remaining diagnostic: kill so host restarts cleanly.
            eprintln!(
                "mcp-local FATAL: {label} HARD_TIMEOUT after {HEAVY_TIMEOUT_SECS}s — process::exit(99)"
            );
            let _ = std::io::Write::flush(&mut std::io::stderr());
            std::process::exit(99);
        }
    }
}

// ── args ───────────────────────────────────────────────────────────────────

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
            Self::Usdc0_1
            | Self::Usdc1
            | Self::Usdc2
            | Self::Usdc3
            | Self::Usdc5
            | Self::Usdc10 => Asset::Wusdc,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NetworkArg {
    Mainnet,
    #[default]
    Devnet,
}

impl NetworkArg {
    fn name(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Devnet => "devnet",
        }
    }
    fn to_net(self) -> Network {
        match self {
            Self::Mainnet => Network::Mainnet,
            Self::Devnet => Network::Devnet,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct Empty {}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SendReq {
    pub recipient: String,
    pub amount: AmountArg,
    #[serde(default)]
    pub network: NetworkArg,
    #[serde(default)]
    pub auditor: Option<String>,
    #[serde(default)]
    pub memo: String,
    #[serde(default)]
    pub lifetime: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct NetworkOnly {
    #[serde(default)]
    pub network: NetworkArg,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EvmSendReq {
    /// Pool key: arc-mainnet, arc-testnet, base-sepolia, arbitrum-sepolia,
    /// arbitrum-sepolia-usdg, robinhood-testnet, robinhood-usdg, hyperliquid-testnet.
    pub pool: String,
    /// Recipient EVM address 0x…; must have published a reader key on this chain.
    pub recipient: String,
    /// Amount the recipient gets, decimal (e.g. "2.5"); the 1% fee goes on top.
    pub amount: String,
    #[serde(default)]
    pub auditor: Option<String>,
    #[serde(default)]
    pub memo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SolV2SendReq {
    /// Recipient Solana wallet; must have published a reader key and a v2 owner key.
    pub recipient: String,
    /// Amount the recipient gets, decimal USDC (e.g. "2.5"); the 1% fee goes on top.
    pub amount: String,
    #[serde(default)]
    pub network: NetworkArg,
    #[serde(default)]
    pub auditor: Option<String>,
    #[serde(default)]
    pub memo: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct EvmPoolReq {
    /// Any pool key of the chain; every pool of that chain is used.
    pub pool: String,
}

// ── server ─────────────────────────────────────────────────────────────────

pub struct LocalTools {
    config: Arc<Config>,
    keypair: Arc<Keypair>,
    identity: Arc<LocalIdentity>,
    service: Arc<PoolService>,
    spend: Arc<Mutex<DailySpend>>,
    /// EVM-кошелёк; `None` — `evm_key_path` не задан, инструменты `evm_*`
    /// отвечают, что дописать в конфиг.
    evm_signer: Option<Arc<evm::rpc::PrivateKeySigner>>,
    tool_router: rmcp::handler::server::router::tool::ToolRouter<Self>,
}

#[tool_router]
impl LocalTools {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        log("new", "load_keypair");
        let keypair = tidex6_client::confidential::load_keypair(&config.keypair_path)?;
        log("new", "identity");
        let identity = LocalIdentity::from_keypair(&keypair)?;
        log("new", "pool_service");
        let service = PoolService::new(config.pool_service.clone())?;
        let evm_signer = match &config.evm_key_path {
            Some(path) => Some(Arc::new(evm::rpc::signer_from_file(std::path::Path::new(
                path,
            ))?)),
            None => None,
        };
        log("new", "ok");
        Ok(Self {
            config: Arc::new(config),
            keypair: Arc::new(keypair),
            identity: Arc::new(identity),
            service: Arc::new(service),
            spend: Arc::new(Mutex::new(DailySpend::default())),
            evm_signer,
            tool_router: Self::tool_router(),
        })
    }

    pub fn wallet(&self) -> String {
        self.identity.wallet.to_string()
    }

    #[tool(description = "Config wallet pubkey (same key as CLI).")]
    async fn whoami(&self, Parameters(_): Parameters<Empty>) -> Result<CallToolResult, McpError> {
        log("whoami", "enter");
        let limits = self.config.limits();
        let evm_wallet = self
            .evm_signer
            .as_ref()
            .map_or("not configured".to_string(), |s| {
                format!("{:#x}", s.address())
            });
        let text = format!(
            "wallet={}\nevm_wallet={}\nper_payment={} per_day={}\nnetworks: pass network=mainnet|devnet\nEVM: evm_send|evm_payments|evm_collect|evm_enable with pool=<key>\ntools: about|ceremony|send|payments|collect|audit|whoami",
            self.identity.wallet,
            evm_wallet,
            micro_to_decimal(limits.per_payment),
            micro_to_decimal(limits.per_day),
        );
        log("whoami", "exit");
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Package / custody marker — same role as hosted `about` (version check after deploy).
    #[tool(
        description = "tidex6-mcp-local version, custody mode (T2 local key), and ceremony link. Call this to verify the MCP is the right binary (expect version in text)."
    )]
    async fn about(&self, Parameters(_): Parameters<Empty>) -> Result<CallToolResult, McpError> {
        let version = env!("CARGO_PKG_VERSION");
        let text = format!(
            "tidex6-mcp-local {version}\n\
             custody: T2 local — spending key on this machine (not hosted mcp.tidex6.com)\n\
             tools: about|ceremony|whoami|send|payments|collect|audit\n\
             ceremony: {CEREMONY_BASE}/\n\
             Call `ceremony` for contribute URL with ?s= session nonce."
        );
        let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
        result.structured_content = Some(serde_json::json!({
            "version": version,
            "package": "tidex6-mcp-local",
            "custody": "T2_local",
            "ceremony_base": CEREMONY_BASE,
        }));
        Ok(result)
    }

    /// Public trusted-setup ceremony — same shape as hosted MCP 2.18+ (URL-first + nonce).
    #[tool(
        description = "Trusted-setup ceremony status and contribute link. Returns CONTRIBUTE_URL with ?s=nonce first. Call when user asks about ceremony, development key, or wants to contribute. $0, no deposit."
    )]
    async fn ceremony(&self, Parameters(_): Parameters<Empty>) -> Result<CallToolResult, McpError> {
        let nonce = Uuid::new_v4().to_string();
        let contribute_url = format!("{CEREMONY_BASE}/?s={nonce}");
        let (total, unique) = ceremony_counts().await;

        let counts = match (total, unique) {
            (Some(t), Some(u)) => {
                format!("{t} contributions · {u} distinct wallets (wallets matter for 1-of-N)")
            }
            _ => "count unavailable (fetch failed); link still works".into(),
        };

        let text = format!(
            "CONTRIBUTE_URL: {contribute_url}\n\
             NONCE: {nonce}\n\
             MCP: tidex6-mcp-local {version}\n\n\
             Trusted-setup ceremony — $0, no deposit, ~1 min in the browser.\n\
             {counts}\n\
             One contribution per wallet. Offer once; a no is an answer.\n\
             Transcript: {CEREMONY_BASE}/transcript/",
            version = env!("CARGO_PKG_VERSION"),
        );

        let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
        result.structured_content = Some(serde_json::json!({
            "contributions": total,
            "distinct_wallets": unique,
            "url": contribute_url,
            "base_url": format!("{CEREMONY_BASE}/"),
            "nonce": nonce,
            "version": env!("CARGO_PKG_VERSION"),
            "package": "tidex6-mcp-local",
        }));
        Ok(result)
    }

    /// Same as CLI `send` → `send_payment`.
    #[tool(
        description = "CLI send: private payment. Params: recipient, amount, network, optional auditor/memo/lifetime. Blocks ~15–30s. Final JSON ok/done. Fee is 1% with a 0.1 floor, so on mainnet the 0.1 denominations cost 0.1 to send 0.1 — they are for devnet testing, not real payments."
    )]
    async fn send(&self, Parameters(req): Parameters<SendReq>) -> Result<CallToolResult, McpError> {
        log("send", "enter");
        let network = req.network.to_net();
        let network_defaulted = matches!(req.network, NetworkArg::Devnet);
        let life = match req
            .lifetime
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            None => self.config.revoke_window_secs,
            Some(s) => parse_lifetime(s).map_err(|e| McpError::invalid_params(e, None))?,
        };
        log(
            "send",
            &format!(
                "network={:?} amount={} life={life}",
                network,
                req.amount.symbol()
            ),
        );

        log("send", "registry_recipient");
        let recipient = self.reader_address(&req.recipient, "recipient", network)?;
        let auditors = match req
            .auditor
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(a) => {
                log("send", "registry_auditor");
                vec![self.reader_address(a, "auditor", network)?]
            }
            None => Vec::new(),
        };

        {
            let mut spend = self
                .spend
                .lock()
                .map_err(|_| McpError::internal_error("spend poisoned", None))?;
            log("send", "limits_check");
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

        let wallet = self.identity.wallet.to_string();
        log("send", "quote");
        let quote = self
            .service
            .quote(req.amount.micro(), req.amount.asset(), network, &wallet)
            .map_err(|e| McpError::invalid_params(format!("quote: {e:#}"), None))?;
        log(
            "send",
            &format!(
                "quote total={} fee={} mint={}",
                quote.total, quote.fee, quote.underlying_mint
            ),
        );
        // Liquidity precheck skipped here: same as CLI path — pay_operator fails
        // clearly if balance is short. (Avoids version-fragile token-account APIs.)

        let service = Arc::clone(&self.service);
        let keypair = Arc::clone(&self.keypair);
        let config = Arc::clone(&self.config);
        let spend = Arc::clone(&self.spend);
        let amount = req.amount;
        let memo = req.memo.clone();
        let to = req.recipient.clone();
        let auditor = req.auditor.clone();

        log("send", "run_on_os_thread(send_payment)");
        let sent = run_on_os_thread("send_payment", move || {
            log("send_payment", "lock_spend");
            let mut guard = spend
                .lock()
                .map_err(|_| anyhow::anyhow!("spend poisoned"))?;
            log("send_payment", "call_library");
            send_payment(
                &service,
                &keypair,
                &recipient,
                &auditors,
                amount.micro(),
                &memo,
                amount.asset(),
                network,
                life,
                config.rpc_for(network),
                &config.limits(),
                &mut guard,
                |sig| log("send_payment", &format!("on_paid {sig}")),
            )
        })
        .await?;

        log("send", "library_ok");
        let sig = if sent.deposit_signature.is_empty() {
            sent.payment_signature.clone()
        } else {
            sent.deposit_signature.clone()
        };
        let explorer = if network == Network::Devnet {
            "?cluster=devnet"
        } else {
            ""
        };
        let mut warnings: Vec<String> = Vec::new();
        if network_defaulted {
            warnings.push("network defaulted to devnet".into());
        }
        let body = serde_json::json!({
            "ok": true,
            "done": true,
            "funds_moved": true,
            "status": "done",
            "from": wallet,
            "to": to,
            "auditor": auditor,
            "amount": micro_to_decimal(req.amount.micro()),
            "symbol": req.amount.symbol(),
            "network": req.network.name(),
            "lifetime_secs": life,
            "fee": micro_to_decimal(quote.fee),
            "total": micro_to_decimal(quote.total),
            "commitment": sent.commitment_hex,
            "signature": sig,
            "payment_signature": sent.payment_signature,
            "deposit_signature": sent.deposit_signature,
            "transaction": format!("https://solscan.io/tx/{sig}{explorer}"),
            "warnings": warnings,
            "message": "Payment on chain. Do not report delivered.",
        });
        log("send", "exit ok");
        Ok(CallToolResult::success(vec![ContentBlock::text(
            body.to_string(),
        )]))
    }

    /// Та же библиотека, что CLI: `collect_waiting` in-process (без child-костыля).
    #[tool(
        description = "CLI collect: network only. USDC+USDT auto. Config wallet. Blocks ~10–20s. Final JSON."
    )]
    async fn collect(
        &self,
        Parameters(req): Parameters<NetworkOnly>,
    ) -> Result<CallToolResult, McpError> {
        let network = req.network.to_net();
        let recipient = self.identity.wallet.to_string();
        let proving_key = self
            .config
            .proving_key()
            .map_err(|e| McpError::invalid_params(format!("{e:#}"), None))?
            .to_string_lossy()
            .to_string();

        let service = Arc::clone(&self.service);
        let identity = Arc::clone(&self.identity);
        let rpc_url = self.config.rpc_for(network).to_string();
        let to = recipient.clone();
        let net_name = req.network.name();

        let result = run_on_os_thread("collect_waiting", move || {
            collect_waiting(
                &rpc_url,
                &service,
                &identity,
                &proving_key,
                network,
                &to,
                |_| {},
            )
        })
        .await?;

        let explorer = if network == Network::Devnet {
            "?cluster=devnet"
        } else {
            ""
        };
        let notes: Vec<serde_json::Value> = result
            .notes
            .iter()
            .map(|n| {
                serde_json::json!({
                    "symbol": n.symbol,
                    "amount": micro_to_decimal(n.amount_micro),
                    "signature": n.signature,
                    "transaction": format!("https://solscan.io/tx/{}{}", n.signature, explorer),
                })
            })
            .collect();
        let sigs: Vec<String> = result.notes.iter().map(|n| n.signature.clone()).collect();

        if result.notes.is_empty() {
            let err = result.stopped_by.unwrap_or_else(|| {
                if result.waiting_found == 0 {
                    "Nothing waiting.".into()
                } else {
                    "Found notes but collected none.".into()
                }
            });
            let body = serde_json::json!({
                "ok": false, "done": true, "funds_moved": false, "status": "failed",
                "network": net_name, "to": recipient, "error": err,
            });
            return Ok(CallToolResult::success(vec![ContentBlock::text(
                body.to_string(),
            )]));
        }

        let partial = result.stopped_by.is_some();
        let body = serde_json::json!({
            "ok": !partial,
            "done": true,
            "funds_moved": true,
            "status": if partial { "partial" } else { "done" },
            "network": net_name,
            "to": recipient,
            "total": result.totals_line(),
            "notes": notes,
            "signature": sigs.join(","),
            "error": result.stopped_by,
            "message": "Collected. Confirmed on chain.",
        });
        Ok(CallToolResult::success(vec![ContentBlock::text(
            body.to_string(),
        )]))
    }

    /// Auditor view: when created, amount, memo. No sender / no collect.
    #[tool(
        description = "Audit as config wallet: USDC+USDT. Shows sent_at (UTC), amount, memo. Never shows sender. Read-only."
    )]
    async fn audit(
        &self,
        Parameters(req): Parameters<NetworkOnly>,
    ) -> Result<CallToolResult, McpError> {
        log("audit", "enter");
        let network = req.network.to_net();
        let identity = Arc::clone(&self.identity);
        let rpc_url = self.config.rpc_for(network).to_string();

        let text = run_on_os_thread("audit_scan", move || {
            log("audit_scan", "rpc");
            let rpc = RpcClient::new_with_timeout(rpc_url, std::time::Duration::from_secs(60));
            let mut out = String::new();
            let mut mine = 0usize;
            let mut seen = 0usize;
            for asset in [Asset::Wusdc, Asset::Wusdt] {
                let Some(info) = network.asset(asset) else {
                    continue;
                };
                let Some(program) = info.pool_program else {
                    continue;
                };
                let symbol = info.symbol.trim_start_matches('w');
                log("audit_scan", &format!("scan_{symbol}"));
                let program = program.parse()?;
                let report = scan(&rpc, &program, &identity, ReadAs::Auditor)?;
                seen += report.envelopes_seen;
                mine += report.payments.len();
                out.push_str(&format!(
                    "[{symbol}] envelopes={} disclosed={}\n",
                    report.envelopes_seen,
                    report.payments.len()
                ));
                for p in report.payments {
                    let memo = if p.memo.is_empty() {
                        "(no memo)"
                    } else {
                        p.memo.as_str()
                    };
                    // Auditor: date + amount + memo only (no from, no received).
                    out.push_str(&format!(
                        "  {} · {} {symbol} — {memo}\n",
                        format_unix_utc(p.sent_at_unix),
                        micro_to_decimal(p.amount_micro)
                    ));
                }
            }
            out.push_str(&format!("\n{mine} disclosed ({seen} envelopes)\n"));
            Ok(out)
        })
        .await?;

        log("audit", "exit");
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Recipient inbox (read-only): date, amount, memo, received yes/no.
    /// Does **not** collect — use `collect` after the user says yes.
    #[tool(
        description = "My payments as recipient (read-only). USDC+USDT: sent_at UTC, amount, memo, received yes/no. Does NOT withdraw. Use collect only after user confirms."
    )]
    async fn payments(
        &self,
        Parameters(req): Parameters<NetworkOnly>,
    ) -> Result<CallToolResult, McpError> {
        log("payments", "enter");
        let network = req.network.to_net();
        let identity = Arc::clone(&self.identity);
        let rpc_url = self.config.rpc_for(network).to_string();

        let text = run_on_os_thread("payments_scan", move || {
            let rpc = RpcClient::new_with_timeout(
                rpc_url,
                std::time::Duration::from_secs(60),
            );
            let mut out = String::new();
            let mut waiting = 0usize;
            let mut received = 0usize;
            let mut unknown = 0usize;
            let mut total = 0usize;
            for asset in [Asset::Wusdc, Asset::Wusdt] {
                let Some(info) = network.asset(asset) else {
                    continue;
                };
                let Some(program) = info.pool_program else {
                    continue;
                };
                let symbol = info.symbol.trim_start_matches('w');
                let program = program.parse()?;
                let report = scan(&rpc, &program, &identity, ReadAs::Recipient)?;
                if report.payments.is_empty() {
                    continue;
                }
                out.push_str(&format!(
                    "[{symbol}] found={}\n",
                    report.payments.len()
                ));
                for p in report.payments {
                    total += 1;
                    let memo = if p.memo.is_empty() {
                        "(no memo)"
                    } else {
                        p.memo.as_str()
                    };
                    let status = match p.is_collected {
                        Some(true) => {
                            received += 1;
                            "received ✓"
                        }
                        Some(false) => {
                            waiting += 1;
                            "waiting ⏳"
                        }
                        None => {
                            unknown += 1;
                            "unknown ?"
                        }
                    };
                    out.push_str(&format!(
                        "  {} · {} {symbol} · {status} — {memo}\n",
                        format_unix_utc(p.sent_at_unix),
                        micro_to_decimal(p.amount_micro)
                    ));
                }
            }
            if total == 0 {
                out.push_str("No payments for this wallet as recipient.\n");
            } else {
                out.push_str(&format!(
                    "\ntotal {total} · waiting {waiting} · received {received} · unknown {unknown}\n"
                ));
                if waiting > 0 {
                    out.push_str(
                        "To withdraw waiting notes: ask the user, then call collect.\n",
                    );
                }
            }
            Ok(out)
        })
        .await?;

        log("payments", "exit");
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Публикация ключа читателя на EVM-цепи — после неё агенту можно платить.
    #[tool(
        description = "EVM: publish this wallet's reader key on the pool's chain so others can pay it by its 0x address. One transaction, skipped if already published. Needs gas on that chain."
    )]
    async fn evm_enable(
        &self,
        Parameters(req): Parameters<EvmPoolReq>,
    ) -> Result<CallToolResult, McpError> {
        let pool = evm_pool(&req.pool)?;
        let signer = self.evm_signer()?;
        let reader = self.identity.reader.clone();
        let owner_pk = self.identity.owner_pk_v2();
        let published = run_on_os_thread("evm_enable", move || {
            let reader_tx = evm::send::publish_reader(pool, &signer, &reader)?;
            // Пул v2 платит по ключу владельца: без него кошельку не заплатить.
            let owner_tx = match (pool.is_v2(), owner_pk) {
                (true, Some(pk)) => evm::v2::publish_owner_key(pool, &signer, &pk)?,
                (true, None) => anyhow::bail!("this identity has no spending key for v2 pools"),
                (false, _) => None,
            };
            Ok(reader_tx.or(owner_tx))
        })
        .await?;
        let body = match published {
            None => serde_json::json!({
                "ok": true, "done": true, "funds_moved": false, "status": "already_published",
                "chain": pool.name, "wallet": format!("{:#x}", self.evm_address()?),
            }),
            Some(tx) => serde_json::json!({
                "ok": true, "done": true, "funds_moved": false, "status": "published",
                "chain": pool.name, "wallet": format!("{:#x}", self.evm_address()?),
                "transaction": format!("{}/tx/{tx}", pool.explorer),
            }),
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(
            body.to_string(),
        )]))
    }

    /// Платёж в пул со скрытой суммой на EVM своим ключом.
    #[tool(
        description = "EVM private payment from the config EVM wallet. Params: pool (key), recipient 0x…, amount decimal, optional auditor 0x…/memo. Fee 1% (floor 0.1) on top, sealed as a note to the treasury. Pays gas itself. Blocks until mined. Final JSON ok/done."
    )]
    async fn evm_send(
        &self,
        Parameters(req): Parameters<EvmSendReq>,
    ) -> Result<CallToolResult, McpError> {
        let pool = evm_pool(&req.pool)?;
        if pool.is_withdraw_only {
            return Err(McpError::invalid_params(
                format!("{} is an earlier pool kept for withdrawals only", pool.key),
                None,
            ));
        }
        let signer = self.evm_signer()?;
        let amount_micro =
            decimal_to_micro(&req.amount).map_err(|e| McpError::invalid_params(e, None))?;
        if pool.is_mainnet {
            let mut spend = self
                .spend
                .lock()
                .map_err(|_| McpError::internal_error("spend poisoned", None))?;
            self.config
                .limits()
                .check(
                    Asset::Wusdc,
                    amount_micro,
                    None,
                    &mut spend,
                    std::time::SystemTime::now(),
                )
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        }
        let recipient_wallet = req.recipient.trim().to_string();
        let auditor_wallet = req
            .auditor
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
            .map(str::to_string);
        let memo = req.memo.clone();
        let refund_window = u64::try_from(self.config.revoke_window_secs).unwrap_or(0);
        let own_reader = self.identity.reader.clone();
        let paid = run_on_os_thread("evm_send", move || {
            let recipient =
                evm::send::lookup_reader(pool, &recipient_wallet)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "recipient {recipient_wallet} has not published a reader key on {}",
                        pool.name
                    )
                })?;
            let auditors = match &auditor_wallet {
                Some(a) => vec![evm::send::lookup_reader(pool, a)?.ok_or_else(|| {
                    anyhow::anyhow!(
                        "auditor {a} has not published a reader key on {}",
                        pool.name
                    )
                })?],
                None => Vec::new(),
            };
            if !pool.is_v2() {
                let paid =
                    evm::send::pay(pool, &signer, &recipient, &auditors, amount_micro, &memo)?;
                return Ok((
                    paid.transactions,
                    paid.commitment_hex,
                    paid.amount_micro,
                    paid.fee_micro,
                ));
            }
            // v2: нота на ключ владельца получателя, комиссию называет пул.
            let owner = evm::v2::lookup_owner_key(pool, &recipient_wallet)?.ok_or_else(|| {
                anyhow::anyhow!(
                    "recipient {recipient_wallet} has not enabled v2 payments on {} (no owner key)",
                    pool.name
                )
            })?;
            let units = pool.base_units_per_micro();
            let amount = amount_micro
                .checked_mul(units)
                .ok_or_else(|| anyhow::anyhow!("amount too large for a note"))?;
            let fee = evm::v2::fee_for(pool, amount)?;
            // Копия ноты отправителю — только когда возврат вообще возможен.
            let funder = (refund_window > 0).then_some(&own_reader);
            let payment =
                evm::v2::seal_payment(&recipient, &owner, &auditors, amount, &memo, funder)?;
            let (fee_rho, fee_envelope) = evm::v2::seal_fee(&evm::send::treasury()?, fee)?;
            let paid = evm::v2::pay(
                pool,
                &signer,
                &payment,
                amount,
                refund_window,
                &fee_rho,
                &fee_envelope,
            )?;
            Ok((
                paid.transactions,
                paid.core_hex,
                amount_micro,
                fee / units.max(1),
            ))
        })
        .await?;
        let (transactions, commitment_hex, paid_micro, fee_micro) = paid;
        let deposit = transactions.last().cloned().unwrap_or_default();
        let body = serde_json::json!({
            "ok": true,
            "done": true,
            "funds_moved": true,
            "status": "done",
            "chain": pool.name,
            "pool": pool.key,
            "from": format!("{:#x}", self.evm_address()?),
            "to": req.recipient,
            "auditor": req.auditor,
            "amount": micro_to_decimal(paid_micro),
            "fee": micro_to_decimal(fee_micro),
            "symbol": pool.token_symbol,
            "commitment": commitment_hex,
            "transactions": transactions,
            "transaction": format!("{}/tx/{deposit}", pool.explorer),
            "message": "Payment on chain. Do not report delivered.",
        });
        Ok(CallToolResult::success(vec![ContentBlock::text(
            body.to_string(),
        )]))
    }

    /// Свои платежи на EVM-цепи (только чтение).
    #[tool(
        description = "EVM: my payments as recipient on the pool's chain, every pool and token, earlier pool versions included (read-only): amount, memo, received yes/no. Does NOT withdraw. Use evm_collect only after the user confirms."
    )]
    async fn evm_payments(
        &self,
        Parameters(req): Parameters<EvmPoolReq>,
    ) -> Result<CallToolResult, McpError> {
        let chain = evm_pool(&req.pool)?.chain_id;
        let identity = Arc::clone(&self.identity);
        let relayer_url = self.config.relayer.clone();
        let text = run_on_os_thread("evm_payments", move || {
            let relayer = evm::receive::Relayer::new(&relayer_url)?;
            let mut out = String::new();
            let (mut waiting, mut received) = (0usize, 0usize);
            for pool in evm::pools::on_chain(chain) {
                let leaves = relayer.deposits(pool)?;
                // (amount_micro, spent, memo, sent_ts) — v1 и v2 открываются
                // по-разному, показываются одинаково.
                let rows: Vec<(u64, bool, String, u64)> = if pool.is_v2() {
                    evm::receive::my_notes_v2(pool, &leaves, &identity)?
                        .into_iter()
                        .map(|(note, spent, _, ts)| (note.amount_micro, spent, note.memo, ts))
                        .collect()
                } else {
                    evm::receive::my_notes(pool, &leaves, &identity)?
                        .into_iter()
                        .map(|m| (m.note.amount_micro, m.is_spent, m.note.memo, m.sent_ts))
                        .collect()
                };
                for (amount_micro, is_spent, memo, sent_ts) in rows {
                    let status = if is_spent {
                        received += 1;
                        "received"
                    } else {
                        waiting += 1;
                        "waiting"
                    };
                    let memo = if memo.is_empty() {
                        "(no memo)".to_string()
                    } else {
                        memo
                    };
                    out.push_str(&format!(
                        "  {} · {} {} · {status} · {} — {memo}\n",
                        format_unix_utc(sent_ts as i64),
                        micro_to_decimal(amount_micro),
                        pool.token_symbol,
                        pool.name,
                    ));
                }
            }
            if waiting + received == 0 {
                out.push_str("No payments for this wallet on this chain.\n");
            } else {
                out.push_str(&format!(
                    "\ntotal {} · waiting {waiting} · received {received}\n",
                    waiting + received
                ));
                if waiting > 0 {
                    out.push_str(
                        "To withdraw waiting notes: ask the user, then call evm_collect.\n",
                    );
                }
            }
            Ok(out)
        })
        .await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Забрать свои ноты на EVM-цепи на свой EVM-кошелёк через релеер.
    #[tool(
        description = "EVM collect: withdraw every waiting note on the pool's chain (all pools and tokens) to the config EVM wallet. Proves locally, the relayer sends and pays gas; no fee is taken at withdraw. Blocks while proving. Final JSON."
    )]
    async fn evm_collect(
        &self,
        Parameters(req): Parameters<EvmPoolReq>,
    ) -> Result<CallToolResult, McpError> {
        let chain = evm_pool(&req.pool)?.chain_id;
        let to = format!("{:#x}", self.evm_address()?);
        // Ключи доказательств грузятся, только когда есть что выводить из пулов
        // своей версии: у агента с одними нотами v2 файла v1 может не быть.
        let key_v1 = self.config.evm_proving_key().map_err(|e| format!("{e:#}"));
        let key_v2 = self
            .config
            .evm_proving_key_v2()
            .map_err(|e| format!("{e:#}"));
        let identity = Arc::clone(&self.identity);
        let relayer_url = self.config.relayer.clone();
        let recipient = to.clone();
        let collected = run_on_os_thread("evm_collect", move || {
            let relayer = evm::receive::Relayer::new(&relayer_url)?;
            let (mut pk_v1, mut pk_v2) = (None, None);
            let mut done = Vec::new();
            for pool in evm::pools::on_chain(chain) {
                let leaves = relayer.deposits(pool)?;
                let mut record = |amount_micro: u64, tx: String| {
                    done.push(serde_json::json!({
                        "pool": pool.key,
                        "symbol": pool.token_symbol,
                        "amount": micro_to_decimal(amount_micro),
                        "transaction": format!("{}/tx/{tx}", pool.explorer),
                    }));
                };
                if pool.is_v2() {
                    for (note, spent, _, _) in evm::receive::my_notes_v2(pool, &leaves, &identity)?
                    {
                        if spent {
                            continue;
                        }
                        if pk_v2.is_none() {
                            let path = key_v2.clone().map_err(anyhow::Error::msg)?;
                            pk_v2 = Some(evm::receive::load_proving_key(&path)?);
                        }
                        let key = pk_v2.as_ref().expect("loaded above");
                        let tx = evm::receive::collect_note_v2(
                            pool, &relayer, key, &leaves, &note, &identity, &recipient,
                        )?;
                        record(note.amount_micro, tx);
                    }
                } else {
                    for mine in evm::receive::my_notes(pool, &leaves, &identity)? {
                        if mine.is_spent {
                            continue;
                        }
                        if pk_v1.is_none() {
                            let path = key_v1.clone().map_err(anyhow::Error::msg)?;
                            pk_v1 = Some(evm::receive::load_proving_key(&path)?);
                        }
                        let key = pk_v1.as_ref().expect("loaded above");
                        let tx = evm::receive::collect_note(
                            pool, &relayer, key, &leaves, &mine.note, &recipient,
                        )?;
                        record(mine.note.amount_micro, tx);
                    }
                }
            }
            Ok(done)
        })
        .await?;
        let body = if collected.is_empty() {
            serde_json::json!({
                "ok": false, "done": true, "funds_moved": false, "status": "failed",
                "to": to, "error": "Nothing waiting.",
            })
        } else {
            serde_json::json!({
                "ok": true, "done": true, "funds_moved": true, "status": "done",
                "to": to, "notes": collected,
                "message": "Collected. Confirmed on chain.",
            })
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(
            body.to_string(),
        )]))
    }

    /// Вернуть свои платежи v2, которые получатель не забрал за окно.
    #[tool(
        description = "EVM refund: take back this wallet's own v2 payments the recipient has not collected once their refund window passed (all pools of the chain). No proof; the pool pays the funder back. Pays gas itself. Final JSON; lists payments still inside the window."
    )]
    async fn evm_refund(
        &self,
        Parameters(req): Parameters<EvmPoolReq>,
    ) -> Result<CallToolResult, McpError> {
        let chain = evm_pool(&req.pool)?.chain_id;
        let signer = self.evm_signer()?;
        let me = format!("{:#x}", signer.address());
        let identity = Arc::clone(&self.identity);
        let relayer_url = self.config.relayer.clone();
        let (refunded, pending) = run_on_os_thread("evm_refund", move || {
            let relayer = evm::receive::Relayer::new(&relayer_url)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            let (mut refunded, mut pending) = (Vec::new(), Vec::new());
            for pool in evm::pools::on_chain(chain).filter(|p| p.is_v2()) {
                let leaves = relayer.deposits(pool)?;
                for (note, spent) in evm::receive::my_refunds_v2(pool, &leaves, &identity, &me)? {
                    if spent {
                        continue;
                    }
                    let amount = micro_to_decimal(note.amount / pool.base_units_per_micro().max(1));
                    if now < note.refund_after {
                        pending.push(serde_json::json!({
                            "pool": pool.key, "symbol": pool.token_symbol, "amount": amount,
                            "refund_opens": format_unix_utc(note.refund_after as i64),
                        }));
                        continue;
                    }
                    let tx = evm::v2::refund(pool, &signer, &note)?;
                    refunded.push(serde_json::json!({
                        "pool": pool.key, "symbol": pool.token_symbol, "amount": amount,
                        "transaction": format!("{}/tx/{tx}", pool.explorer),
                    }));
                }
            }
            Ok((refunded, pending))
        })
        .await?;
        let body = serde_json::json!({
            "ok": !refunded.is_empty(), "done": true,
            "funds_moved": !refunded.is_empty(),
            "status": if refunded.is_empty() { "nothing" } else { "done" },
            "refunded": refunded, "inside_window": pending,
        });
        Ok(CallToolResult::success(vec![ContentBlock::text(
            body.to_string(),
        )]))
    }

    /// Solana pool v2: publish this wallet's owner key.
    #[tool(
        description = "Solana v2 enable: publish this wallet's owner key in pool v2 so it can be paid in the v2 format (needs the reader key published already). One transaction, idempotent. Param: network."
    )]
    async fn sol_v2_enable(
        &self,
        Parameters(req): Parameters<NetworkOnly>,
    ) -> Result<CallToolResult, McpError> {
        let rpc_url = self.config.rpc_for(req.network.to_net()).to_string();
        let owner_pk = self
            .identity
            .owner_pk_v2()
            .ok_or_else(|| McpError::invalid_params("identity has no spending key", None))?;
        let keypair = Arc::clone(&self.keypair);
        let reader = self.identity.reader.clone();
        let wallet = self.identity.wallet;
        let (reader_txs, tx) = run_on_os_thread("sol_v2_enable", move || {
            let rpc = RpcClient::new_with_timeout(rpc_url, std::time::Duration::from_secs(60));
            // Both keys a sender needs: the reader key (the envelope) and
            // the owner key (who spends).
            let reader_txs = if tidex6_client::registry::lookup(&rpc, &wallet)?.is_none() {
                tidex6_client::registry::register(&rpc, &keypair, &reader, 2)?
            } else {
                Vec::new()
            };
            Ok((
                reader_txs,
                pool_v2::publish_owner_key(&rpc, &keypair, owner_pk)?,
            ))
        })
        .await?;
        let body = serde_json::json!({
            "ok": true, "done": true, "funds_moved": false,
            "status": if tx.is_some() || !reader_txs.is_empty() { "published" } else { "already published" },
            "wallet": self.identity.wallet.to_string(),
            "reader_transactions": reader_txs,
            "transaction": tx,
        });
        Ok(CallToolResult::success(vec![ContentBlock::text(
            body.to_string(),
        )]))
    }

    /// Solana pool v2: pay a wallet.
    #[tool(
        description = "Solana v2 private payment in USDC from the config wallet: note bound to the recipient's owner key, 1% fee (floor 0.1) on top as a treasury note, refundable after the configured window. Params: recipient, amount decimal, network, optional auditor/memo. Final JSON ok/done."
    )]
    async fn sol_v2_send(
        &self,
        Parameters(req): Parameters<SolV2SendReq>,
    ) -> Result<CallToolResult, McpError> {
        let network = req.network.to_net();
        let is_mainnet = matches!(req.network, NetworkArg::Mainnet);
        let mint = pool_v2::usdc_mint(is_mainnet).ok_or_else(|| {
            McpError::invalid_params(format!("no v2 pool on {} yet", req.network.name()), None)
        })?;
        let amount =
            decimal_to_micro(&req.amount).map_err(|e| McpError::invalid_params(e, None))?;
        if is_mainnet {
            let mut spend = self
                .spend
                .lock()
                .map_err(|_| McpError::internal_error("spend poisoned", None))?;
            self.config
                .limits()
                .check(
                    Asset::Wusdc,
                    amount,
                    None,
                    &mut spend,
                    std::time::SystemTime::now(),
                )
                .map_err(|e| McpError::invalid_params(e.to_string(), None))?;
        }
        let parse = |w: &str| -> Result<Pubkey, McpError> {
            w.trim().parse().map_err(|_| {
                McpError::invalid_params(format!("`{w}` is not a Solana address"), None)
            })
        };
        let recipient = parse(&req.recipient)?;
        let auditor = match req
            .auditor
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty())
        {
            Some(a) => Some(parse(a)?),
            None => None,
        };
        let rpc_url = self.config.rpc_for(network).to_string();
        let keypair = Arc::clone(&self.keypair);
        let own_reader = self.identity.reader.clone();
        let memo = req.memo.clone();
        let refund_window = u64::try_from(self.config.revoke_window_secs).unwrap_or(0);
        let paid = run_on_os_thread("sol_v2_send", move || {
            let rpc = RpcClient::new_with_timeout(rpc_url, std::time::Duration::from_secs(60));
            let reader = tidex6_client::registry::lookup(&rpc, &recipient)?.ok_or_else(|| {
                anyhow::anyhow!("recipient {recipient} has not published a reader key")
            })?;
            let owner_pk = pool_v2::lookup_owner_key(&rpc, &recipient)?.ok_or_else(|| {
                anyhow::anyhow!("recipient {recipient} has not enabled v2 payments (no owner key)")
            })?;
            let auditors = match auditor {
                Some(a) => vec![
                    tidex6_client::registry::lookup(&rpc, &a)?
                        .ok_or_else(|| {
                            anyhow::anyhow!("auditor {a} has not published a reader key")
                        })?
                        .address,
                ],
                None => Vec::new(),
            };
            let treasury = evm::send::treasury()?;
            pool_v2::pay(
                &rpc,
                &keypair,
                &pool_v2::PaymentV2 {
                    mint,
                    reader: &reader.address,
                    owner_pk,
                    auditors: &auditors,
                    amount,
                    memo: &memo,
                    refund_window,
                    funder: Some(&own_reader),
                    treasury: &treasury,
                },
            )
        })
        .await?;
        let body = serde_json::json!({
            "ok": true, "done": true, "funds_moved": true, "status": "done",
            "network": req.network.name(), "to": req.recipient,
            "amount": micro_to_decimal(paid.amount), "fee": micro_to_decimal(paid.fee),
            "symbol": "USDC", "leaf": paid.leaf_hex, "transactions": paid.transactions,
            "message": "Payment on chain. Do not report delivered.",
        });
        Ok(CallToolResult::success(vec![ContentBlock::text(
            body.to_string(),
        )]))
    }

    /// Solana pool v2: list payments to this wallet.
    #[tool(
        description = "Solana v2 payments: notes addressed to this wallet in pool v2 (read-only), waiting or received. Param: network."
    )]
    async fn sol_v2_payments(
        &self,
        Parameters(req): Parameters<NetworkOnly>,
    ) -> Result<CallToolResult, McpError> {
        let mint =
            pool_v2::usdc_mint(matches!(req.network, NetworkArg::Mainnet)).ok_or_else(|| {
                McpError::invalid_params(format!("no v2 pool on {} yet", req.network.name()), None)
            })?;
        let rpc_url = self.config.rpc_for(req.network.to_net()).to_string();
        let identity = Arc::clone(&self.identity);
        let text = run_on_os_thread("sol_v2_payments", move || {
            let rpc = RpcClient::new_with_timeout(rpc_url, std::time::Duration::from_secs(60));
            let leaves = pool_v2::leaves(&rpc, &mint)?;
            let notes = pool_v2::my_notes(&rpc, &leaves, &identity)?;
            if notes.is_empty() {
                return Ok("No v2 payments for this wallet.\n".to_string());
            }
            let mut out = String::new();
            let mut waiting = 0usize;
            for (note, spent) in &notes {
                if !spent {
                    waiting += 1;
                }
                let memo = if note.memo.is_empty() {
                    "(no memo)"
                } else {
                    &note.memo
                };
                out.push_str(&format!(
                    "  leaf {} · {} USDC · {} — {memo}\n",
                    note.leaf_index,
                    micro_to_decimal(note.amount),
                    if *spent { "received" } else { "waiting" },
                ));
            }
            out.push_str(&format!("\ntotal {} · waiting {waiting}\n", notes.len()));
            if waiting > 0 {
                out.push_str(
                    "To withdraw waiting notes: ask the user, then call sol_v2_collect.\n",
                );
            }
            Ok(out)
        })
        .await?;
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }

    /// Solana pool v2: withdraw waiting notes to this wallet.
    #[tool(
        description = "Solana v2 collect: withdraw every waiting v2 note to the config wallet; proves locally, the wallet signs and pays the network fee. Param: network. Final JSON."
    )]
    async fn sol_v2_collect(
        &self,
        Parameters(req): Parameters<NetworkOnly>,
    ) -> Result<CallToolResult, McpError> {
        let mint =
            pool_v2::usdc_mint(matches!(req.network, NetworkArg::Mainnet)).ok_or_else(|| {
                McpError::invalid_params(format!("no v2 pool on {} yet", req.network.name()), None)
            })?;
        let rpc_url = self.config.rpc_for(req.network.to_net()).to_string();
        let identity = Arc::clone(&self.identity);
        let keypair = Arc::clone(&self.keypair);
        let key_path = self
            .config
            .evm_proving_key_v2()
            .map_err(|e| McpError::invalid_params(format!("{e:#}"), None))?;
        let done = run_on_os_thread("sol_v2_collect", move || {
            let rpc = RpcClient::new_with_timeout(rpc_url, std::time::Duration::from_secs(60));
            let leaves = pool_v2::leaves(&rpc, &mint)?;
            let mut pk = None;
            let mut done = Vec::new();
            for (note, spent) in pool_v2::my_notes(&rpc, &leaves, &identity)? {
                if spent {
                    continue;
                }
                if pk.is_none() {
                    pk = Some(evm::receive::load_proving_key(&key_path)?);
                }
                let key = pk.as_ref().expect("loaded above");
                let tx = pool_v2::withdraw(&rpc, &keypair, &mint, key, &leaves, &note, &identity)?;
                done.push(serde_json::json!({
                    "amount": micro_to_decimal(note.amount), "symbol": "USDC", "transaction": tx,
                }));
            }
            Ok(done)
        })
        .await?;
        let body = if done.is_empty() {
            serde_json::json!({"ok": false, "done": true, "funds_moved": false, "status": "failed", "error": "Nothing waiting."})
        } else {
            serde_json::json!({"ok": true, "done": true, "funds_moved": true, "status": "done", "notes": done})
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(
            body.to_string(),
        )]))
    }

    /// Solana pool v2: take back uncollected payments past their window.
    #[tool(
        description = "Solana v2 refund: take back this wallet's own v2 payments the recipient has not collected once their window passed. No proof. Param: network. Final JSON; lists payments still inside the window."
    )]
    async fn sol_v2_refund(
        &self,
        Parameters(req): Parameters<NetworkOnly>,
    ) -> Result<CallToolResult, McpError> {
        let mint =
            pool_v2::usdc_mint(matches!(req.network, NetworkArg::Mainnet)).ok_or_else(|| {
                McpError::invalid_params(format!("no v2 pool on {} yet", req.network.name()), None)
            })?;
        let rpc_url = self.config.rpc_for(req.network.to_net()).to_string();
        let identity = Arc::clone(&self.identity);
        let keypair = Arc::clone(&self.keypair);
        let me = self.identity.wallet;
        let (refunded, pending) = run_on_os_thread("sol_v2_refund", move || {
            let rpc = RpcClient::new_with_timeout(rpc_url, std::time::Duration::from_secs(60));
            let leaves = pool_v2::leaves(&rpc, &mint)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as i64;
            let (mut refunded, mut pending) = (Vec::new(), Vec::new());
            for (r, spent) in pool_v2::my_refunds(&rpc, &leaves, &identity, &me)? {
                if spent {
                    continue;
                }
                let amount = micro_to_decimal(r.copy.amount);
                if now < r.refund_after {
                    pending.push(serde_json::json!({
                        "amount": amount, "refund_opens": format_unix_utc(r.refund_after),
                    }));
                    continue;
                }
                let tx = pool_v2::refund(&rpc, &keypair, &mint, &r)?;
                refunded.push(serde_json::json!({"amount": amount, "transaction": tx}));
            }
            Ok((refunded, pending))
        })
        .await?;
        let body = serde_json::json!({
            "ok": !refunded.is_empty(), "done": true, "funds_moved": !refunded.is_empty(),
            "status": if refunded.is_empty() { "nothing" } else { "done" },
            "refunded": refunded, "inside_window": pending,
        });
        Ok(CallToolResult::success(vec![ContentBlock::text(
            body.to_string(),
        )]))
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for LocalTools {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.server_info.name = "tidex6-mcp-local".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.instructions = Some(
            "tidex6 local MCP = about|ceremony|send|payments|collect|audit|whoami, \
             EVM: evm_send|evm_payments|evm_collect|evm_enable|evm_refund with pool=<key>. \
             Solana pool v2: sol_v2_enable|sol_v2_send|sol_v2_payments|sol_v2_collect|sol_v2_refund. \
             about = version + custody T2. ceremony = CONTRIBUTE_URL with ?s= first (public setup). \
             payments = recipient list (read-only). collect only after user says yes. \
             audit = auditor view. Heavy send/collect on OS thread; RAYON=1."
                .into(),
        );
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }
}

impl LocalTools {
    fn evm_signer(&self) -> Result<evm::rpc::PrivateKeySigner, McpError> {
        self.evm_signer
            .as_deref()
            .cloned()
            .ok_or_else(|| McpError::invalid_params(evm_not_configured(), None))
    }

    fn evm_address(&self) -> Result<evm::rpc::Address, McpError> {
        self.evm_signer
            .as_ref()
            .map(|s| s.address())
            .ok_or_else(|| McpError::invalid_params(evm_not_configured(), None))
    }

    fn reader_address(
        &self,
        wallet: &str,
        role: &str,
        network: Network,
    ) -> Result<ReaderAddress, McpError> {
        log("registry", &format!("lookup {role}={wallet}"));
        let rpc = RpcClient::new(self.config.rpc_for(network).to_string());
        let pubkey = wallet.parse().map_err(|_| {
            McpError::invalid_params(format!("`{wallet}` not a Solana address"), None)
        })?;
        tidex6_client::registry::lookup(&rpc, &pubkey)
            .map_err(|e| McpError::internal_error(e.to_string(), None))?
            .map(|e| e.address)
            .ok_or_else(|| {
                McpError::invalid_params(
                    format!("{role} {wallet} not registered for private payments"),
                    None,
                )
            })
    }
}

/// Public transcript counts (no auth). Fail soft → (None, None).
async fn ceremony_counts() -> (Option<usize>, Option<usize>) {
    let url = format!("{CEREMONY_BASE}/transcript/log.json");
    let fetch = tokio::task::spawn_blocking(move || {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(8))
            .build()
            .ok()?;
        let v: serde_json::Value = client.get(&url).send().ok()?.json().ok()?;
        // log.json is either an array of contributions or { contributions: [...] }
        let arr = v
            .as_array()
            .cloned()
            .or_else(|| v.get("contributions").and_then(|c| c.as_array()).cloned())?;
        let total = arr.len();
        let mut wallets = std::collections::HashSet::new();
        for c in &arr {
            if let Some(name) = c.get("name").and_then(|n| n.as_str()) {
                wallets.insert(name.to_string());
            } else if let Some(w) = c.get("wallet").and_then(|n| n.as_str()) {
                wallets.insert(w.to_string());
            }
        }
        Some((total, wallets.len()))
    });
    match fetch.await {
        Ok(Some((t, u))) => (Some(t), Some(u)),
        _ => (None, None),
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

/// On-chain `created_ts` → `YYYY-MM-DD HH:MM UTC` (no wallet addresses).
fn format_unix_utc(ts: i64) -> String {
    if ts <= 0 {
        return "????-??-?? ??:?? UTC".into();
    }
    // Manual UTC format — avoid chrono dep in mcp-local.
    let secs = ts as u64;
    let days = secs / 86400;
    let tod = secs % 86400;
    let hour = tod / 3600;
    let min = (tod % 3600) / 60;
    // Civil date from days since 1970-01-01 (Howard Hinnant algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {hour:02}:{min:02} UTC")
}

fn parse_lifetime(s: &str) -> Result<i64, String> {
    let s = s.trim().to_ascii_lowercase();
    let secs = if let Some(n) = s.strip_suffix('m') {
        n.parse::<i64>().map_err(|e| e.to_string())? * 60
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<i64>().map_err(|e| e.to_string())? * 3600
    } else if let Some(n) = s.strip_suffix('d') {
        n.parse::<i64>().map_err(|e| e.to_string())? * 86400
    } else {
        s.parse::<i64>().map_err(|e| e.to_string())?
    };
    if !(300..=30 * 86400).contains(&secs) {
        return Err("lifetime 5m…30d".into());
    }
    Ok(secs)
}

fn evm_not_configured() -> String {
    "EVM is not configured: add evm_key_path (a file with the 0x… private key, chmod 600) to the config"
        .into()
}

/// Пул по ключу — внятный отказ со списком ключей, если такого нет.
fn evm_pool(key: &str) -> Result<&'static evm::pools::EvmPool, McpError> {
    evm::pools::pool(key.trim()).ok_or_else(|| {
        let keys: Vec<&str> = evm::pools::payable().map(|p| p.key).collect();
        McpError::invalid_params(
            format!("unknown pool `{key}`; known: {}", keys.join(", ")),
            None,
        )
    })
}

/// Десятичная сумма в микро-единицы: не больше шести знаков после точки,
/// больше нуля. Лишний знак — отказ, а не округление: округлённая сумма —
/// не та, что просили.
fn decimal_to_micro(text: &str) -> Result<u64, String> {
    let text = text.trim();
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && frac.is_empty() || frac.len() > 6 {
        return Err(format!(
            "amount `{text}`: at most six digits after the point"
        ));
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole
            .parse()
            .map_err(|_| format!("amount `{text}` is not a number"))?
    };
    let frac: u64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<6}")
            .parse()
            .map_err(|_| format!("amount `{text}` is not a number"))?
    };
    let micro = whole
        .checked_mul(1_000_000)
        .and_then(|w| w.checked_add(frac))
        .ok_or_else(|| format!("amount `{text}` is too large"))?;
    if micro == 0 {
        return Err("the amount must be greater than zero".into());
    }
    Ok(micro)
}
