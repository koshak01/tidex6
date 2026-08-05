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
use solana_rpc_client::rpc_client::RpcClient;
use tidex6_client::confidential::{
    DailySpend, LocalIdentity, PoolService, ReadAs, collect_waiting, scan, send_payment,
};
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

// ── server ─────────────────────────────────────────────────────────────────

pub struct LocalTools {
    config: Arc<Config>,
    keypair: Arc<Keypair>,
    identity: Arc<LocalIdentity>,
    service: Arc<PoolService>,
    spend: Arc<Mutex<DailySpend>>,
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
        log("new", "ok");
        Ok(Self {
            config: Arc::new(config),
            keypair: Arc::new(keypair),
            identity: Arc::new(identity),
            service: Arc::new(service),
            spend: Arc::new(Mutex::new(DailySpend::default())),
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
        let text = format!(
            "wallet={}\nper_payment={} per_day={}\nnetworks: pass network=mainnet|devnet\ntools: about|ceremony|send|payments|collect|audit|whoami",
            self.identity.wallet,
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
        description = "CLI send: private payment. Params: recipient, amount, network, optional auditor/memo/lifetime. Blocks ~15–30s. Final JSON ok/done."
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
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for LocalTools {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::default();
        info.server_info.name = "tidex6-mcp-local".into();
        info.server_info.version = env!("CARGO_PKG_VERSION").into();
        info.instructions = Some(
            "tidex6 local MCP = about|ceremony|send|payments|collect|audit|whoami. \
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
