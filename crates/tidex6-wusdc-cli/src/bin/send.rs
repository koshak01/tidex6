//! Отправить stealth-платёж (библиотека `send_payment`).
//!
//! Кошелёк-отправитель — **только** из `~/.tidex6-local/config.toml`.
//!
//! ```text
//! send <mainnet|devnet> <amount> <recipient> [--auditor ADDR] [--memo TEXT] [--lifetime 12h]
//!
//! amount: usdc0_1 usdc1 usdc2 usdc3 usdc5 usdc10
//!         usdt0_1 usdt1 usdt2 usdt3 usdt5 usdt10
//! ```
//!
//! Local MCP `payment_request` зовёт ту же library-функцию.

use std::io::Write;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use solana_rpc_client::rpc_client::RpcClient;
use tidex6_client::confidential::{
    DailySpend, Limits, LocalIdentity, PoolService, load_keypair, send_payment,
};
use tidex6_core::envelope::ReaderAddress;
use tidex6_core::network::{Asset, Network};

#[derive(Deserialize)]
struct Config {
    keypair_path: String,
    rpc_mainnet: String,
    rpc_devnet: String,
    #[serde(default = "default_pool")]
    pool_service: String,
    #[serde(default = "default_life")]
    revoke_window_secs: i64,
}

fn default_pool() -> String {
    "https://tidex6.com".to_string()
}
fn default_life() -> i64 {
    24 * 3600
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return Ok(());
    }

    let network = parse_network(args.first().map(String::as_str))?;
    let amount_key = args.get(1).context("нужен номинал (usdc0_1 / usdt1 / …)")?;
    let (asset, amount_micro, symbol) = parse_amount(amount_key)?;
    let recipient_str = args
        .get(2)
        .context("нужен recipient (Solana address)")?
        .clone();

    let mut auditor: Option<String> = None;
    let mut memo = String::new();
    let mut lifetime: Option<String> = None;
    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "--auditor" => {
                i += 1;
                auditor = Some(args.get(i).context("--auditor needs address")?.clone());
            }
            "--memo" => {
                i += 1;
                memo = args.get(i).context("--memo needs text")?.clone();
            }
            "--lifetime" => {
                i += 1;
                lifetime = Some(
                    args.get(i)
                        .context("--lifetime needs 30m|12h|24h|7d")?
                        .clone(),
                );
            }
            other => bail!("unknown arg `{other}` (see --help)"),
        }
        i += 1;
    }

    let home = std::env::var("HOME").context("$HOME")?;
    let cfg_path = format!("{home}/.tidex6-local/config.toml");
    let config: Config = toml::from_str(
        &std::fs::read_to_string(&cfg_path).with_context(|| format!("нет {cfg_path}"))?,
    )?;

    let keypair = load_keypair(&config.keypair_path)?;
    let identity = LocalIdentity::from_keypair(&keypair)?;
    let wallet = identity.wallet.to_string();

    let rpc_url = match network {
        Network::Mainnet => config.rpc_mainnet.as_str(),
        Network::Devnet => config.rpc_devnet.as_str(),
    };
    let rpc = RpcClient::new(rpc_url.to_string());
    let recipient = lookup_reader(&rpc, &recipient_str, "recipient")?;
    let auditors: Vec<ReaderAddress> = match auditor.as_deref() {
        Some(a) => vec![lookup_reader(&rpc, a, "auditor")?],
        None => Vec::new(),
    };

    let revoke_window_secs = match lifetime.as_deref() {
        None => config.revoke_window_secs,
        Some(s) => parse_lifetime(s)?,
    };

    let service = PoolService::new(config.pool_service.clone())?;
    let limits = Limits::default();
    let mut spend = DailySpend::default();

    say(&format!("from:      {wallet}  (config key)"));
    say(&format!("to:        {recipient_str}"));
    if let Some(a) = &auditor {
        say(&format!("auditor:   {a}"));
    }
    say(&format!("network:   {network:?}"));
    say(&format!(
        "amount:    {} {symbol}",
        amount_micro as f64 / 1e6
    ));
    say(&format!("lifetime:  {revoke_window_secs}s"));
    if !memo.is_empty() {
        say(&format!("memo:      {memo}"));
    }
    say(&format!("service:   {}", config.pool_service));
    say("");

    let t0 = Instant::now();
    let mut paid_at = None;
    let sent = send_payment(
        &service,
        &keypair,
        &recipient,
        &auditors,
        amount_micro,
        &memo,
        asset,
        network,
        revoke_window_secs,
        rpc_url,
        &limits,
        &mut spend,
        |sig| {
            paid_at = Some(t0.elapsed());
            say(&format!(
                "paid operator  t={:.1}s  {sig}",
                t0.elapsed().as_secs_f64()
            ));
        },
    )?;
    let total = t0.elapsed();

    say(&format!(
        "deposit ok     t={:.1}s  {}",
        total.as_secs_f64(),
        sent.deposit_signature
    ));
    say(&format!("commitment: {}", sent.commitment_hex));
    say(&format!("https://solscan.io/tx/{}", sent.deposit_signature));
    say(&format!(
        "TIME send {symbol}: {:.2}s (pay {:.2}s + deposit {:.2}s)",
        total.as_secs_f64(),
        paid_at.map(|d| d.as_secs_f64()).unwrap_or(0.0),
        paid_at
            .map(|d| (total - d).as_secs_f64())
            .unwrap_or(total.as_secs_f64()),
    ));
    Ok(())
}

fn lookup_reader(rpc: &RpcClient, wallet: &str, role: &str) -> Result<ReaderAddress> {
    let pk: solana_pubkey::Pubkey = wallet.parse().with_context(|| format!("{role} address"))?;
    tidex6_client::registry::lookup(rpc, &pk)?
        .map(|e| e.address)
        .with_context(|| {
            format!("{role} {wallet} has not enabled private payments (register at tidex6.com)")
        })
}

fn parse_network(s: Option<&str>) -> Result<Network> {
    match s {
        Some("mainnet") => Ok(Network::Mainnet),
        Some("devnet") => Ok(Network::Devnet),
        Some(o) => bail!("сеть: mainnet|devnet, не `{o}`"),
        None => bail!("нужна сеть: mainnet|devnet"),
    }
}

fn parse_amount(s: &str) -> Result<(Asset, u64, &'static str)> {
    Ok(match s {
        "usdc0_1" => (Asset::Wusdc, 100_000, "USDC"),
        "usdc1" => (Asset::Wusdc, 1_000_000, "USDC"),
        "usdc2" => (Asset::Wusdc, 2_000_000, "USDC"),
        "usdc3" => (Asset::Wusdc, 3_000_000, "USDC"),
        "usdc5" => (Asset::Wusdc, 5_000_000, "USDC"),
        "usdc10" => (Asset::Wusdc, 10_000_000, "USDC"),
        "usdt0_1" => (Asset::Wusdt, 100_000, "USDT"),
        "usdt1" => (Asset::Wusdt, 1_000_000, "USDT"),
        "usdt2" => (Asset::Wusdt, 2_000_000, "USDT"),
        "usdt3" => (Asset::Wusdt, 3_000_000, "USDT"),
        "usdt5" => (Asset::Wusdt, 5_000_000, "USDT"),
        "usdt10" => (Asset::Wusdt, 10_000_000, "USDT"),
        other => bail!("unknown amount `{other}`"),
    })
}

fn parse_lifetime(s: &str) -> Result<i64> {
    let s = s.trim().to_ascii_lowercase();
    let secs = if let Some(n) = s.strip_suffix('m') {
        n.parse::<i64>().context("lifetime minutes")? * 60
    } else if let Some(n) = s.strip_suffix('h') {
        n.parse::<i64>().context("lifetime hours")? * 3600
    } else if let Some(n) = s.strip_suffix('d') {
        n.parse::<i64>().context("lifetime days")? * 86400
    } else {
        s.parse::<i64>().context("lifetime seconds")?
    };
    if !(300..=30 * 86400).contains(&secs) {
        bail!("lifetime must be 5m … 30d");
    }
    Ok(secs)
}

fn print_help() {
    say("send — private payment (same library as local MCP)\n\n\
         Usage:\n  \
         send <mainnet|devnet> <amount> <recipient> [--auditor ADDR] [--memo TEXT] [--lifetime 12h]\n\n\
         amount: usdc0_1 usdc1 usdc2 usdc3 usdc5 usdc10\n         \
                 usdt0_1 usdt1 usdt2 usdt3 usdt5 usdt10\n\n\
         Signer: keypair_path in ~/.tidex6-local/config.toml");
}

fn say(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}
