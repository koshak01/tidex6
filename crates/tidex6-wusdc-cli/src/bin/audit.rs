//! Прочитать платежи, раскрытые этому кошельку как **аудитору** (library `scan`).
//!
//! Только сеть. USDC и USDT — оба пула автоматически. Кошелёк — из config.
//! Сумма и memo видны; spend (забрать) — нет.
//!
//! ```text
//! audit <mainnet|devnet>
//! ```
//!
//! Local MCP `audit` — тот же `scan` с `ReadAs::Auditor`.

use std::io::Write;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use solana_rpc_client::rpc_client::RpcClient;
use tidex6_client::confidential::{LocalIdentity, ReadAs, load_keypair, scan};
use tidex6_core::network::{Asset, Network};

#[derive(Deserialize)]
struct Config {
    keypair_path: String,
    rpc_mainnet: String,
    rpc_devnet: String,
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        say("audit — list payments disclosed to the config wallet as auditor\n\n\
             Usage:\n  audit <mainnet|devnet>\n\n\
             Scans USDC + USDT. Key: ~/.tidex6-local/config.toml");
        return Ok(());
    }
    let network = match args.first().map(String::as_str) {
        Some("mainnet") => Network::Mainnet,
        Some("devnet") => Network::Devnet,
        Some(o) => bail!("сеть: mainnet|devnet, не `{o}`"),
        None => bail!("нужна сеть: audit mainnet|devnet"),
    };

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

    say(&format!("wallet:  {wallet}  (config, as auditor)"));
    say(&format!("network: {network:?}"));
    say(&format!("pools:   USDC + USDT (auto)"));
    say("");

    let mut total_seen = 0usize;
    let mut total_mine = 0usize;

    for asset in [Asset::Wusdc, Asset::Wusdt] {
        let Some(info) = network.asset(asset) else {
            continue;
        };
        let Some(program) = info.pool_program else {
            continue;
        };
        let symbol = info.symbol.trim_start_matches('w');
        let program = program.parse().context("pool program")?;
        let report = scan(&rpc, &program, &identity, ReadAs::Auditor)
            .with_context(|| format!("scan {symbol}"))?;
        total_seen += report.envelopes_seen;
        total_mine += report.payments.len();
        say(&format!(
            "[{symbol}] envelopes={} disclosed_to_you={}",
            report.envelopes_seen,
            report.payments.len()
        ));
        for p in report.payments {
            let amount = p.amount_micro as f64 / 1e6;
            let memo = if p.memo.is_empty() {
                "(no memo)"
            } else {
                p.memo.as_str()
            };
            // sent_at on-chain; no sender (privacy).
            say(&format!(
                "  {} · {amount} {symbol} — {memo}",
                format_unix_utc(p.sent_at_unix)
            ));
        }
    }

    say("");
    if total_mine == 0 {
        say(&format!(
            "nothing disclosed to this auditor ({total_seen} envelopes scanned)"
        ));
    } else {
        say(&format!(
            "{total_mine} payment(s) disclosed ({total_seen} envelopes scanned)"
        ));
    }
    Ok(())
}

fn say(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}

fn format_unix_utc(ts: i64) -> String {
    if ts <= 0 {
        return "????-??-?? ??:?? UTC".into();
    }
    let secs = ts as u64;
    let days = secs / 86400;
    let tod = secs % 86400;
    let hour = tod / 3600;
    let min = (tod % 3600) / 60;
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
