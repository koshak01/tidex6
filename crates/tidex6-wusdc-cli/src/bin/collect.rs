//! Забрать **все** waiting stealth-платежи (библиотека `collect_waiting`).
//!
//! Только сеть. USDC и USDT — оба пула автоматически. Кошелёк — из config.
//! Куда вывести — тот же кошелёк (ordinary balance).
//!
//! ```text
//! collect <mainnet|devnet> [--json]
//! ```
//!
//! Local MCP runs this binary as a **cold child process** (same prove as CLI
//! main — avoids long-lived host thrash). `--json` is for MCP.

use std::io::Write;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde::Serialize;
use tidex6_client::confidential::{
    LocalIdentity, PoolService, collect_waiting, init_prover_runtime, load_keypair,
};
use tidex6_core::network::Network;

#[derive(Deserialize)]
struct Config {
    keypair_path: String,
    rpc_mainnet: String,
    rpc_devnet: String,
    #[serde(default = "default_pool")]
    pool_service: String,
    #[serde(default)]
    proving_key_path: Option<String>,
}

fn default_pool() -> String {
    "https://tidex6.com".to_string()
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        say("collect — take all waiting notes for the config wallet\n\n\
             Usage:\n  collect <mainnet|devnet> [--json]\n\n\
             Scans USDC + USDT pools. Signer/recipient: ~/.tidex6-local/config.toml\n\
             --json: machine output for MCP (cold child process).");
        return Ok(());
    }
    let json = args.iter().any(|a| a == "--json");
    let network = match args.iter().map(String::as_str).find(|a| *a != "--json") {
        Some("mainnet") => Network::Mainnet,
        Some("devnet") => Network::Devnet,
        Some(o) => bail!("сеть: mainnet|devnet, не `{o}`"),
        None => bail!("нужна сеть: collect mainnet|devnet"),
    };

    let home = std::env::var("HOME").context("$HOME")?;
    let cfg_path = format!("{home}/.tidex6-local/config.toml");
    let config: Config = toml::from_str(
        &std::fs::read_to_string(&cfg_path).with_context(|| format!("нет {cfg_path}"))?,
    )?;

    let keypair = load_keypair(&config.keypair_path)?;
    let identity = LocalIdentity::from_keypair(&keypair)?;
    let wallet = identity.wallet.to_string();
    // Получение = забрать всё себе. Адрес вывода = config wallet.
    let recipient = wallet.clone();
    let proving_key = config
        .proving_key_path
        .unwrap_or_else(|| format!("{home}/.tidex6-local/withdraw_pk_depth20.bin"));
    let rpc_url = match network {
        Network::Mainnet => config.rpc_mainnet.as_str(),
        Network::Devnet => config.rpc_devnet.as_str(),
    };
    let service = PoolService::new(config.pool_service.clone())?;
    init_prover_runtime();

    if !json {
        say(&format!("wallet:  {wallet}  (config)"));
        say(&format!("network: {network:?}"));
        say(&format!("to:      {recipient}  (same wallet)"));
        say(&format!("pools:   USDC + USDT (auto)"));
        say("");
    }

    let t0 = Instant::now();
    let result = collect_waiting(
        rpc_url,
        &service,
        &identity,
        &proving_key,
        network,
        &recipient,
        |step| {
            if !json {
                say(&format!("· {step}"));
            }
        },
    )?;
    let elapsed = t0.elapsed().as_secs_f64();

    if json {
        #[derive(Serialize)]
        struct NoteOut {
            symbol: &'static str,
            amount_micro: u64,
            signature: String,
        }
        #[derive(Serialize)]
        struct Out {
            ok: bool,
            waiting_found: usize,
            notes: Vec<NoteOut>,
            recipient: String,
            stopped_by: Option<String>,
            elapsed_secs: f64,
        }
        let notes: Vec<NoteOut> = result
            .notes
            .iter()
            .map(|n| NoteOut {
                symbol: n.symbol,
                amount_micro: n.amount_micro,
                signature: n.signature.clone(),
            })
            .collect();
        // Success only if we collected ≥1 note and did not stop mid-way with error
        // after zero notes. Partial (notes + stopped_by) → ok=false, notes kept.
        let out = Out {
            ok: result.stopped_by.is_none() && !notes.is_empty(),
            waiting_found: result.waiting_found,
            notes,
            recipient: result.recipient,
            stopped_by: result.stopped_by.clone(),
            elapsed_secs: elapsed,
        };
        println!("{}", serde_json::to_string(&out)?);
        if result.stopped_by.is_some() {
            std::process::exit(1);
        }
        return Ok(());
    }

    say("");
    if result.notes.is_empty() {
        if let Some(err) = &result.stopped_by {
            bail!("{err}");
        }
        say("nothing waiting to collect");
        say(&format!("TIME collect: {elapsed:.2}s"));
        return Ok(());
    }
    for n in &result.notes {
        say(&format!(
            "[{}] {} — https://solscan.io/tx/{}",
            n.symbol,
            micro_dec(n.amount_micro),
            n.signature
        ));
    }
    say(&format!(
        "collected {} note(s) ({}) → {recipient}",
        result.notes.len(),
        result.totals_line()
    ));
    say(&format!("TIME collect: {elapsed:.2}s"));
    if let Some(err) = &result.stopped_by {
        bail!("partial collect, then stopped: {err}");
    }
    Ok(())
}

fn micro_dec(micro: u64) -> String {
    let whole = micro / 1_000_000;
    let frac = micro % 1_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    format!("{whole}.{frac:06}")
        .trim_end_matches('0')
        .to_string()
}

fn say(line: &str) {
    println!("{line}");
    let _ = std::io::stdout().flush();
}
