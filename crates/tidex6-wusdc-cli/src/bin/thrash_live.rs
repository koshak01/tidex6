//! Живой repro thrash: как MCP — tokio multi_thread(2) + OS-thread +
//! `collect_waiting` (scan mainnet + prove). Без child-костыля.
//!
//! ```text
//! cargo run --release -p tidex6-wusdc-cli --bin thrash_live -- mainnet
//! ```
//!
//! Печатает RSS на вехах. CLI-cold: `collect mainnet` ~50 MB.
//! Если тут multi-100MB на commitment — thrash = long-lived host + полный collect.

use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
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

fn rss_kb() -> u64 {
    let pid = std::process::id().to_string();
    Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}

fn mark(step: &str, t0: Instant, peak: &mut u64) {
    let r = rss_kb();
    *peak = (*peak).max(r);
    eprintln!(
        "thrash_live: step={step:28} elapsed_ms={:>6} rss_kb={:>8} peak_kb={:>8} thread={:?}",
        t0.elapsed().as_millis(),
        r,
        *peak,
        std::thread::current().name().unwrap_or("?"),
    );
}

fn main() -> Result<()> {
    let net = match std::env::args().nth(1).as_deref() {
        Some("mainnet") | None => Network::Mainnet,
        Some("devnet") => Network::Devnet,
        Some(o) => bail!("mainnet|devnet, not {o}"),
    };

    // Как MCP main:
    init_prover_runtime();
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build_global();

    let t0 = Instant::now();
    let mut peak = rss_kb();
    mark("start", t0, &mut peak);

    let home = std::env::var("HOME")?;
    let cfg: Config = toml::from_str(&std::fs::read_to_string(format!(
        "{home}/.tidex6-local/config.toml"
    ))?)?;
    let keypair = load_keypair(&cfg.keypair_path)?;
    let identity = LocalIdentity::from_keypair(&keypair)?;
    let wallet = identity.wallet.to_string();
    let pk = cfg
        .proving_key_path
        .unwrap_or_else(|| format!("{home}/.tidex6-local/withdraw_pk_depth20.bin"));
    let rpc = match net {
        Network::Mainnet => cfg.rpc_mainnet.clone(),
        Network::Devnet => cfg.rpc_devnet.clone(),
    };
    let service = PoolService::new(cfg.pool_service.clone())?;
    mark("config_ok", t0, &mut peak);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("mcp-rt")
        .build()?;
    mark("tokio_ok", t0, &mut peak);

    let identity = std::sync::Arc::new(identity);
    let service = std::sync::Arc::new(service);

    let result = rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let id2 = std::sync::Arc::clone(&identity);
        let svc2 = std::sync::Arc::clone(&service);
        let rpc2 = rpc.clone();
        let pk2 = pk.clone();
        let to = wallet.clone();

        std::thread::Builder::new()
            .name("lib-collect_waiting".into())
            .spawn(move || {
                let mut peak_t = rss_kb();
                let t_lib = Instant::now();
                eprintln!(
                    "thrash_live: OS thread entered rss_kb={} peak={}",
                    peak_t, peak_t
                );
                let r = collect_waiting(
                    &rpc2,
                    &svc2,
                    &id2,
                    &pk2,
                    net,
                    &to,
                    |step| {
                        let r = rss_kb();
                        peak_t = peak_t.max(r);
                        // только редкие вехи prove
                        if step.contains("prove") || step.contains("merkle") || step.contains("scan")
                        {
                            eprintln!(
                                "thrash_live: on_step={step} rss_kb={r} peak={peak_t} lib_ms={}",
                                t_lib.elapsed().as_millis()
                            );
                        }
                    },
                );
                eprintln!(
                    "thrash_live: OS thread done ok={} peak_kb={} lib_ms={}",
                    r.is_ok(),
                    peak_t,
                    t_lib.elapsed().as_millis()
                );
                let _ = tx.send((r, peak_t));
            })
            .context("spawn lib thread")?;

        let mut peak_parent = rss_kb();
        let mut rx = rx;
        loop {
            peak_parent = peak_parent.max(rss_kb());
            match tokio::time::timeout(Duration::from_millis(500), &mut rx).await {
                Ok(Ok((inner, child_peak))) => {
                    return Ok::<_, anyhow::Error>((inner, child_peak, peak_parent));
                }
                Ok(Err(_)) => bail!("oneshot dropped"),
                Err(_) => {
                    if t0.elapsed() > Duration::from_secs(120) {
                        bail!("HARD_TIMEOUT 120s parent_peak={peak_parent}");
                    }
                }
            }
        }
    })?;

    let (inner, child_peak, parent_peak) = result;
    match inner {
        Ok(res) => {
            eprintln!(
                "thrash_live: RESULT ok notes={} waiting={} stopped={:?} \
                 child_peak_kb={} parent_peak_kb={} total_ms={}",
                res.notes.len(),
                res.waiting_found,
                res.stopped_by,
                child_peak,
                parent_peak,
                t0.elapsed().as_millis()
            );
            for n in &res.notes {
                eprintln!("  note {} {} {}", n.symbol, n.amount_micro, n.signature);
            }
        }
        Err(e) => {
            eprintln!(
                "thrash_live: FAIL {e:#} child_peak_kb={} parent_peak_kb={}",
                child_peak, parent_peak
            );
            return Err(e);
        }
    }
    Ok(())
}
