//! Local MCP — thin shell over the same libraries as the stealth CLI.
//!
//! **Blocker fix:** no `spawn_blocking` + rayon storm; dedicated OS thread;
//! rayon pinned to 1 worker; **hard timeout (see HEAVY_TIMEOUT_SECS)** on heavy tools → `process::exit`
//! so a hang cannot live forever and thrash the machine.
//!
//! **Session isolation (Grok / any stdio host):**
//! Grok does not pass a stable session UUID into the child. Each MCP instance
//! is a child of the host process (`PPID`). On startup we **kill sibling**
//! `tidex6-mcp-local` processes with the **same PPID** (same host session /
//! same Grok parent), not other clients (different parent). That way a restart
//! does not leave a 100% CPU orphan under the same Grok, and does not kill
//! another IDE's MCP.
//!
//! stdout = MCP protocol. stderr = logs.

mod config;
mod handler;

use anyhow::Result;
use rmcp::ServiceExt;
use rmcp::transport::stdio;

fn main() -> Result<()> {
    // ark-groth16 default features pull rayon — pin before any prove.
    // Library Once + local build_global (no `unsafe` env mutation; crate denies it).
    tidex6_client::confidential::init_prover_runtime();
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build_global();

    // `selftest-collect mainnet|devnet` — same libraries as the tool, no rmcp/stdio.
    // Used to A/B thrash: if this is ~50 MB and tools/call multi-GB, the host path
    // (rmcp + long-lived tokio) is the difference, not the circuit itself.
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("selftest-collect") {
        let net = args.next().unwrap_or_else(|| "mainnet".into());
        return selftest_collect(&net);
    }

    // Before listening: reap prior instances from *this* host session only.
    reap_same_session_siblings();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("mcp-rt")
        .build()?;

    rt.block_on(async_main())
}

/// Cold path through the same binary as MCP, without stdio protocol.
fn selftest_collect(net: &str) -> Result<()> {
    use tidex6_client::confidential::{
        LocalIdentity, PoolService, collect_waiting, load_keypair,
    };
    use tidex6_core::network::Network;

    let network = match net {
        "mainnet" => Network::Mainnet,
        "devnet" => Network::Devnet,
        other => anyhow::bail!("selftest-collect: mainnet|devnet, not {other}"),
    };

    // Optional A/B: `TIDEX6_SELFTEST_TRACING=1` installs the *serve* filter
    // (warn + our crates). `TIDEX6_SELFTEST_TRACING=info` reproduces the
    // historical thrash (global info).
    if let Ok(mode) = std::env::var("TIDEX6_SELFTEST_TRACING") {
        let filter = if mode == "info" {
            "info,tidex6_mcp_local=debug".to_string()
        } else {
            "warn,tidex6_mcp_local=info,rmcp=info".to_string()
        };
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(tracing_subscriber::EnvFilter::new(&filter))
            .init();
        eprintln!("selftest: tracing_subscriber filter={filter}");
    }

    let t0 = std::time::Instant::now();
    let mut peak = rss_kb();
    let mark = |step: &str, peak: &mut u64| {
        let r = rss_kb();
        *peak = (*peak).max(r);
        eprintln!(
            "selftest: step={step:28} elapsed_ms={:>6} rss_kb={r:>8} peak_kb={peak} \
             rayon_threads={}",
            t0.elapsed().as_millis(),
            rayon::current_num_threads(),
        );
    };
    mark("start", &mut peak);

    let config = config::Config::load()?;
    let keypair = load_keypair(&config.keypair_path)?;
    let identity = LocalIdentity::from_keypair(&keypair)?;
    let wallet = identity.wallet.to_string();
    let pk = config
        .proving_key()
        .map(|p| p.to_string_lossy().into_owned())?;
    let rpc = config.rpc_for(network).to_string();
    let service = PoolService::new(config.pool_service.clone())?;
    mark("config_ok", &mut peak);

    // Same shape as thrash_live / tool path: multi-thread tokio + OS worker.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("mcp-rt")
        .build()?;
    mark("tokio_ok", &mut peak);

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
                let r = collect_waiting(&rpc2, &svc2, &id2, &pk2, network, &to, |step| {
                    let r = rss_kb();
                    peak_t = peak_t.max(r);
                    if step.contains("prove") || step.contains("scan") || step.contains("merkle") {
                        eprintln!(
                            "selftest: on_step={step} rss_kb={r} peak={peak_t} \
                             rayon_threads={}",
                            rayon::current_num_threads()
                        );
                    }
                });
                let _ = tx.send((r, peak_t));
            })?;
        let (inner, child_peak) = rx.await.map_err(|_| anyhow::anyhow!("worker dropped"))?;
        Ok::<_, anyhow::Error>((inner, child_peak))
    })?;

    let (inner, child_peak) = result;
    peak = peak.max(child_peak).max(rss_kb());
    match inner {
        Ok(res) => {
            eprintln!(
                "selftest: RESULT ok notes={} waiting={} stopped={:?} \
                 peak_kb={} child_peak_kb={} total_ms={} rayon_threads={}",
                res.notes.len(),
                res.waiting_found,
                res.stopped_by,
                peak,
                child_peak,
                t0.elapsed().as_millis(),
                rayon::current_num_threads(),
            );
            for n in &res.notes {
                eprintln!("  note {} {} {}", n.symbol, n.amount_micro, n.signature);
            }
        }
        Err(e) => {
            eprintln!("selftest: FAIL {e:#} peak_kb={peak}");
            return Err(e);
        }
    }
    Ok(())
}

async fn async_main() -> Result<()> {
    // CRITICAL: default must NOT be global `info`.
    // arkworks / r1cs / groth16 pull `tracing`; under `info` the constraint
    // walk emits a flood of events → multi-GB thrash on prove (observed:
    // tools/call and selftest+tracing stick in prove_withdraw for minutes at
    // multi-GB RSS; same note without tracing finishes ~2s at ~55 MB).
    // Operators can still raise with RUST_LOG=info if they accept the cost.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "warn,tidex6_mcp_local=info,rmcp=info".into()
            }),
        )
        .init();

    log_boot("start");
    log_boot(&tidex6_client::confidential::prover_runtime_status());
    log_boot("rayon_global_pool_num_threads=1");
    log_boot(&format!(
        "pid={} ppid={} cpus={:?} heavy_timeout_secs={}",
        std::process::id(),
        parent_pid(),
        std::thread::available_parallelism(),
        handler::HEAVY_TIMEOUT_SECS,
    ));

    let config = config::Config::load()?;
    log_boot("config_ok");
    let tools = handler::LocalTools::new(config)?;
    log_boot(&format!("wallet={}", tools.wallet()));

    let service = tools.serve(stdio()).await?;
    log_boot("stdio_listening");
    service.waiting().await?;
    log_boot("exit");
    Ok(())
}

/// Kill other `tidex6-mcp-local` that share our parent (same Grok/stdio host).
/// Leaves processes owned by other apps (different PPID) alone.
fn reap_same_session_siblings() {
    let me = std::process::id();
    let my_ppid = parent_pid();
    let exe_mark = "tidex6-mcp-local";
    let out = std::process::Command::new("ps")
        .args(["-axo", "pid=,ppid=,command="])
        .output();
    let Ok(out) = out else {
        return;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if !line.contains(exe_mark) {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(pid_s) = parts.next() else { continue };
        let Some(ppid_s) = parts.next() else { continue };
        let Ok(pid) = pid_s.parse::<u32>() else { continue };
        let Ok(ppid) = ppid_s.parse::<u32>() else { continue };
        if pid == me {
            continue;
        }
        if ppid != my_ppid {
            // Different host session / different client — do not touch.
            eprintln!(
                "mcp-local BOOT skip foreign pid={pid} ppid={ppid} (mine ppid={my_ppid})"
            );
            continue;
        }
        eprintln!(
            "mcp-local BOOT reap sibling same-session pid={pid} ppid={ppid} (me={me})"
        );
        let _ = std::process::Command::new("kill")
            .args(["-9", &pid.to_string()])
            .status();
    }
}

fn parent_pid() -> u32 {
    let me = std::process::id().to_string();
    let out = std::process::Command::new("ps")
        .args(["-o", "ppid=", "-p", &me])
        .output()
        .ok();
    out.and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}

fn log_boot(msg: &str) {
    eprintln!(
        "mcp-local BOOT pid={} rss_kb={} msg={msg}",
        std::process::id(),
        rss_kb()
    );
}

fn rss_kb() -> u64 {
    let pid = std::process::id().to_string();
    std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}
