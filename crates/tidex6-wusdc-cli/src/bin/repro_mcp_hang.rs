//! A/B repro: same `prove_withdraw` under CLI-like vs MCP-like wrappers.
//!
//! Goal: isolate whether hang/multi‑GB RSS is **library crypto under rayon**
//! or **tokio spawn_blocking + rayon** (MCP anomaly). Offline — no chain.
//!
//! ```text
//! cargo run --release -p tidex6-wusdc-cli --bin repro_mcp_hang -- all
//! cargo run --release -p tidex6-wusdc-cli --bin repro_mcp_hang -- plain
//! cargo run --release -p tidex6-wusdc-cli --bin repro_mcp_hang -- blocking
//! cargo run --release -p tidex6-wusdc-cli --bin repro_mcp_hang -- os_thread
//! cargo run --release -p tidex6-wusdc-cli --bin repro_mcp_hang -- blocking_rayon16
//! ```
//!
//! TRACE lines: `REPRO mode=… step=… elapsed_ms=… rss_kb=…`

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use ark_bn254::Bn254;
use ark_groth16::ProvingKey;
use ark_serialize::CanonicalDeserialize;
use ark_std::rand::thread_rng;
use tidex6_circuits::withdraw::{
    WITHDRAW_TREE_DEPTH, WithdrawWitness, prove_withdraw, relayer_fee_bytes_from_u64,
};
use tidex6_core::merkle::MerkleTree;
use tidex6_core::types::{Commitment, Nullifier, Secret};

fn rss_kb() -> u64 {
    let pid = std::process::id().to_string();
    Command::new("ps")
        .args(["-o", "rss=", "-p", &pid])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}

fn tr(mode: &str, step: &str, t0: Instant, peak: &mut u64) {
    let rss = rss_kb();
    *peak = (*peak).max(rss);
    eprintln!(
        "REPRO mode={mode:22} step={step:28} elapsed_ms={:>6} rss_kb={:>8} peak_rss_kb={:>8}",
        t0.elapsed().as_millis(),
        rss,
        *peak
    );
}

struct Prepared {
    pk: ProvingKey<Bn254>,
    secret: [u8; 32],
    nullifier: [u8; 32],
    siblings: Vec<[u8; 32]>,
    path_indices: [bool; WITHDRAW_TREE_DEPTH],
    root: [u8; 32],
    nullifier_hash: [u8; 32],
    recipient: [u8; 32],
    relayer_fee: [u8; 32],
}

fn prepare(pk_path: &PathBuf) -> Result<Prepared> {
    let t0 = Instant::now();
    let mut peak = rss_kb();
    tr("prepare", "start", t0, &mut peak);

    let secret = Secret::random()?;
    let nullifier = Nullifier::random()?;
    let commitment = Commitment::derive(&secret, &nullifier)?;
    let mut tree = MerkleTree::new(WITHDRAW_TREE_DEPTH)?;
    tree.insert(commitment)?;
    let proof = tree.proof(0)?;
    let root = *tree.root().as_bytes();
    let nullifier_hash = nullifier.derive_hash()?.to_bytes();
    let siblings: Vec<[u8; 32]> = proof.siblings.iter().map(|c| *c.as_bytes()).collect();
    let mut path_indices = [false; WITHDRAW_TREE_DEPTH];
    for (i, bit) in path_indices.iter_mut().enumerate() {
        *bit = (proof.leaf_index >> i) & 1 == 1;
    }
    tr("prepare", "witness_ok", t0, &mut peak);

    let key_bytes =
        std::fs::read(pk_path).with_context(|| format!("read {}", pk_path.display()))?;
    tr("prepare", "pk_read_ok", t0, &mut peak);
    let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&key_bytes[..])?;
    tr("prepare", "pk_deser_ok", t0, &mut peak);
    drop(key_bytes);

    Ok(Prepared {
        pk,
        secret: *secret.as_bytes(),
        nullifier: *nullifier.as_bytes(),
        siblings,
        path_indices,
        root,
        nullifier_hash,
        recipient: [0x11u8; 32],
        relayer_fee: relayer_fee_bytes_from_u64(0),
    })
}

fn do_prove(p: &Prepared) -> Result<()> {
    let sibling_refs: [&[u8; 32]; WITHDRAW_TREE_DEPTH] = std::array::from_fn(|i| &p.siblings[i]);
    let witness = WithdrawWitness::<WITHDRAW_TREE_DEPTH> {
        secret: &p.secret,
        nullifier: &p.nullifier,
        path_siblings: sibling_refs,
        path_indices: p.path_indices,
        merkle_root: &p.root,
        nullifier_hash: &p.nullifier_hash,
        recipient: &p.recipient,
        relayer_address: &p.recipient,
        relayer_fee: &p.relayer_fee,
    };
    let mut rng = thread_rng();
    let (_proof, _) = prove_withdraw::<WITHDRAW_TREE_DEPTH, _>(&p.pk, witness, &mut rng)?;
    Ok(())
}

fn run_plain(p: &Arc<Prepared>) -> Result<(u128, u64)> {
    let t0 = Instant::now();
    let mut peak = rss_kb();
    tr("plain_main", "prove_start", t0, &mut peak);
    do_prove(p)?;
    tr("plain_main", "prove_ok", t0, &mut peak);
    Ok((t0.elapsed().as_millis(), peak))
}

fn run_os_thread(p: &Arc<Prepared>) -> Result<(u128, u64)> {
    let t0 = Instant::now();
    let mut peak = rss_kb();
    tr("os_thread", "spawn", t0, &mut peak);
    let (tx, rx) = mpsc::channel();
    let p2 = Arc::clone(p);
    std::thread::Builder::new()
        .name("repro-os".into())
        .spawn(move || {
            let r = do_prove(&p2);
            let _ = tx.send(r);
        })?;
    loop {
        match rx.try_recv() {
            Ok(r) => {
                r?;
                tr("os_thread", "prove_ok", t0, &mut peak);
                return Ok((t0.elapsed().as_millis(), peak));
            }
            Err(mpsc::TryRecvError::Empty) => {
                peak = peak.max(rss_kb());
                if t0.elapsed() > Duration::from_secs(60) {
                    anyhow::bail!("os_thread TIMEOUT 60s peak_rss_kb={peak}");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(mpsc::TryRecvError::Disconnected) => anyhow::bail!("os_thread disconnected"),
        }
    }
}

/// Exact MCP pattern: rayon=1 already; tokio multi_thread(2) like mcp-rt;
/// OS thread `lib-collect_waiting` + oneshot await (handler::run_on_os_thread).
fn run_mcp_like(p: &Arc<Prepared>) -> Result<(u128, u64)> {
    let t0 = Instant::now();
    let mut peak = rss_kb();
    tr("mcp_like", "rt_build", t0, &mut peak);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("mcp-rt")
        .build()?;
    tr("mcp_like", "rt_ok", t0, &mut peak);

    let p2 = Arc::clone(p);
    let result = rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("lib-collect_waiting".into())
            .spawn(move || {
                let r = do_prove(&p2);
                let _ = tx.send(r);
            })
            .map_err(|e| anyhow::anyhow!("spawn: {e}"))?;

        // Same hard wait shape as MCP (no soft cancel).
        match tokio::time::timeout(Duration::from_secs(120), rx).await {
            Ok(Ok(inner)) => inner.map_err(|e| anyhow::anyhow!("{e:#}")),
            Ok(Err(_)) => anyhow::bail!("worker dropped"),
            Err(_) => anyhow::bail!("HARD_TIMEOUT 120s"),
        }
    });

    peak = peak.max(rss_kb());
    result?;
    tr("mcp_like", "prove_ok", t0, &mut peak);
    Ok((t0.elapsed().as_millis(), peak))
}

/// MCP-like + hold ~80 MB alive during prove (dirty multi-thread heap).
fn run_mcp_like_hold(p: &Arc<Prepared>) -> Result<(u128, u64)> {
    let t0 = Instant::now();
    let mut peak = rss_kb();
    // Touch memory so RSS is real, not virtual.
    let mut hold = vec![0u8; 80 * 1024 * 1024];
    for (i, b) in hold.iter_mut().enumerate().step_by(4096) {
        *b = (i % 251) as u8;
    }
    tr("mcp_like_hold", "hold_80mb", t0, &mut peak);
    peak = peak.max(rss_kb());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("mcp-rt")
        .build()?;
    let p2 = Arc::clone(p);
    let result = rt.block_on(async move {
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::Builder::new()
            .name("lib-collect_waiting".into())
            .spawn(move || {
                let r = do_prove(&p2);
                let _ = tx.send(r);
            })
            .map_err(|e| anyhow::anyhow!("spawn: {e}"))?;
        match tokio::time::timeout(Duration::from_secs(120), rx).await {
            Ok(Ok(inner)) => inner.map_err(|e| anyhow::anyhow!("{e:#}")),
            Ok(Err(_)) => anyhow::bail!("worker dropped"),
            Err(_) => anyhow::bail!("HARD_TIMEOUT 120s"),
        }
    });
    // keep hold until prove done
    peak = peak.max(rss_kb());
    let _touch = hold[0];
    drop(hold);
    result?;
    tr("mcp_like_hold", "prove_ok", t0, &mut peak);
    Ok((t0.elapsed().as_millis(), peak))
}

fn run_spawn_blocking(p: &Arc<Prepared>) -> Result<(u128, u64)> {
    let t0 = Instant::now();
    let mut peak = rss_kb();
    tr("spawn_blocking", "rt_build", t0, &mut peak);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .thread_name("repro-rt")
        .build()?;
    tr("spawn_blocking", "rt_ok", t0, &mut peak);

    let p2 = Arc::clone(p);
    let handle = rt.spawn(async move {
        tokio::task::spawn_blocking(move || do_prove(&p2))
            .await
            .expect("join")
    });

    loop {
        if handle.is_finished() {
            break;
        }
        peak = peak.max(rss_kb());
        if t0.elapsed() > Duration::from_secs(60) {
            anyhow::bail!("spawn_blocking TIMEOUT 60s peak_rss_kb={peak}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    rt.block_on(handle)??;
    tr("spawn_blocking", "prove_ok", t0, &mut peak);
    Ok((t0.elapsed().as_millis(), peak))
}

fn run_blocking_rayon16(p: &Arc<Prepared>) -> Result<(u128, u64)> {
    let t0 = Instant::now();
    let mut peak = rss_kb();
    tr("blocking_rayon16", "start", t0, &mut peak);
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(16)
        .build()
        .context("rayon pool 16")?;
    let p2 = Arc::clone(p);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    let handle = rt.spawn(async move {
        tokio::task::spawn_blocking(move || pool.install(|| do_prove(&p2)))
            .await
            .expect("join")
    });
    loop {
        if handle.is_finished() {
            break;
        }
        peak = peak.max(rss_kb());
        if t0.elapsed() > Duration::from_secs(90) {
            anyhow::bail!("blocking_rayon16 TIMEOUT 90s peak_rss_kb={peak}");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    rt.block_on(handle)??;
    tr("blocking_rayon16", "prove_ok", t0, &mut peak);
    Ok((t0.elapsed().as_millis(), peak))
}

/// Simulate the **historical MCP bug**: soft-timeout spawn_blocking without
/// joining, then stack more proves. On free RAM this may still finish; the
/// point is to show RSS/CPU while orphans are live (and document why hard
/// `process::exit` is required).
fn run_orphan_stack(p: &Arc<Prepared>) -> Result<(u128, u64)> {
    let t0 = Instant::now();
    let mut peak = rss_kb();
    tr("orphan_stack", "start", t0, &mut peak);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(32)
        .enable_all()
        .build()?;

    // Fire 4 blocking proves; "soft timeout" after 200ms without aborting them.
    let mut handles = Vec::new();
    for i in 0..4 {
        let p2 = Arc::clone(p);
        handles.push(rt.spawn(async move {
            tokio::task::spawn_blocking(move || {
                let _ = do_prove(&p2);
            })
            .await
        }));
        tr("orphan_stack", &format!("spawned_{i}"), t0, &mut peak);
        // Soft "timeout" — we stop awaiting this one and spawn another.
        std::thread::sleep(Duration::from_millis(100));
        peak = peak.max(rss_kb());
    }

    // Observe stacked workers for up to 30s (do not abort — that is the bug).
    while t0.elapsed() < Duration::from_secs(30) {
        peak = peak.max(rss_kb());
        let done = handles.iter().filter(|h| h.is_finished()).count();
        tr(
            "orphan_stack",
            &format!("live done={done}/4"),
            t0,
            &mut peak,
        );
        if done == 4 {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    for h in handles {
        let _ = rt.block_on(h);
    }
    tr("orphan_stack", "all_joined", t0, &mut peak);
    Ok((t0.elapsed().as_millis(), peak))
}

fn main() -> Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "all".into());
    let home = std::env::var("HOME")?;
    let pk = PathBuf::from(format!("{home}/.tidex6-local/withdraw_pk_depth20.bin"));
    eprintln!(
        "REPRO start pid={} cpus={:?} mode={mode}",
        std::process::id(),
        std::thread::available_parallelism()
    );

    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build_global();

    let prepared = Arc::new(prepare(&pk)?);
    let mut results: Vec<(&str, u128, u64)> = Vec::new();

    let modes: Vec<&str> = if mode == "all" {
        vec![
            "plain",
            "os_thread",
            "mcp_like",
            "mcp_like_hold",
            "blocking",
            "blocking_rayon16",
            "orphan_stack",
        ]
    } else {
        vec![mode.as_str()]
    };

    for m in modes {
        eprintln!("\n======== MODE {m} ========");
        std::thread::sleep(Duration::from_millis(200));
        let r = match m {
            "plain" => run_plain(&prepared),
            "os_thread" => run_os_thread(&prepared),
            "mcp_like" => run_mcp_like(&prepared),
            "mcp_like_hold" => run_mcp_like_hold(&prepared),
            "blocking" => run_spawn_blocking(&prepared),
            "blocking_rayon16" => run_blocking_rayon16(&prepared),
            "orphan_stack" => run_orphan_stack(&prepared),
            other => anyhow::bail!("unknown mode {other}"),
        };
        match r {
            Ok((ms, peak)) => {
                eprintln!("REPRO RESULT mode={m} prove_ms={ms} peak_rss_kb={peak}");
                results.push((m, ms, peak));
            }
            Err(e) => {
                eprintln!("REPRO FAIL mode={m} err={e:#} peak_rss_kb={}", rss_kb());
            }
        }
    }

    eprintln!("\n======== SUMMARY ========");
    for (m, ms, peak) in &results {
        eprintln!(
            "  {m:22} prove_ms={ms:>6} peak_rss_mb={:>7.1}",
            *peak as f64 / 1024.0
        );
    }
    eprintln!(
        "\nInterpretation:\n\
         - plain ≈ CLI path\n\
         - os_thread ≈ fixed MCP worker\n\
         - blocking ≈ old MCP (tokio spawn_blocking)\n\
         - blocking_rayon16 ≈ multi-rayon under spawn_blocking\n\
         - orphan_stack ≈ soft-timeout without cancel (historical multi-GB class)\n\
         Steady-state prove is ~50 MB. Multi-GB needs thrash + stacked orphans.\n\
         See docs/SECURITY_NOTE_SPAWN_BLOCKING_PROVE.md"
    );
    Ok(())
}
