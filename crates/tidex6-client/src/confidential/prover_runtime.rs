//! Runtime hygiene for CPU-bound Groth16 prove (long-lived hosts).
//!
//! # Why this exists
//!
//! `ark-groth16` enables the `parallel` feature by default and fans work out
//! through **rayon**. That is fine for a short-lived CLI process that proves
//! once and exits. It is a footgun for **long-lived** hosts (local MCP, agent
//! runtimes, web workers) that wrap prove in `tokio::task::spawn_blocking`:
//!
//! 1. Soft timeouts **cannot cancel** a `spawn_blocking` task.
//! 2. A timed-out job is marked failed while the prove thread keeps running.
//! 3. Rayon defaults to ~`num_cpus` workers; under memory pressure the process
//!    thrash-grows RSS (observed: multi-GB, ~99% CPU for minutes) while a cold
//!    CLI prove of the same note finishes in ~seconds at ~50 MB.
//! 4. Restarting the host without reaping orphans multiplies the thrash.
//!
//! Offline A/B (`repro_mcp_hang`) on free RAM: plain / OS-thread /
//! `spawn_blocking` / rayon-16 all complete in ~2–5 s at ~50–75 MB. The
//! multi-GB failure is the **stacked uncancellable worker + thrash** mode,
//! not the steady-state cost of one prove.
//!
//! # Library contract
//!
//! Call [`init_prover_runtime`] once at process start (before any prove).
//! Hosts must **not** run prove on a tokio worker or via `spawn_blocking`;
//! use a dedicated OS thread and a hard process-level deadline if the host
//! cannot tolerate a runaway prove.
//!
//! See `docs/SECURITY_NOTE_SPAWN_BLOCKING_PROVE.md`.

use std::sync::Once;

static INIT: Once = Once::new();

/// Pin the global rayon pool used by arkworks MSM / QAP helpers.
///
/// Safe to call many times; only the first call installs the pool. If another
/// crate already built the global pool, this is a no-op (rayon returns `Err`)
/// — set `RAYON_NUM_THREADS=1` in the environment **before** process start as
/// a belt-and-braces fallback.
pub fn init_prover_runtime() {
    INIT.call_once(|| {
        // Prefer env if the operator already constrained the process.
        if std::env::var_os("RAYON_NUM_THREADS").is_none() {
            // Best-effort: ignore if the global pool is already built.
            let _ = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .thread_name(|i| format!("tidex6-rayon-{i}"))
                .build_global();
        }
    });
}

/// Human-readable status for logs / MCP boot banners.
pub fn prover_runtime_status() -> String {
    let env = std::env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".into());
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    format!("RAYON_NUM_THREADS={env} available_parallelism={cpus} (ark-groth16 parallel→rayon pinned when possible)")
}
