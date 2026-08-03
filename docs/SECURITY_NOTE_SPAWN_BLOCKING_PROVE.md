# Security note: uncancellable `spawn_blocking` + arkworks parallel prove

**Status:** Confirmed incident class (2026-08-01…2026-08-02)  
**Severity:** High for long-lived local agents (resource exhaustion / DoS of host)  
**Not a consensus bug.** Does not forge notes, break nullifiers, or weaken the on-chain verifier.  
**Is a host-safety bug** when the same Groth16 path is embedded in MCP / agent processes.

## Summary

Wrapping `tidex6_circuits::withdraw::prove_withdraw` (or any `ark-groth16` prove
with default features) in `tokio::task::spawn_blocking` and applying only a
**soft** timeout produces **orphan CPU/RAM workers**. Under memory pressure those
workers thrash; RSS was observed climbing into multi-GB while CPU stuck near 99%
for minutes. The same note, collected via a short-lived CLI on free RAM, finished
in ~12–15 s.

## Evidence

| Measurement | Result |
|---|---|
| Offline single prove (`prove_rss`, free RAM) | ~2.5 s, peak ~50 MB |
| Offline A/B (`repro_mcp_hang all`) | plain 4.9 s / 48 MB; OS thread 5.4 s / 59 MB; `spawn_blocking` 5.4 s / 67 MB; rayon-16 1.7 s / 76 MB |
| 8 concurrent `prove_rss` processes | aggregate ~378 MB, all finished ~7 s |
| Live MCP hang (jobs + `spawn_blocking`, 2026-08-01) | PID ~7 min @ ~99% CPU, **~2.9 GB RSS**, host free ~20 MB |
| Live MCP after hard timeout rewrite | tool ends at **~45170 ms** with `Transport closed` (= `process::exit(99)` at 45 s) |
| CLI salvage of the same waiting note | ~12.5 s success |

**Interpretation:** Steady-state prove cost is modest (~50 MB, few seconds). The
catastrophic multi-GB mode is **stacked uncancellable work + thrash**, not a
hidden O(GB) allocation inside one healthy prove.

## Root cause chain

1. `ark-groth16` **default features** include `parallel` → rayon.
2. `ark-ec` MSM (`msm_bigint`) uses `cfg_into_iter!` / `into_par_iter` under that feature.
3. Long-lived MCP used `tokio::task::spawn_blocking(|| prove…)` plus a soft job timeout.
4. Tokio **does not cancel** `spawn_blocking` when the `timeout` future drops.
5. Job state flipped to `Failed`; the blocking task kept proving (and allocating).
6. Retries / restarts left sibling `tidex6-mcp-local` processes; thrash amplified.

This is the same general class as “fire-and-forget blocking pool work without a
supervisor that can kill the process.” It is **not** a novel crypto break; it is
an integration hazard that becomes a host DoS when agents auto-retry.

## What is *not* the bug

- Not “Groth16 is multi-GB by nature” for this circuit (PK ~2.1 MB file, ~5k
  `a_query` rows, prove peak ~50 MB offline).
- Not a difference in the library API between CLI and MCP after the rewrite —
  both call `collect_waiting` → `prove_withdraw`.
- Not fixed by “just use more RAM” — soft timeout still leaves orphans.

## Related: global `tracing` at `info` (2026-08-03)

A second multi-GB mode was isolated on the **same** OS-thread + rayon=1 path:

| Path | Peak RSS | Result |
|---|---|---|
| `selftest-collect` (no tracing subscriber) | ~55 MB | prove OK ~2 s |
| `selftest-collect` + filter `info,...` | multi-GB | stuck after `prove_withdraw_start` |
| `tools/call collect` + old default `info` | multi-GB / 120s exit(99) | thrash |
| `tools/call collect` + `warn,tidex6_mcp_local=info,rmcp=info` | ~58 MB | full e2e collect OK |

`arkworks`/R1CS emit a high volume of `tracing` events during constraint
generation. A process-wide `info` subscriber materialises them and starves the
prove. Default MCP filter must stay narrow; `RUST_LOG=info` is an explicit
operator choice that re-enables the thrash.

## Mitigations shipped in-tree

| Layer | Control |
|---|---|
| Library | `tidex6_client::confidential::init_prover_runtime()` pins rayon global pool to 1 worker (best-effort; also honour `RAYON_NUM_THREADS`) |
| Library | Documented contract: **never** prove on a tokio worker / via cancellable-looking soft timeout |
| MCP | Dedicated **OS thread** for library work (not `spawn_blocking`) |
| MCP | **Hard** deadline → `process::exit(99)` (only reliable stop for mid-prove) |
| MCP | Reap sibling `tidex6-mcp-local` with the **same PPID** on boot |
| Repro | `tidex6-wusdc-cli` bin `repro_mcp_hang` / `prove_rss` for offline A/B |

## Guidance for integrators

```text
DO:
  - call init_prover_runtime() once at process start
  - run collect/prove on a dedicated OS thread (or a short-lived subprocess)
  - hard-kill the process (or subprocess) if the deadline is exceeded
  - set RAYON_NUM_THREADS=1 in the environment for belt-and-braces

DO NOT:
  - tokio::task::spawn_blocking(|| prove_withdraw(...)) + timeout(...)
  - assume dropping a JoinHandle cancels CPU-bound ark/rayon work
  - leave timed-out MCP/agent processes alive “for cleanup later”
```

## Upstream-facing narrative (optional issue text)

> **Title:** Soft-timeout + `spawn_blocking` + rayon-backed Groth16 prove leaves
> uncancellable host thrash  
> **Crates:** `tokio` (cancel semantics of `spawn_blocking`), `ark-groth16` /
> `ark-ec` (default `parallel` → rayon), integrator hosts  
> **Ask:** Document that CPU-bound rayon work under `spawn_blocking` is not
> cancelled by `timeout`; consider defaulting `parallel` off or reading a
> well-known env for thread caps in long-lived embedding scenarios.

## Reproduction (offline)

```bash
cargo build --release -p tidex6-wusdc-cli --bin repro_mcp_hang --bin prove_rss
./target/release/prove_rss
./target/release/repro_mcp_hang all
```

For the multi-GB *failure mode*, reproduce only under memory pressure with
**stacked** uncancellable workers (historical MCP jobs path); a single prove on
free RAM will not show multi-GB.

## Related code

- `crates/tidex6-client/src/confidential/prover_runtime.rs`
- `crates/tidex6-client/src/confidential/collect.rs`
- `crates/tidex6-mcp-local/src/{main,handler}.rs`
- `crates/tidex6-wusdc-cli/src/bin/repro_mcp_hang.rs`
- `crates/tidex6-wusdc-cli/src/bin/prove_rss.rs`
