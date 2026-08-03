# tidex6-mcp-local (rewritten)

Local stdio MCP = **same libraries as the stealth CLI** (`send` / `collect` / `audit`).

## Blocker fixes

| | CLI | Broken MCP | Now |
|--|-----|------------|-----|
| prove | OS main | `spawn_blocking` + rayon storm | dedicated OS thread |
| rayon | default | multi‑GB thrash under soft timeout | **1 thread** via `init_prover_runtime()` |
| hang forever | process exits | orphan 100% CPU after UI restart | **120s hard timeout → `exit(99)`** |
| multi instance | n/a | restart leaves old process | **reap same PPID siblings** at start |
| tracing | none | default `RUST_LOG=info` on whole process | **`warn` + our crates only** (see below) |

**Rayon** comes from `ark-groth16` (`default = ["parallel"]`), not our crate.

### Tracing thrash (2026-08-03)

`arkworks` / R1CS crates use `tracing`. A default filter of global `info` turns
`prove_withdraw` into a multi‑GB event storm (stuck past `prove_withdraw_start`,
RSS multi‑GB, 120s `HARD_TIMEOUT`). The same note without that filter finishes
in ~2 s at ~55 MB.

Default filter is now:

```text
warn,tidex6_mcp_local=info,rmcp=info
```

Override with `RUST_LOG` only if you accept the cost (`RUST_LOG=info` will thrash
again on collect/prove).

**Selftest (no stdio):** `tidex6-mcp-local selftest-collect mainnet`  
**Root cause write-up:** `docs/SECURITY_NOTE_SPAWN_BLOCKING_PROVE.md`  
**Offline A/B:** `cargo run --release -p tidex6-wusdc-cli --bin repro_mcp_hang -- all`

Steady-state prove is ~50–60 MB / few seconds.

**Session (Grok):** no session UUID in env. Isolation = **PPID** (parent Grok/stdio host). On start we `kill -9` other `tidex6-mcp-local` with the **same parent** only — not other apps’ MCP.

**No** subprocess CLI. Logs: stderr `mcp-local LOG …` / `BOOT …` / `heartbeat …`.

## Tools

| tool | library |
|------|---------|
| `whoami` | config key |
| `send` | `send_payment` |
| `collect` | `collect_waiting` (network only) |
| `audit` | `scan(Auditor)` |

Config: `~/.tidex6-local/config.toml`  
Proving key: `~/.tidex6-local/withdraw_pk_depth20.bin`

```bash
cargo build --release -p tidex6-mcp-local
```
