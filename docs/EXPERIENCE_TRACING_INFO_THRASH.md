# Experience: global `tracing=info` thrash on arkworks prove (MCP)

**Date:** 2026-08-03  
**Severity:** Critical for long-lived hosts embedding Groth16  
**Кузница:** experience hash `9529279d2319449eb9835371e3984764`  
**Instruction:** `no_global_info_tracing_on_arkworks_host` (`c5586faf6de5481685b94be0e49cd2dd`)

## One-liner

Long-lived MCP with default EnvFilter **`info`** (process-wide) turns a healthy
`prove_withdraw` (~50 MB / few seconds) into multi-GB thrash + hard timeout.
The library was fine; the host logging filter was not.

## Symptoms

| Path | Peak RSS | Outcome |
|------|----------|---------|
| CLI / thrash_live | ~55 MB | prove OK |
| MCP `collect` + filter `info,...` | multi-GB | stuck after `prove_withdraw_start`, exit(99) |
| MCP `collect` + `warn` + crate info | ~55–60 MB | e2e OK |

Looks like “Poseidon/MDS/circuit is broken under MCP” — it is usually **not**.

## Root cause

`arkworks` / R1CS / groth16 emit a high volume of `tracing` events during
constraint generation. A process-wide `info` subscriber materialises them.

Default that hurt us:

```text
info,tidex6_mcp_local=debug
```

## Fix (shipped)

Default filter in `tidex6-mcp-local`:

```text
warn,tidex6_mcp_local=info,rmcp=info
```

`RUST_LOG=info` re-enables thrash on purpose — operator choice.

## Fast triage (do this first next time)

1. Is host EnvFilter / `RUST_LOG` global `info` or `debug`?
2. Cold path without subscriber (CLI or `selftest-collect`) still ~50 MB?
3. Same binary + host filter thrashs? → logging, not circuit.
4. Only then dig rayon / spawn_blocking / Poseidon.

## Related

- `docs/SECURITY_NOTE_SPAWN_BLOCKING_PROVE.md` (spawn_blocking + rayon + tracing section)
- `crates/tidex6-mcp-local/README.md`
- Architecture that stays: rayon pin=1, OS thread for prove, hard timeout
