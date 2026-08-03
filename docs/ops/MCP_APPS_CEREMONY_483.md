# MCP Apps ceremony card (task 483) — implementation note

**Status:** implemented in tree (2026-08-04) · deploy web+MCP to go live  
**rmcp:** 2.2 — supports `_meta` on tools, resources, `structured_content`

## Decision (step 0)

`rmcp` **keeps** tool `_meta` (macro `meta = …` → `Tool::with_meta`). No fork.

## Shipped

| Piece | Where |
|-------|--------|
| `ui://tidex6/ceremony` resource + mime `text/html;profile=mcp-app` | `tidex6-mcp` list/read resources |
| Tool `_meta["ui/resourceUri"]` | `ceremony` tool |
| `structuredContent` `{contributions, distinct_wallets, url, nonce}` | `ceremony` result |
| Text content still has full URL | degradation path |
| Session store + `ceremony_status` | `ceremony_ui.rs` |
| Web `?s=` + contribute `session` → complete | `ceremony.html.tera` + `ws_handlers/ceremony.rs` |

## Hard rules

- Nonce **ceremony only** — never payments.  
- Card does **not** iframe ceremony site.  
- No payment columns in session store.

## Not done / host-dependent

- Full `callServerTool` / `updateModelContext` depends on host (Claude etc.). Card degrades to open link.  
- Live verify in Claude after deploy.

## Deploy

1. Ship `tidex6-mcp` + `tidex6-web` together (same process = shared session memory).  
2. Restart so MCP and ceremony WS share the in-memory session map.
