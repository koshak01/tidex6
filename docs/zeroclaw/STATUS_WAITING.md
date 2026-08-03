# ZeroClaw Earn — status: WAITING

**Date checked:** 2026-08-04 (operator session)  
**Listing:** https://superteam.fun/earn/listing/zeroclaw  
**Sponsor:** Superteam Brasil · **Total prizes:** 5,000 USDG  
**Winner announcement (sponsor schedule):** 2026-08-21  
**Submission format:** showcase post in ZeroClaw Discord `#solana-bounty` + Superteam Submit link to that post.

## Verdict

**Submitted package is complete. We are waiting for judging / winner announcement.**

No further build required for the bounty unless the sponsor asks for a fix.

---

## Re-verification (2026-08-04)

| Check | Result |
|-------|--------|
| Listing open / live | Yes — Open, Global, 103+ submissions |
| `docs/ZEROCLAW_SUBMISSION.md` | Present (write-up) |
| `docs/zeroclaw/post.txt` | Present (Discord showcase body, ≤2000 chars) |
| `docs/zeroclaw/config.example.toml` | Present (T1 HTTP + T2 stdio) |
| `docs/zeroclaw/SKILL.md` | Present (agent skill language — not Rust) |
| `docs/zeroclaw/tidex6-local.example.toml` | Present |
| Demo video | https://youtu.be/UBOqarzqlIM (requirement: real agent, terminal+phone) |
| On-chain demo tx (devnet) | Linked in `post.txt` / submission |
| Public skill for agents | https://tidex6.com/skill.md (200) |
| MCP OAuth metadata | `https://mcp.tidex6.com/.well-known/oauth-authorization-server` → OK |
| MCP OAuth dynamic client registration | POST `/oauth/register` → issues `client_id` (smoke OK) |
| MCP without token | POST `/mcp` → **401** (expected; not open anonymous RPC) |
| OAuth access token TTL (source) | `tidex6-web` ws: `token_ttl_secs: 30 * 24 * 3600` (**30 days**, ZeroClaw static Bearer blocker addressed) |
| Local MCP (T2 path) | `tidex6-local` tools live: whoami, payments, send, collect, audit |
| Hosted MCP (T1 path) | `https://mcp.tidex6.com/mcp` requires Bearer after wallet OAuth |

---

## What “another language” meant (for the archive)

ZeroClaw integration is **not** a Rust rewrite. Earn deliverable is:

- **Skill / SOP text** (`SKILL.md`)
- **Agent config** (TOML)
- **MCP server** already live (Rust)

Same Solana/tidex6 stack; packaging language = agent skill + config.

---

## Operator posture until 2026-08-21

1. **Do not re-submit** unless Superteam/ZeroClaw asks.
2. Optional: build-in-public X posts still count if before their window (see listing rules).
3. Watch Discord / Earn for questions from sponsor.
4. Keep `mcp.tidex6.com` and mainnet/devnet paths healthy (ops only).

---

## Open work that is *not* ZeroClaw (separate inbox)

| Task | Why separate |
|------|----------------|
| MCP Apps ceremony card (`c0878c0e…`) | Product conversion in Claude UI — not bounty judging |
| Fee/security pass (`faaa496d…`) | Product ops |

---

*Recorded by Aид after live re-check of listing, public URLs, OAuth smoke, and local MCP.*
