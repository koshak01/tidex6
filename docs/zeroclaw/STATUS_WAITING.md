# ZeroClaw Earn — status: WAITING

**Last re-check (UTC):** 2026-08-03T23:13Z (operator session, Aид)  
**Listing:** https://superteam.fun/earn/listing/zeroclaw  
**Sponsor:** Superteam Brasil · **Total prizes:** 5,000 USDG  
**Winner announcement (sponsor schedule):** **2026-08-21**  
**Submission format:** showcase post in ZeroClaw Discord `#solana-bounty` + Superteam Submit link to that post.

## Verdict

**Submitted package is complete. We are WAITING for judging / winner announcement.**

No further build required for the bounty unless the sponsor asks for a fix.  
**Do not re-submit.** Ops only: keep `mcp.tidex6.com` and skill URL healthy.

---

## Live re-verification (2026-08-03 / session 2026-08-04 local)

| Check | Result |
|-------|--------|
| Listing open / live | **Yes** — Open, Global · prizes 5 000 USDG · announce **Aug 21, 2026** · ~101–103 submissions |
| Write-up | `docs/ZEROCLAW_SUBMISSION.md` (22 643 B) |
| Discord body | `docs/zeroclaw/post.txt` (≤2000 chars, links write-up + video + tx) |
| Config (T1 HTTP + T2 stdio) | `docs/zeroclaw/config.example.toml` |
| Agent skill | `docs/zeroclaw/SKILL.md` |
| Local MCP config | `docs/zeroclaw/tidex6-local.example.toml` |
| Demo video | https://youtu.be/UBOqarzqlIM → **HTTP 200** |
| On-chain demo tx (devnet) | Linked in `post.txt` (Solscan) |
| Public skill for agents | `https://tidex6.com/skill.md` → **HTTP 200**, 6988 B, frontmatter `name: tidex6` v0.3.0 |
| MCP OAuth metadata | `GET https://mcp.tidex6.com/.well-known/oauth-authorization-server` → **200** (issuer, token, registration, PKCE S256) |
| MCP OAuth DCR | `POST /oauth/register` → **200**, issues `client_id` |
| MCP without token | `POST /mcp` → **401 unauthorized** (expected; not open anonymous RPC) |
| OAuth access token TTL (source) | `tidex6-web/src/bin/ws.rs`: `token_ttl_secs: 30 * 24 * 3600` (**30 days** — ZeroClaw static Bearer OK) |
| Local MCP binary (T2) | `target/release/tidex6-mcp-local` present |
| Hosted MCP (T1) | `https://mcp.tidex6.com/mcp` requires Bearer after wallet OAuth |

### curl evidence (smoke, no secrets)

```text
GET  https://tidex6.com/skill.md                                          → 200
GET  https://mcp.tidex6.com/.well-known/oauth-authorization-server        → 200
POST https://mcp.tidex6.com/oauth/register  (public client registration)  → 200 + client_id
POST https://mcp.tidex6.com/mcp             (no Authorization)            → 401
GET  https://youtu.be/UBOqarzqlIM                                         → 200
```

Git: package recorded in tree; status commit lineage includes `7f72b75` (WAITING after first re-check).

---

## What shipped (reminder)

| Layer | Deliverable |
|-------|-------------|
| Protocol | tidex6 mainnet: CT amounts + Groth16 link + ML-KEM memo + auditor slot |
| T1 hosted MCP | no key; prepare-only tools; OAuth + 30d token for static ZeroClaw headers |
| T2 local MCP | key on operator machine; caps in code; stdio — **what the video shows** |
| ZeroClaw package | stock binary + TOML + `SKILL.md` — **no WASM plugin, no fork** |
| Showcase | video + Discord post + Superteam submit |

---

## Operator posture until 2026-08-21

1. **Do not re-submit** unless Superteam / ZeroClaw asks.
2. Optional: build-in-public X posts only if still inside their window (see listing rules).
3. Watch Discord / Earn for sponsor questions.
4. Keep `mcp.tidex6.com`, `tidex6.com/skill.md`, mainnet/devnet paths healthy (ops only).

---

## Open work that is *not* ZeroClaw (separate inbox)

| Task | Why separate |
|------|----------------|
| MCP Apps ceremony card (`c0878c0e…`) | Product conversion in Claude UI — not bounty judging |
| Fee/security pass (`faaa496d…`) | Product ops |
| Aleo/Leo privacy contour (`bbb21cfd…` **done**; materials in `docs/aleo/`) | Next earn language / grant — not ZeroClaw |

---

*Recorded by Aид after live re-check of listing, public URLs, OAuth smoke, MCP 401, skill.md, video, and local package files. Status: **WAITING**.*
