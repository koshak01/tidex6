# ZeroClaw Earn — status: WAITING

**Last re-check (UTC):** 2026-08-04 (operator session, Aид — full package vs live repo drift)  
**Listing:** https://superteam.fun/earn/listing/zeroclaw  
**Sponsor:** Superteam Brasil · **Total prizes:** 5,000 USDG  
**Winner announcement (sponsor schedule):** **2026-08-21**  
**Submission format:** showcase post in ZeroClaw Discord `#solana-bounty` + Superteam Submit link to that post.

## Verdict

**Submitted package is complete. We are WAITING for judging / winner announcement.**

No further build required for the bounty unless the sponsor asks for a fix.  
**Do not re-submit.** Ops only: keep `mcp.tidex6.com` and skill URL healthy.

**Freeze for judges:** Discord post + Superteam submit + write-up as of **~2026-07-30**  
(`docs/ZEROCLAW_SUBMISSION.md` last content commit `e302e75`). Live product code may have moved on; that is OK for product, but **do not silently break the URLs in `post.txt`**.

---

## Live re-verification (2026-08-04)

| Check | Result |
|-------|--------|
| Listing open / live | **Yes** — Open, Global · **5 000 USDG** · announce **Aug 21, 2026** · **~106 submissions** |
| Write-up | `docs/ZEROCLAW_SUBMISSION.md` (22 643 B) — still on master, GitHub **HTTP 200** |
| Discord body | `docs/zeroclaw/post.txt` (**2001** Unicode chars — Discord hard limit 2000; was documented as 1977; **+1 over** — do not re-edit unless sponsor asks) |
| Config (T1 HTTP + T2 stdio) | `docs/zeroclaw/config.example.toml` |
| Agent skill (ZeroClaw bundle) | `docs/zeroclaw/SKILL.md` (`name: private-payments` v1.0.0) |
| Local MCP config | `docs/zeroclaw/tidex6-local.example.toml` |
| Demo video | https://youtu.be/UBOqarzqlIM → **HTTP 303/OK** |
| On-chain demo tx (devnet) | Linked in `post.txt` (Solscan) |
| Public skill for agents | `https://tidex6.com/skill.md` → **HTTP 200**, 6988 B, frontmatter `name: tidex6` **v0.3.0** (different file from ZeroClaw `SKILL.md` — intentional) |
| MCP OAuth metadata | `GET …/oauth-authorization-server` → **200** (issuer, token, registration, PKCE S256) |
| MCP OAuth DCR | `POST /oauth/register` → **200**, issues `client_id` |
| MCP without token | `POST /mcp` → **401 unauthorized** (expected) |
| Hosted MCP version (about) | **2.18.1** in tree (post-submit product bumps OK) |
| Local MCP binary (T2) | `target/release/tidex6-mcp-local` present |

### curl evidence (smoke, no secrets) — 2026-08-04

```text
GET  https://tidex6.com/skill.md                                          → 200
GET  https://mcp.tidex6.com/.well-known/oauth-authorization-server        → 200
POST https://mcp.tidex6.com/oauth/register  (public client registration)  → 200 + client_id
POST https://mcp.tidex6.com/mcp             (no Authorization)            → 401
GET  https://youtu.be/UBOqarzqlIM                                         → 303
GET  https://github.com/koshak01/tidex6/blob/master/docs/ZEROCLAW_SUBMISSION.md → 200
```

---

## Repo vs submitted package — drift matrix

Judges reproduce from **write-up + config + skill + video**, not from “whatever master compiles today”.

| Layer | At submission (~Jul 30) | Live repo now (Aug 4) | Risk for bounty |
|-------|-------------------------|------------------------|-----------------|
| **Write-up** `ZEROCLAW_SUBMISSION.md` | T1 ten tools; T2 five tools named `whoami`, `payment_request`, `payment_status`, `receive`, `audit` | **Unchanged** (no post-submit rewrite of tool claims) | Low — still the story judges read |
| **Hosted MCP T1** | prepare-only payment_* surface | Still: `about`, `whoami`, `balance`, `payment_quote`, `payment_request`, `payment_status`, `receive`, `audit`, `ceremony`, `ceremony_status` + core `version` | Low — matches write-up; **extra** `ceremony_status` / Apps card is additive |
| **Local MCP T2** | Same *protocol idea*; write-up names `payment_request` / `payment_status` | **Renamed in code** to `send` / `collect` (+ `payments`, `about`, `ceremony`) | **Medium if judge rebuilds tip of master for T2** — names no longer match write-up/config auto_approve list for spend tools |
| **`config.example.toml`** | auto_approve lists `tidex6__payment_*` (T1-safe) | Still payment_* names; **not** updated for local `send`/`collect` | OK for T1 block; T2 operators must not assume auto_approve names = local tool names |
| **`docs/zeroclaw/SKILL.md`** | ZeroClaw skill, EN-only, T1/T2 | Still T1/T2 language with `payment_request` wording | Matches **write-up**, not latest local tool names |
| **`tidex6.com/skill.md`** | Public agent skill T1 | Still T1 `payment_*` table | Aligned with **hosted** path; separate from ZeroClaw bundle |
| **post.txt** | Discord showcase | Still points at same GitHub path + video + tx | Length now **2001** chars (Discord 2000) — cosmetic; post already live, do not re-paste unless needed |
| **Protocol claim** | CT + Groth16 + ML-KEM + auditor | Unchanged product | OK |

### What this means

1. **Do not re-submit** and **do not “fix” the package on master** to match new local tool names unless a judge asks — that rewrites the freeze.  
2. If a judge rebuilds **latest** `tidex6-mcp-local`, they will see `send`/`collect`/`payments`, not `payment_request`/`payment_status`. Video + write-up still describe the **same custody model**.  
3. Hosted path (`mcp.tidex6.com` + OAuth + `payment_*`) remains the cleanest repro for Tier-1 / “no key” claims.  
4. Product work after submit (ceremony Apps, instructions budget, local rename) is **allowed** and does not cancel the submission — just keep public URLs healthy.

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
2. Optional: build-in-public X only if still inside their window (submit deadline was earlier; winners **Aug 21**).  
3. Watch Discord / Earn for sponsor questions.  
4. Keep `mcp.tidex6.com`, `tidex6.com/skill.md`, mainnet/devnet paths healthy (ops only).  
5. Prefer **not** to retarget ZeroClaw package files to new local tool names until after announce (or on explicit judge request).

---

## Open work that is *not* ZeroClaw (separate inbox)

| Task | Why separate |
|------|----------------|
| X Ads / ceremony post | Product growth — not bounty judging |
| PrivatePay / Aleo grant (Atlas) | Separate peer — not ZeroClaw |
| Local MCP rename cleanup in docs | Optional post-announce hygiene |

---

*Recorded by Aид 2026-08-04 after live listing + URL smoke + package vs code drift matrix. Status: **WAITING** until ~2026-08-21.*
