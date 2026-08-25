# Stage A — detailed plan (English only)

**Order:** (1) finish Stage A until the demo works → (2) only then submit the Aleo grant form.  
**Language for all public / grant materials:** **English**. No Russian in grant text, repo public README for this track, or Asana form.

---

## 1. Goal of Stage A (one sentence)

Prove a **minimal private payment sketch on Aleo (Leo language)** that can:

1. Hold a private amount (not readable on a public explorer as plaintext).  
2. Transfer it (full or split).  
3. Issue an **auditor slip** so one chosen party sees the amount **without** gaining the right to spend the main token.

This is the same *product idea* as tidex6 on Solana (private transfer + selective disclosure), not a full port.

---

## 2. What we already have (code)

Path: `aleo/tidex6_private_transfer/`

| Piece | Role |
|-------|------|
| `Token` record | Spendable private value: `owner` + `amount` |
| `mint_private` | Create a token (demo mint; production would gate this) |
| `transfer_full` | Move entire token to a new owner |
| `transfer_private` | Split: receiver amount + change to sender |
| `AuditSlip` record | Non-spendable (as Token) slip for an auditor |
| `issue_audit_slip` | Owner keeps Token; auditor receives AuditSlip with same amount |
| `leo build` | Compiles cleanly (Leo 4.4) |

---

## 3. Micro-application (what we build next)

Not a full website. A **tiny, reproducible demo** so a stranger (and the grant reviewer) can run:

```text
build → mint → transfer → issue auditor slip
```

### Layout

```text
aleo/
  tidex6_private_transfer/   # Leo program (already)
  demo/
    README.md                # English: how to run
    run_demo.sh              # one-shot script
docs/aleo/
  STAGE_A_DETAILED.md        # this file
  GRANT_ONE_PAGER_DRAFT.md   # English grant text (after demo works)
```

### Script behaviour (`run_demo.sh`)

1. Check `leo` is on `PATH`.  
2. `leo build` in the program folder.  
3. `leo run mint_private <ADDR> 10u64` and print the private record.  
4. Document the next manual step for `issue_audit_slip` (record input requires the minted record blob from step 3 — Leo local VM workflow).  
5. Exit non-zero if build fails.

Later (still Stage A if time): wrap record piping so audit slip is one command.

### Success criteria for “it works”

- [x] Program builds.  
- [x] Mint runs and returns a private `Token`.  
- [x] Auditor path exists in source (`issue_audit_slip`).  
- [ ] Demo script runs on a clean shell without hand-holding.  
- [ ] English README maps tidex6 concepts → Leo names (5+ rows).  
- [ ] Security checklist linked (wrong vs right).  

**Only after those boxes are green → grant form.**

---

## 4. Separate Synapse peer (recommended)

**Yes — a dedicated peer is cleaner.**

| | tidex6 peer (Аид) | New peer (Aleo track) |
|--|-------------------|------------------------|
| Focus | Solana privacy product, ceremony, MCP | Aleo/Leo grant + micro-demo only |
| Inbox | Ads, MCP, Solana ops | Grant milestones, Leo code only |
| Risk | Mixed priorities | Clear ownership |

### What “peer” means here

In the collective, each project has a **Synapse identity** (code + secret + bridge).  
Tasks go to that peer. You are not “another Grok personality” by magic — **operator + synapse admin** create the peer row and issue `synapse.toml` secrets.

### Proposed identity (English-facing)

| Field | Suggestion |
|-------|------------|
| `snp_code` | `aleo` or `privatepay-aleo` |
| Display name | e.g. **Atlas** / **Hermes-Aleo** — pick one Greek name if you keep the pantheon |
| Description | `Aleo/Leo private payments contour (tidex6 architecture port) — OSS grant track` |
| Repo path | Prefer **sibling** `~/work/rust/aleo-privatepay/` later; for now code can stay under `tidex6/aleo/` until split |

### How to create it (operator checklist)

1. **Petr / Socrates (synapse):** add peer in synapse admin (code, name, description EN).  
2. Issue **secret** + **handshake_key** → write `synapse.toml` in the project folder.  
3. Point Grok Build (or Claude) at that folder + MCP `synapse-bridge` with that peer’s secret.  
4. **Аид (tidex6)** keeps Solana work; new peer only receives Aleo tasks.

**I cannot invent a live peer secret myself** — only request + use after you/admin create it.

Until the peer exists, we continue under tidex6 repo path, but **all Aleo docs stay English** so the later split is painless.

---

## 5. Grant submit (only after Stage A works)

1. Open https://aleo.org/grants → apply form (Asana).  
2. Paste from `GRANT_ONE_PAGER_DRAFT.md` (**English only**).  
3. Ask **$35k–$50k**, milestones M1–M3, OSS required.  
4. Link public GitHub path to Leo program + demo.  
5. Attach security checklist.

**Do not submit while demo is half-broken.**

---

## 6. What we explicitly do *not* put in Stage A

- Full tidex6 port (CT Token-2022, ML-KEM memo, relayer product).  
- Russian grant text.  
- Mixing Solana ceremony ads tasks into the Aleo peer inbox.  
- Claiming mainnet production on Aleo before it is true.

---

## 7. Immediate next actions (this session)

1. Add `aleo/demo/run_demo.sh` + English `aleo/demo/README.md`.  
2. Tighten English `aleo/README.md` + grant one-pager (no Russian names in “Team” line for public form — use roles).  
3. Write peer request blurb for Petr (English).  
4. Stop before Asana until you say: **demo OK, apply.**
