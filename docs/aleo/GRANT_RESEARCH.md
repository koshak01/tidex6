# Aleo / Leo — grant research (deep dig)

**Date:** 2026-08-04  
**Owner:** Аид  
**Status:** research complete → spike next  
**Apply:** https://form.asana.com/?k=sCm0WT9M-V_fHl8AA48czQ&d=1199198487809755  
**Program:** https://aleo.org/grants  

---

## 1. Program facts (live)

| Field | Value |
|-------|--------|
| Ceiling | **up to $100K** |
| License | **Open-source required** |
| Who | teams + solo |
| Scope tags | **Payment**, Identity, Gaming, DeFi |
| Funding style | **milestone-based** |
| Review | ~1 week initial feedback (program copy) |
| Ecosystem | 50+ projects funded, $1M+ grants deployed (marketing numbers on page) |
| Pitch fit | Payments + compliance/selective disclosure is a **first-class use case** on the page (Request Finance highlighted) |

### Why this fits tidex6 DNA

Aleo’s public grant copy is literally:

> *Payments that safeguard user data while meeting regulations — global payroll and cross-border payments.*

That is the same story as tidex6 (Lena / payroll / auditor), not a stretch pitch.

### What we do **not** claim

| Claim | Status |
|-------|--------|
| Full tidex6 port in week 1 | **No** |
| Solana Token-2022 CT on Aleo | **Does not port** — native private records instead |
| Dual-submit Colosseum product | **No** — separate L1 grant |
| Closed source until funding | **No** — OSS required |

---

## 2. Mapping: tidex6 → Leo / Aleo

| tidex6 (Solana) | Meaning | Aleo / Leo direction |
|-----------------|---------|----------------------|
| Groth16 shielded pool | hide **link** | private records + transitions; spent nullifiers |
| Token-2022 CT / wUSDC | hide **amount** | private amounts in records (private-by-default) |
| Viewing key / auditor slot | selective disclosure | design view/share pattern carefully (MVP: optional second viewer field or off-chain memo) |
| Relayer fee-in-circuit | fee payer ≠ user | public submitter vs private owner (phase 2) |
| ML-KEM stealth memo | find notes without handoff | encrypt / scan pattern — **not MVP** |
| Browser WASM prover | client prove | snarkVM / web later |
| tip-jar CPI | 30-line integrate | host program + short Leo example |

**MVP grant slice (honest):**

1. Leo program: private transfer (mint/deposit → spend/transfer → double-spend fails).  
2. Tests + local/testnet execute path.  
3. README: concept map tidex6 ↔ Leo + wrong-vs-right security checklist.  
4. Grant one-pager + milestones + budget.  

**Out of MVP:** mainnet funds, full relayer product, MCP surface, parity with Solana CT pools.

---

## 3. Competitive / landscape notes (for honesty, not marketing)

- Aleo already funds **payment** and **compliance** narratives (Request Finance, bridges, staking).  
- Differentiator for us: **shipped dual-layer privacy on Solana** + explicit selective-disclosure product language + agent/MCP packaging experience.  
- Risk: “another private transfer demo” — mitigate with **compliance viewing path** + mapping doc from a live mainnet protocol (tidex6), not a greenfield toy.

Public docs: no competitor name-drops in grant text beyond standard ecosystem references if required by form.

---

## 4. Proposed ask & milestones

**Ask (draft):** **$35k–$50k** (solo/small team, OSS private-payments contour)  
Not max $100k on day one — credibility over greed. Can expand after M1.

| # | Milestone | Deliverable | Est. | Payout share |
|---|-----------|-------------|------|--------------|
| M0 | Spike | Leo hello + record sketch builds; repo skeleton `tidex6-aleo/` or monorepo path | 2–3 days | 0 (pre-grant) |
| M1 | Private transfer MVP | Leo program + tests (double-spend fail) + README map | 2–3 weeks | 40% |
| M2 | Selective disclosure sketch | Auditor/view path or documented equivalent + wrong-vs-right appendix | +1–2 weeks | 30% |
| M3 | Integration example + polish | Host/client example, testnet runbook, grant report | +1–2 weeks | 30% |

Total calendar after grant start: **~6–8 weeks** part-time alongside tidex6 ops.

---

## 5. Pitch angle (one paragraph)

> We already ship dual-layer private stablecoin payments on Solana (tidex6): hidden link (Groth16 pool), hidden amount (Token-2022 CT), optional auditor slot. Aleo’s native private records let us express the same product DNA without fighting a public L1. This grant funds an open-source Leo private-transfer MVP with a compliance-oriented selective-disclosure path and a honest mapping from a production Solana privacy stack — so builders get a portable architecture, not a one-off demo.

Slogan remains product-side on Solana: *I grant access, not permission.* On Aleo application materials: lead with privacy + compliance, not the Solana slogan alone.

---

## 6. Links

| | |
|--|--|
| Grants | https://aleo.org/grants |
| Apply | https://form.asana.com/?k=sCm0WT9M-V_fHl8AA48czQ&d=1199198487809755 |
| Leo | https://www.leo-lang.org · https://docs.leo-lang.org |
| Docs | https://docs.aleo.org (redirect from developer.aleo.org) |
| Playground | https://play.leo-lang.org |
| GitHub Leo | https://github.com/ProvableHQ/leo |
| Handoff | `HANDOFF_ALEO_LEO_PRIVACY_CONTOUR_AID.md` |
| Security | `ALEO_LEO_SECURITY_CHECKLIST_AID.md` |
| Spike | `SPIKE_PLAN.md` |
| One-pager draft | `GRANT_ONE_PAGER_DRAFT.md` |

---

## 7. Decision log

| When | Decision |
|------|----------|
| 2026-08-04 | Owner = Аид; Nike = research only |
| 2026-08-04 | Priority: tidex6 ceremony/ops first; Leo spike parallel when bandwidth |
| 2026-08-04 | Grant submit **after** spike green (not before) |
