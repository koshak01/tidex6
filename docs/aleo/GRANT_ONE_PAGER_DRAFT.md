# Grant one-pager draft — Aleo Developer Grants

**Working title:** Private compliant payments on Aleo (tidex6 contour in Leo)  
**Team:** Аид (ZK/product) · Пётр (direction) · research support as needed  
**License:** Open source (required)  
**Ask:** $35,000 – $50,000 (milestone-based)  
**Category:** Payment (+ selective disclosure / compliance)  

---

## Problem

Public chains turn payroll and contractor payments into permanent ledgers: competitors and counterparties see rates forever. Hiding *everything* fails tax and accounting. Businesses need **both**: public privacy and one-party selective disclosure.

## Solution

Port the **architecture** already live on Solana as tidex6 into Aleo’s native private model using **Leo**:

1. Private transfer of value (records / transitions).  
2. Double-spend protection (nullifiers / spent records).  
3. Selective disclosure path for an auditor/accountant (MVP sketch).  
4. Honest documentation: what ports, what is Solana-specific (Token-2022 CT, etc.).

Not a closed product fork — **OSS learning + reusable contour**.

## Why Aleo

Private-by-default records + programmable ZK + grant scope that names **payments and compliance**. Avoid bolting privacy onto a public L1; express the product where privacy is native.

## Team credibility

- tidex6 live on Solana mainnet (shielded pool + confidential amounts + auditor slot + agent MCP).  
- OtterSec-verified programs; immutable Groth16 verifier.  
- Agent packaging (ZeroClaw Superteam Earn package shipped).  

## Milestones

| Milestone | Deliverable | Timeline |
|-----------|-------------|----------|
| M1 | Leo private transfer + tests (double-spend fail) + concept map README | weeks 1–3 |
| M2 | Selective-disclosure / view path sketch + security wrong-vs-right | weeks 4–5 |
| M3 | Integration example, testnet runbook, final report | weeks 6–8 |

## Budget (illustrative $40k)

| Use | Share |
|-----|-------|
| Engineering (Leo + tests + docs) | 70% |
| Review / security write-up | 15% |
| Integration example + polish | 15% |

## Risks & honesty

- Setup / proving stack maturity on Aleo may constrain UX; document limits.  
- MVP is **not** full tidex6 parity.  
- Frontend leakage and public transition fields remain the usual ZK footguns — checklist attached.

## Links

- Solana product: https://tidex6.com  
- Repo: https://github.com/koshak01/tidex6  
- This brief: `docs/aleo/` in the same monorepo after spike lands code under `aleo/` or sibling.

---

*Draft only — submit after spike green and operator OK.*
