# Aleo / Leo — security checklist (wrong vs right) · for Аид

**От:** Ника · **2026-08-04**  
**Scope:** grant MVP (private transfer + README). Not full tidex6 parity.

Use as **wrong vs right** notes in README / grant appendix.

---

## 1. Records & ownership

| Wrong | Right |
|-------|--------|
| Treat record as «account anyone can spend if they know the fields» | Only owner with correct private key / view path can transition spend |
| Reuse spent record (double-spend) | Nullifier / spent set; reject second spend |
| Put private balance in public transition inputs | Keep amount in private record; public only what’s required for consensus |

## 2. Nullifier / double-spend

| Wrong | Right |
|-------|--------|
| Nullifier derived from public-only data (guessable) | Nullifier binds secret note + domain separator |
| No on-chain nullifier set | Commit nullifiers immutably; check uniqueness |
| Same nullifier domain for different programs | Domain-separate by program / circuit id |

## 3. Frontend / host leakage

| Wrong | Right |
|-------|--------|
| Log private keys / notes in browser console | Never log secrets; clear memory after prove |
| Ship note in URL query / public IPFS without encrypt | Encrypt memo; or hand off out-of-band |
| «Private» UX but amount shown in public event | Audit every public field of transition |

## 4. Proof / circuit trust

| Wrong | Right |
|-------|--------|
| Assume testnet trusted setup = mainnet | Document setup status; ceremony if required |
| Unbounded loops / unconstrained branches | Fixed bounds; document incompleteness |
| Skip verification of program ID / verifier | Pin program + checksum in README |

## 5. Relayer / fee payer (if any)

| Wrong | Right |
|-------|--------|
| Relayer can steal note | Relayer only submits; cannot open record |
| User signature binds to wrong recipient | Recipient binding in circuit |

## 6. Grant / OSS honesty

| Wrong | Right |
|-------|--------|
| Claim full tidex6 port in week 1 | MVP = private transfer sketch + mapping doc |
| Closed source «for now» | Aleo grants require OSS elements |
| Hide Solana-specific dead ends | Explicit «does not port» list (CT Token-2022, etc.) |

---

## Quick smoke for MVP PR

1. Deposit private note (or mint private record)  
2. Withdraw/transfer once → success  
3. Second spend same note → **fail**  
4. Wrong owner → **fail**  
5. README: map tidex6 concepts → Leo names  

---

## Links

- Handoff: `HANDOFF_ALEO_LEO_PRIVACY_CONTOUR_AID.md` (same folder)  
- Leo: https://leo-lang.org · https://developer.aleo.org  
- Grants: https://aleo.org/grants  
