# Fee + security pass (task 599)

**Date:** 2026-08-04  
**Operator ask:** (1) fee lands only where it should, no extra charges; fee covers costs. (2) no unauthorized reads/transfers of others’ money or txs.

---

## 1. Fee model (where money goes)

| Layer | Policy | Destination |
|-------|--------|-------------|
| **ct-lab / pool service** | `fee_bps = 100` (1%), `fee_floor_micro = 100_000` (0.1 token) | Operator: underlying ATA **or** private stealth note if `fee_collector_address` set (`config.rs`) |
| **MCP quote** | Same numbers hardcoded in `FeePolicy::default()` (`tidex6-mcp/src/quote.rs`) | Quote only — does not move funds |
| **Browser / local send** | Sender pays `amount + fee`; recipient gets `amount` | `pay_operator` → operator ATA with memo = commitment (`transfer.rs`) |
| **Relayer fee (Groth16 withdraw)** | Separate ADR-011 path; often **0** on confidential collect | Relayer account if non-zero — **not** a second “platform tax” on the same CT payment |

### Public story (matches code)

- Sender pays fee **on top**.  
- Recipient receives **full amount**.  
- Fee is the **only** protocol/service charge on the payment path (covers ZK verify + landing txs).  
- Floor explains small payments where 1% would be below operational cost.

### Double-charge check

| Path | Extra take? |
|------|-------------|
| MCP `payment_quote` / `payment_request` | Numbers only + link; **no** move |
| Hosted sign page → pool quote | Single operator total (`amount+fee`) verified on-chain |
| Local MCP T2 | Same quote arithmetic + `pay_operator` once |
| Groth16 withdraw relayer_fee | Independent; default 0 on collect path reviewed |

**Verdict fee:** single economic fee to **operator** (open ATA or stealth collector). No hidden second platform fee found on the stablecoin payment path. MCP and ct-lab defaults **match** (1% / 0.1 floor).

### Follow-ups (non-blocking)

1. Prefer loading MCP `FeePolicy` from the same config as ct-lab (env or shared constants) so they cannot drift.  
2. When `fee_collector_address` is set in prod, document “fee is a private note” on `/business`.  
3. Relayer mainnet fee policy: keep explicit and user-visible if ever non-zero.

---

## 2. Security surface (MCP + payments)

### Auth

| Control | Status |
|---------|--------|
| Hosted MCP requires OAuth Bearer | **Yes** — unauth `POST /mcp` → 401 |
| Tools see caller wallet via token extensions | **Yes** — `CallerWallet` |
| Payment sender taken from token, not agent args | **Yes** — cannot name someone else’s wallet as payer |
| Signing page binds request to `sender_wallet` | **Yes** (commented in create path) |

### What tools can see

| Tool | Risk | Assessment |
|------|------|------------|
| `balance` | Any public address if supplied | **OK** — public chain data only; private pool balances **not** exposed |
| `payment_status` | Anyone with `request_id` | **Acceptable** — id is unguessable short store id; reveals signed/pending + optional public sig only; **not** amount ciphertext |
| `receive` / `audit` | Links only | **OK** — decryption only in user browser with their key |
| `payment_request` | Prepare only | **OK** — no key on server |
| `ceremony` | Public transcript | **OK** |

### What tools cannot do

- Move funds without user signature (hosted).  
- Read private notes / amounts for third parties.  
- Create payment for a different sender than the OAuth wallet.

### Hard rules preserved

- **No** chat-session ↔ payment correlation (nonce pattern only for ceremony — MCP Apps).  
- Memo remains sensitive; separate bug (memo enum deserialize) still open — not part of fee sink.

---

## 3. Checklist (operator)

- [x] Fee = 1% with 0.1 floor, sender-paid  
- [x] Recipient full amount  
- [x] Operator is fee sink (ATA or stealth collector)  
- [x] MCP does not take a second fee  
- [x] Unauth MCP denied  
- [x] Sender identity from token  
- [x] Private balances not via `balance`  
- [ ] Optional: unify fee config source MCP ↔ ct-lab  
- [ ] Optional: payment_request memo deserialize fix (separate task)

---

## 4. Verdict

**Fee path:** correct and singular.  
**Security:** no critical “see others’ private money / spend for them” hole found on the reviewed paths.  
**Residual:** public data is public; request_id secrecy is capability-based; upgradeable pool authority remains an honesty item (already in ZeroClaw write-up).

*Recorded for task `faaa496d…`.*
