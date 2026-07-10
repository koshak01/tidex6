# ADR-016 — Fee monetization: sender-pays, fee-on-top, private-note collection

**Status:** Accepted
**Date:** 2026-07-10
**Related:** ADR-011 (relayer fee in circuit), ADR-014 (ML-KEM memo + auditor), ADR-007 (Shielded Memo)

## Context

The demonstration runs an **operator-pays** model: the service operator
(`ED1HHG…` on mainnet) `wrap`s its own USDC/USDT for every deposit, so the
operator's balance is spent on each payment and the tokens end up with the
recipient. In that model a service fee is only a *partial refund* — the operator
still nets `−(amount − fee)` per payment. "The amount I put in comes back, plus a
fee on top" is impossible while the operator funds the payments.

For a real product the payer must be the **sender**, not the operator. Then the
operator only takes a fee and never spends its own principal — that is genuine
monetization.

Two further requirements from the operator:
1. The fee should be a **setting**, tunable without a rebuild.
2. The fee must be **collected privately** — nobody on-chain should see the fee
   amount or where it goes — while remaining **transparent to the operator and
   its auditor** (income accounting).

## Decision

1. **Sender-pays (production model).** The browser user pays with **their own**
   tokens (Phantom signs the transfer into the pool); the operator only relays
   (pays SOL gas) and takes the fee. Operator net per payment: **+fee**.

2. **Fee on top.** The recipient receives the **full requested amount**; the
   sender pays `amount + fee`. ("I want 1000 to arrive" → sender pays `1000 +
   fee`.) This mirrors a bank transfer and keeps the recipient's number clean.

3. **Fee is configuration.** `config.toml`: `fee_bps` (basis points, default
   `100` = 1%) and `fee_floor_micro` (minimum, default `100000` = 0.1 token, so
   small payments still cover gas). `Config::fee_micro(amount)` =
   `max(floor, amount · bps / 10_000)`. Tunable without a rebuild.

4. **`fee_payer` is selectable — sender or receiver.** Sender-pays splits the
   sender's payment into fee + delivery; receiver-pays deducts the fee at
   withdrawal. Both land the fee in the same place (below). *(Sender-pays first;
   receiver-pays is a follow-up.)*

5. **Private-note collection (model B).** Each fee becomes a **separate private
   note in the same shielded pool**, addressed to the operator's key —
   on-chain indistinguishable from an ordinary deposit. The operator **sweeps**
   the fees with its own key (scans the pool like any recipient). An **auditor
   key** can be attached to the fee notes so the operator's accountant / tax
   authority sees the full fee ledger (date, amount) — clean income accounting,
   invisible to everyone else.

6. **UI transparency, on-chain privacy.** The fee is shown **openly to the
   payer** in the interface ("you pay 1010, of which 10 is the fee"), while the
   fee's on-chain movement stays private (point 5). Transparent to the user,
   hidden from strangers — the project's core stance applied to the operator's
   own revenue.

7. **Mainnet cap raised 1 → 5.** `mainnet_gate` is generalized to `cap_N`
   (`cap_1` / `cap_5` / `cap_10`, default `cap_5`) so per-operation test
   payments are large enough for a meaningful, uniform fee.

## Consequences

- **Deposit is reworked**: the browser user pays their own tokens instead of the
  operator `wrap`-ing its own. This is the largest piece of work and the
  foundation of the production model.
- **Fee-split logic** added in `tidex6-ct-lab` at the payout point (`pay_one`
  pays the recipient, the fee is diverted into a fee note).
- **Fee as a private note** (model B) requires minting the fee as a pool note
  addressed to the operator (+ optional auditor slot), not a plaintext transfer.
- The operator **no longer subsidizes** payments; principal is never spent, net
  is `+fee`.
- A **"Who pays" card** goes on the site **only once the fee is live** (until
  then it stays in the roadmap, so we never advertise what isn't shipped).
- `fee_bps` / `fee_floor_micro` / `mainnet_policy` become operator-tunable
  config; changing the fee is a one-line edit, not a deploy.

## Implementation stages

1. Production deposit — browser user pays their own USDC (foundation).
2. Fee-split on top (`Config::fee_micro`), recipient gets full amount.
3. `fee_payer` sender / receiver selection.
4. Fee as a private note to the operator (+ auditor slot).
5. "Who pays" card + monetization copy on the site.

`cap_N` generalization and the `fee_bps` / `fee_floor_micro` config are already
in place (stage 0).
