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

0. `cap_N` generalization + `fee_bps` / `fee_floor_micro` config. **Done.**
1. Production deposit — browser user pays their own USDC. **Done** (live on
   mainnet + devnet, both stablecoins, verified 2026-07-15).
2. Fee-split on top (`Config::fee_micro`), recipient gets full amount. **Done.**
3. `fee_payer` sender / receiver selection. *Open* (sender-pays only for now).
4. Fee as a private note to the operator. **Done 2026-07-15** (recipient slot;
   auditor slot on the fee note is a follow-up).
5. "Who pays" / monetization copy on the site. **Done** (per-transaction fee
   described on the home page).

## Stage 4 — how the private fee note works

When `fee_collector_address` is set in `config.toml` (a hex `ReaderAddress` =
`mlkem_pk ‖ x25519_pk`, produced by `tidex6 keygen print-mlkem-pk`), a paid
deposit does **two** pool deposits instead of one:

1. `ct::wrap(amount + fee)` — the operator wraps the **whole** paid sum (not just
   `amount`), so the fee is inside the confidential pool, not left in the
   operator's underlying ATA.
2. `flow::deposit_browser(user_commitment, user_envelope)` — the recipient's note
   for `amount` (unchanged; the browser built it).
3. `flow::deposit_fee_note(collector, fee)` — a **fresh stealth note** for `fee`,
   `secret`/`nullifier` generated server-side (this is the operator's own money,
   not user self-custody), sealed with `envelope::build` into the operator's
   recipient slot, `memo = "fee"`.

On-chain the fee note is **indistinguishable** from any other deposit: another
commitment leaf, amount hidden by Token-2022 CT, addressee hidden by the stealth
envelope, same operator fee-payer as every deposit. Nobody can tell which leaf is
a fee or that a fee exists.

The operator **sweeps** the fees by scanning the pool with the fee-collector
ML-KEM secret through the ordinary `/receive/` flow (or CLI) — the fee notes
decrypt to spendable `secret`/`nullifier`, and a normal withdraw moves them to
the operator's wallet.

When `fee_collector_address` is empty the deposit keeps stage-1 behaviour
(`wrap(amount)`, fee stays in the operator's underlying ATA, visible on-chain) —
so the private collection is opt-in and backward-compatible.
