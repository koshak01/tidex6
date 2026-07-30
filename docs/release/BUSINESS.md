# How tidex6 makes money

One page, written because a judge asked the question we had not answered
anywhere: *is there a business here, or is this a very good demo?*

Everything below is in the code today, not planned. The numbers are the defaults
in `crates/tidex6-ct-lab/src/config.rs`.

---

## The charge

**1% of the payment, with a floor of 0.1 tokens.** Paid on top by the sender, so
the recipient receives exactly the amount that was named:

```rust
pub fn fee_micro(&self, amount_micro: u64) -> u64 {
    let pct = (amount_micro as u128 * self.fee_bps as u128 / 10_000) as u64;
    pct.max(self.fee_floor_micro)
}
```

A 100 USDC payment costs the sender 101 USDC. A 1 USDC payment costs 1.1 — the
floor dominates at small amounts, deliberately: a private payment costs us the
same rent and compute whether it moves one dollar or ten thousand.

The floor is also what makes the economics honest at the bottom. Below roughly
10 tokens, percentage alone would not cover the on-chain cost of the envelope
account, and we would be paying people to use us.

## Who pays, and why that matters

The sender pays, in the same transaction that funds the payment. Not a
subscription, not a listing fee, not a token. If nobody pays anybody, we earn
nothing — which is the correct incentive for a payment rail and the reason we did
not build a fee that charges for access.

**The honest caveat, stated because it is currently true:** in the demo the
operator wraps with its own funds, so "amount plus fee" is a number the operator
moves for itself. The revenue model turns real when the sender's own tokens fund
the wrap — that path exists in the code (`payment_sig` verification before the
wrap) and is what the browser flow already does. Until there are senders who are
not us, this section describes a mechanism, not an income.

## What it looks like at volume

At 1% with a 0.1 floor, monthly revenue by payment mix:

| payments / month | average size | fee revenue |
|---|---|---|
| 1 000 | 50 USDC | 500 USDC |
| 10 000 | 50 USDC | 5 000 USDC |
| 10 000 | 500 USDC | 50 000 USDC |
| 100 000 | 200 USDC | 200 000 USDC |

The interesting column is the average size, not the count. Payroll and
contractor invoices — the case this was built for — sit in the hundreds, not the
single digits. Ten thousand payments a month is one mid-size company paying two
hundred contractors twice a month, plus a handful of others.

Costs against that: rent for one envelope account per payment (~0.018 SOL,
recoverable), compute, and an RPC bill. At 10 000 payments a month the on-chain
cost is roughly 180 SOL of *rent-locked* capital, not expense — it returns when
accounts close after the reclaim window.

## The fee is collected privately

Worth saying because it is unusual and it is the product working on itself: the
fee does not land in a visible ATA. It is deposited as its own stealth note to
the operator's reader key (ADR-016), so an observer cannot separate "fee income"
from any other payment in the pool, and cannot count our revenue by watching the
chain.

We can. Nobody else can. That is exactly what we sell.

## Why this is not a token

There is no token and no plan for one. A privacy rail that needs its own asset to
work has a second reason to exist, and that reason competes with the first. Fees
in the asset being moved — USDC and USDT — keep the incentive single: make
payments people want to make.

## What has to be true for this to be a business

Not a large number of users. A small number of **integrators**, because the unit
of adoption here is a program or an agent, not a person:

- an agent runtime that ships tidex6 as its payment capability (one MCP config
  block, no code — this is live today);
- a payroll or invoicing product that routes through the pool via CPI (~30 lines
  of Rust — the reference integration existed as `tidex6-tip-jar`);
- a business that pays contractors and cannot publish what it pays.

Each of those brings a stream of payments rather than one. That is the shape we
are building toward, and it is why the SDK, the MCP servers and the CPI example
matter more than a consumer interface.

## What we have not solved

**Collecting the fee privately is solved; spending it is not.** Revenue
accumulates as stealth notes, and turning that into an operating account is a
withdrawal like any other — which means the operator's own income becomes
linkable at the moment it is cashed out. Fixing that properly needs the same
association-set work as everything else in the roadmap.

**The pool operator sees the send side.** Wrapping into confidential Token-2022
requires the mint authority, so the operator knows which wallet paid how much.
Privacy from the public is complete; privacy from the operator on the send path
is not, and pretending otherwise would be the kind of claim this project exists
to avoid making.
