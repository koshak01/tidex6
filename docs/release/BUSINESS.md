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

### Costs against that, corrected 22.09.2026

An earlier version of this page called the envelope rent "recoverable capital,
returned when accounts close after the reclaim window". That was wrong, and the
correction matters more than the revenue table above it.

Measured on the live mainnet pool: an envelope account holds **0.0102–0.0191
SOL** of rent depending on how many readers the envelope carries, and the
nullifier record written at withdrawal holds **0.00117 SOL**. The envelope
account is closed in exactly one instruction — `refund`, the path taken when a
payment is *never collected* and the sender takes it back. A payment that is
collected normally leaves its envelope account on chain permanently. So the rent
is an **expense, not a float**: roughly **1–2 USD per payment** at SOL around
100 USD.

Against that, the fee on a small payment is 0.1 USDC. The floor does not cover
the rent — it is an order of magnitude short, and the sentence above about the
floor "making the economics honest at the bottom" is only true for compute, not
for rent. Below roughly 200 USDC per payment, Solana payments lose money at the
current parameters.

Three ways out, none of them chosen yet (the decision is the operator's):

1. **Collect the fee once a day, not per payment.** Today a private fee note is
   its own deposit, so each payment writes *two* envelope accounts instead of
   one. Batching removes about half the rent immediately and needs no program
   change.
2. **Raise the floor** to cover the rent (~0.3 USDC), which prices out small
   payments.
3. **Stop storing envelopes in accounts.** The envelope is already in the
   deposit transaction's instruction data; readers could be found by replaying
   transactions instead of listing accounts, leaving only a small header account
   for the refund path (~0.0016 SOL). This is the only option that removes the
   cost rather than moving it, and it is a program change plus a rewrite of how
   both the recipient and the auditor find their payments.

Compute and the RPC bill are the rest, and they are small next to the above.

**On the EVM chains none of this applies:** the envelope rides in the event log,
which costs gas once and no rent ever.

## The fee is collected privately

Worth saying because it is unusual and it is the product working on itself: the
fee does not land in a visible ATA. It is deposited as its own stealth note to
the operator's reader key (ADR-016), so an observer cannot separate "fee income"
from any other payment in the pool, and cannot count our revenue by watching the
chain.

We can. Nobody else can. That is exactly what we sell.

**Same on the EVM hidden-amount pools since 22.09.2026.** Before that date the
EVM side worked the other way round: the sender saw no fee at all and the
relayer took 1% out of the note when the recipient withdrew — publicly, as a
parameter of the withdrawal. Now the sender pays the fee on top, sees the exact
total before signing (enter 1, the page says 1.01), and the fee travels as its
own sealed note to the treasury's published reader key. The recipient gets the
full amount named, and the relayer charges nothing at the exit. The
fixed-denomination pools still work the old way; they are not the product we
are building on.

One consequence, stated because it is the kind of thing that should not be
discovered by a reader: the fee note and the payment note are two separate
deposits from the same wallet, seconds apart. Their *values* are individually
visible on the token's transfer log — that is how ERC-20 works, and it was
already true of every deposit before any fee mechanism existed. What the pool
hides is which withdrawal later spends which note, not how much went in.

## What the fee pays for

The fee is also how the system pays its own running costs, and on one chain that
loop is closed.

**Arc** is the clean case: gas there is USDC, the same token the pools move. The
relayer keeps a 2 USDC reserve on its hot wallet and sweeps the rest to the
treasury once a day — no conversion, nothing to buy.

**Solana** needs a swap, and it has one: when the operator's SOL falls below
0.1, the fee of the next payment is swapped to SOL through Jupiter instead of
being sealed to the treasury (`crates/tidex6-ct-lab/src/gas.rs`). The swap
transaction is built by Jupiter and checked against a whitelist before the
operator key signs it.

**The other EVM chains** have no such loop yet: gas there is ETH or HYPE, the
fee is USDC, and nothing converts one to the other. Their relayer gas is
topped up by hand. Closing that is the next piece of work on this page, and the
target is the shape above: fee into a fund, fund into whichever gas each chain
needs, no human in the loop.

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

**Rent makes small Solana payments unprofitable.** See the corrected cost
section above: ~1–2 USD of permanent rent per payment against a 0.1 USDC floor.
Three ways out are listed there; none is chosen.

**Collecting the fee privately is solved; spending it is half-solved.** Revenue
accumulates as stealth notes. Spending it on the system's own gas is automatic
on Arc (gas is USDC) and on Solana (swapped through Jupiter under a threshold).
Spending it as *income* — moving it to an account a human uses — is still a
withdrawal like any other, so the operator's own money becomes linkable at the
moment it is cashed out. Fixing that properly needs the same association-set
work as everything else in the roadmap.

**On the other EVM chains the fee does not reach the gas.** Fee in USDC, gas in
ETH or HYPE, no conversion — those relayers are funded by hand. The design for
closing it (one fund, per-chain swaps, no human) is agreed; the code is not
written.

**One signature, not three.** A hidden-pool payment on EVM is currently an
approval, a deposit and a second deposit for the fee — three wallet prompts for
one payment. The sender sees the right total before any of them, and a failed
fee deposit cannot fail the payment, but it is three prompts. Doing it in one
transaction means a pool contract that takes both notes in a single call, which
means new contracts on every EVM chain: the existing ones are immutable by
design. That is the next contract-level piece of work, and it carries a
trade-off worth naming — two notes in one transaction are provably linked, so
the fee's value would become a hint about the payment's value unless the fee is
salted.

**The pool operator sees the send side.** Wrapping into confidential Token-2022
requires the mint authority, so the operator knows which wallet paid how much.
Privacy from the public is complete; privacy from the operator on the send path
is not, and pretending otherwise would be the kind of claim this project exists
to avoid making.
