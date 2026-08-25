# ZeroClaw Earn — closed, no prize

**Listing:** https://superteam.fun/earn/listing/zeroclaw
**Sponsor:** Superteam Brasil · **Prize pool:** 5,000 USDG · **Submitted:** 2026-07-30
**Outcome:** not among the winners. Top five were announced the week of 2026-08-21.

This file used to say "waiting". It is kept, rather than deleted, because the
submission produced things that outlived it and are still in the product.

## What it left behind

- **`tidex6-mcp-local`** — the stdio MCP server, where the signing key sits on
  the operator's own machine. Custody T2, not T1.
- **Limits in code, not in a policy document** — per-payment and rolling-day
  caps, USDC/USDT only, recipient must be in the on-chain registry. A cap that
  lives in prose is a cap the software does not have.
- **The path an agent actually pays through.** On 2026-08-25 an agent made a
  real mainnet payment over exactly this interface. That run surfaced six
  separate defects, every one of them reachable by an ordinary user — which is
  the real return on this submission.

## What not to repeat

Do not describe this bounty as pending anywhere: the answer arrived and it was
no. It can be cited as work that was done, never as a reward that is coming.
