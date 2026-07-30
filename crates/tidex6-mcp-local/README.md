# tidex6-mcp-local

An MCP server that sends private Solana payments **with a key on your own
machine** — no browser, no link, no hosted service in the signing path.

Point any MCP client at it (Claude, ZeroClaw, anything speaking stdio) and the
agent can pay, receive and audit. What bounds it is not the prompt but the code:

- a per-payment cap and a rolling 24-hour cap, checked before the first
  transaction;
- USDC and USDT only, not configurable;
- amounts are an enum, so "send 4,999" is not expressible on the wire and an
  injection has no way to say it;
- the recipient must already exist in the on-chain reader registry, so a fresh
  attacker address is not a valid destination;
- the key file must not be readable by group or other, or the server refuses to
  start.

There is a hosted sibling that holds no key at all and returns a link for a human
to sign. Same tool names, same skill, different custody. Which one you run is the
question this crate exists to let you answer.

## Status

Live on Solana mainnet. The verifier program
[`CSDD31Zm…`](https://solscan.io/account/CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd)
is immutable and OtterSec-verified; the pools and the reader registry are
verified and still upgradeable.

**Pre-audit.** The verifying key comes from a single-contributor trusted setup, so
proofs against it are forgeable by whoever ran that setup. A public ceremony is
live at [ceremony.tidex6.com](https://ceremony.tidex6.com) and needs
contributors — it takes a minute in a browser, spends nothing, and authorises no
payment. Until it finalises, do not use this to secure real funds.

- Repository: <https://github.com/koshak01/tidex6>
- Docs: [THE_LEGEND](https://github.com/koshak01/tidex6/blob/master/docs/release/THE_LEGEND.md) ·
  [PROJECT_BRIEF](https://github.com/koshak01/tidex6/blob/master/docs/release/PROJECT_BRIEF.md) ·
  [security](https://github.com/koshak01/tidex6/blob/master/docs/release/security.md)

License: MIT OR Apache-2.0.
