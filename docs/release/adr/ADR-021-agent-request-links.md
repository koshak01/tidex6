# ADR-021 — One link shape for everything an agent hands a person

**Status:** Accepted (implemented)
**Date:** 2026-07-28

## Context

An agent connected over MCP cannot move money, and that is deliberate: it holds
no spending key, and the only thing it can produce is a link the person opens
and signs themselves (ADR-018). Three of the server's tools end that way —
`payment_request`, `receive`, `audit`.

They ended that way in three different shapes. A payment produced
`/send/?r=<id>`, backed by a stored request carrying the amount, the recipient
and the memo. Receiving and auditing produced a bare `/receive/` and
`/accountant/` — nothing stored, nothing carried.

Which was defensible: there is genuinely nothing to carry. A scan takes no
parameters. The key that finds the payments is derived in the browser from a
wallet signature, and the filter is the decryption itself — a foreign envelope
simply fails to open.

Two things made it wrong anyway.

**For the person, the three are one gesture.** The agent sends a link, they open
it, they sign. Two link shapes make them ask which kind they are looking at,
and that question has no useful answer.

**A bare link forgets who it was for.** The MCP connection knows the caller's
wallet — the OAuth token was issued against a wallet signature. A link with
nothing in it drops that knowledge at the door, and the page opens in whatever
network was last selected, scanning with whatever wallet happens to be
connected. On 2026-07-27 that produced the exact failure it sounds like: a
payment of 10 USDT sent to `2GdZ…`, `/receive/` open with `Cs9F…` connected, an
empty list, and a person reasonably asking where his money went. Nothing was
broken. The page just never said whose key it was looking with, and silence
reads as *"there is nothing here."*

## Decision

### 1. Every agent-issued link is `/<page>/?r=<id>`

`payment_request`, `receive` and `audit` all create a stored request through the
same `POST /api/pay/new` and return the same shape. On the MCP side there is one
`post_request` helper, not one copy per tool.

### 2. The request's `kind` says what it carries, and it carries only that

- `payment` — amount, recipient, memo, auditor, reclaim window. Without the
  request there is nothing to pay.
- `receive`, `audit` — network and wallet only. There is nothing else to carry,
  and inventing fields to make the three look symmetric would be dressing.

### 3. The wallet in the request is checked, and said out loud

The page states whose payments it is looking for before anything happens, and
refuses a different connected wallet with a sentence naming both.

For a payment this is a security boundary: the link is not payable to bearer,
or a forwarded link would spend a stranger's money and the sign-in signature
would have meant nothing.

For a scan it is not a security boundary — a foreign wallet derives a different
key and decrypts nothing, with or without the check. It is an **honesty**
boundary. The cryptography already refuses; the check is what turns that refusal
from an empty list into an answer.

### 4. An expired link does not close the door

Scanning needs no request. A stale `?r=` says so and lets the person continue —
the request was a convenience, and a convenience that expires into a locked door
is worse than no convenience.

## Consequences

- One thing to change when the shape changes, not three.
- The page can say what it is doing, which is most of what went wrong.
- Stored requests now exist for actions that store nothing else. They are
  short-lived and hold only what is already public — a network name and a wallet
  address — but they are state where there was none, and that is the price.
- Requests are in memory: a restart drops the pending ones. Acceptable while a
  link is opened within minutes of being issued; if that stops being true, this
  is the thing to revisit.

## Related

- ADR-018 — MCP server: what an agent may and may not do.
- ADR-020 — Wallet sign-in: where the caller's wallet comes from.
- `tidex6-web/docs/WEB_CANON.md §4-бис` — the page-side contract.
