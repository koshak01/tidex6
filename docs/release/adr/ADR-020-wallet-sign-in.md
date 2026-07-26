# ADR-020 — Signing in with a wallet, and the two signatures that must never be one

**Status:** Accepted (implemented, not yet wired to the WS commands)
**Date:** 2026-07-26

## Context

Until now a session identified itself by handing over a public key. Anyone could
hand over anyone's — there was no proof the browser held the matching secret.
For a product whose entire claim is about who may see what, that is not a small
gap.

The obvious fix is Sign-In With Solana: the server issues a challenge, the
wallet signs it, the server verifies. Passwords disappear, which is right for a
product where identity is already a key pair.

The reason this needs an ADR is not the mechanism. It is that tidex6 now has
**two** signatures over two different messages, and merging them would quietly
destroy the privacy the rest of the system is built to provide.

## Decision

### 1. Identity is a wallet signature, not a password

`wallet_challenge` returns a text containing the domain, the wallet address, a
random single-use nonce and a validity note. `wallet_verify` checks the ed25519
signature over exactly that text and binds the session to the wallet.

The text is built by the server, never by the page: a challenge the client
composes proves nothing. The nonce is removed on the first attempt, successful
or not, so one issued challenge cannot be answered twice — an intercepted
signature is not a second sign-in. The domain is in the text so a signature
collected elsewhere does not work here.

Challenge lives five minutes; a session lives a day.

### 2. The sign-in challenge and the key-derivation phrase are different texts

This is the load-bearing decision.

- **The challenge** proves possession of a wallet. It carries no secret
  material — it is a signature over a random nonce — so it may go to the server.
- **`IDENTITY_MESSAGE`** (ADR-018 §3) produces the ML-KEM secret that reads
  **every payment ever addressed to that person**. It must never leave the
  browser tab: not to the server, not into a cookie, not to an MCP server.

If sign-in asked for the derivation phrase, the server would receive the
material from which the reading key is rebuilt. Privacy would end at the moment
we switched sign-in on, and nothing in the running system would look wrong.

So the two texts must differ, and the difference is enforced by a test that
fails the build if they ever converge. A boundary this consequential should not
depend on a reviewer noticing.

### 3. A session says who you are. It does not open anything

Signing in binds a wallet to a session and stops there. Reading payments needs
the wallet present, because the key is derived in the tab each time.

The consequence is worth stating plainly: **a stolen session does not read
anyone's payments.** It permits impersonation until it expires, which is
serious and ordinary; it does not permit reading, which would not be.

### 4. One signature per surface, not two

Because reading needs no session and sending needs no reading key, each page
asks for exactly one signature:

| surface | signature | why |
|---|---|---|
| `/send` | the transfer itself | paying needs no reading key |
| `/receive`, `/accountant` | `IDENTITY_MESSAGE` | reading needs no session |
| MCP authorisation | the challenge | proving whose agent this is |

Nobody is asked to approve two dialogs in a row, and no surface handles a key it
has no use for.

### 5. Authorising an MCP server means the wallet address, and nothing else

An MCP server is a local process with no browser and no wallet; it cannot ask
for a signature, and it must not be able to. Authorisation therefore happens in
a browser page, and what comes back to the server is the **wallet address** plus
a session token.

This is what removes registration from the agent's tool list: the server learns
whose it is once, at connection, instead of treating its owner's setup as a task
it performs.

## Consequences

**Good:**
- Sign-in without a password, on a product where identity is already a key.
- A stolen session cannot read payments — the strongest property here, and it
  comes for free from keeping the two signatures apart.
- The build fails if anyone ever merges the two messages.

**Bad:**
- Sessions live in the ws process, so a restart signs everyone out. Acceptable:
  signing in again is one click, and not persisting is one fewer place holding
  metadata about who reads what.
- `ed25519-dalek` and `bs58` join `tidex6-web`'s dependencies. Pinned to the
  versions already in the workspace graph so the build carries one copy.

**Ugly:**
- Two signature texts is a thing to explain, and someone will eventually propose
  simplifying it. The test is there for that day.

## Related

- ADR-018 — MCP server, custody tier T1, key derivation from wallet signatures
- ADR-019 — the on-chain reader registry that makes wallet addresses sufficient
