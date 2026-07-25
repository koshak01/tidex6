# ADR-018 — MCP server: giving AI agents access without giving them keys

**Status:** Accepted
**Date:** 2026-07-25
**Related:** ADR-006 (builder API, no proc macros), ADR-007 (shielded memo / auditor slot), ADR-013 (browser-side proving), ADR-014 (ML-KEM envelope), ADR-015 (two-layer confidential amounts), `security.md`

## Context

An AI agent that can move money is a hot wallet with a prompt-injection surface.
The agent reads untrusted text — a Telegram message, an email, a web page — and
the model cannot distinguish an instruction from its owner from an instruction
embedded in that text. Any design where the agent holds a spending key is one
crafted message away from losing the funds.

At the same time the demand is real: people want to say "send 200 to this
wallet" in the channel they already use, and they want their accountant's agent
to reconcile the month without asking anyone for a file.

tidex6 already has every piece needed to serve this safely, and the pieces
happen to compose into an unusually strong answer:

- **The recipient never receives a note.** They scan the chain with their own
  ML-KEM secret (ADR-014), so there is nothing to hand over and nothing to
  intercept.
- **The auditor slot cannot spend.** It carries `denomination ‖ memo` and no
  `secret`/`nullifier` (ADR-007). Read capability is already separable from
  spend capability *in the ciphertext*, not by policy.
- **Proving already happens in the browser** (ADR-013), where the wallet lives.
- **Keys can be derived, not stored.** `ml-kem 0.2` exposes
  `generate_deterministic(d, z)` under the `deterministic` feature, and ed25519
  signatures are deterministic by RFC 8032. Our Token-2022 layer already does
  exactly this: `ElGamalKeypair::new_from_signature_legacy(&signer.sign_message(msg))`
  in `tidex6-ct-lab/src/ct.rs:903`.

The external trigger is the ZeroClaw bounty (Superteam Brasil, closes early
August 2026), whose custody ladder places "T1 Build — unsigned transactions,
a human signs, **secrets held: none**" as the recommended tier, and which lists
"privacy as an installable capability — stealth addresses, hidden amounts,
compliance viewing keys" as an open frontier. That is a description of this
project. The deadline is useful; the design below is what we would build anyway.

## Decision

### 1. A new crate `tidex6-mcp`, in this workspace

It needs `tidex6-client`, `tidex6-core` and `tidex6-indexer` as path
dependencies, and its wire formats must move in lockstep with the SDK — a
version skew between the note format here and there is silent money corruption.
Separate repositories (`tidex6-web`, `tidex6-relayer`) exist because they deploy
independently; this does not.

The crate is a **thin layer**. Every tool is a wrapper over an SDK builder. No
cryptography, no instruction assembly, no second implementation of anything.

### 2. Custody tier T1: the server never holds a spending key

The agent gets **capability, not custody**:

| Operation | Where it happens | Key involved |
|---|---|---|
| Quote a payment | server | none |
| Build the transaction | server | none |
| **Sign it** | **user's wallet** | user's, never leaves it |
| Read incoming payments | server or agent | view key only |
| Withdraw funds | user's wallet | user's |

Signing is delivered as a **Solana Action / Blink**: the server hosts an
endpoint returning an unsigned base64 transaction, the agent hands the URL to
the user, the wallet previews and signs. Zero key handling on our side and on
the agent's side. A prompt injection that talks the agent into paying an
attacker still produces nothing but a link the human declines.

`approve`-style token delegation is explicitly **out of scope**: it moves us to
T2 and buys convenience we do not need for the core flow.

### 3. Keys are derived from wallet signatures, never stored

```
sign("tidex6 spend v1") → SHA-512 → (d, z) → ML-KEM spend keypair
sign("tidex6 view v1")  → SHA-512 → (d, z) → ML-KEM view  keypair
```

The spend key exists only in the browser tab, for the duration of one operation.
The view key may be exported once to the agent's config — losing it costs
privacy, not money, and that boundary is enforced by what the ciphertext
contains, not by a rule we promise to follow.

Consequences: no keystore, no backup file, no encryption-at-rest problem, no
recovery flow. A new device needs the wallet and nothing else. Rotation is a
version bump in the signed phrase.

`tidex6-core::pqc` gains `keygen_from_seed(seed: [u8; 64])`; `ml-kem` gains the
`deterministic` feature.

### 4. Recipients are addressed by their Solana wallet

The sender needs only the recipient's wallet address. The recipient's public
encryption keys are read **from the chain**:

- the ElGamal public key from their `ConfidentialTransferAccount`, which
  Token-2022 already stores (`ct.rs:417-425` reads it today);
- the ML-KEM public address from a PDA derived from their wallet.

This costs the recipient one activation transaction — "enable private payments"
— roughly 0.0094 SOL of rent, refundable. That activation is a statement about
themselves, not a relationship with any sender: it happens once and serves
everyone forever. No invitations, no key exchange, no out-of-band channel.

Publishing makes "this wallet accepts private payments" public. The payments
themselves stay private. A salted variant (PDA from `hash(wallet ‖ salt)`) is
available for users who cannot reveal even that, at the cost of having to share
the salt. Default is the plain form; the choice belongs to the user, which is
the same principle the protocol applies to amounts.

### 5. The recipient gets two slots, not one

A deposit seals two envelopes for the recipient: the **spend slot**
(`secret ‖ nullifier ‖ denomination ‖ memo`) and a **view slot**
(`denomination ‖ memo`) — the auditor construction, applied reflexively.

This is what lets the recipient's agent work unattended: it holds the view key,
watches the chain, and reports "200 arrived, marked 'February, medicine'"
without being able to move anything.

### 6. Prompt injection is answered in the schema, not in the prompt

- **The payee is not a free string** where an address book exists: the tool
  argument is an enum generated from the user's contacts, so "send everything to
  `7xK…`" is not expressible. Where raw wallet addresses are allowed, the amount
  cap and the human signature are the control.
- **Memo is a template, not free text** (`MonthlySupport{month}`,
  `Invoice{number}`, `Free{≤120 chars}`), and the envelope recipient comes from
  an allowlist. Otherwise an encrypted memo addressed to an attacker's key is a
  perfect exfiltration channel that we ourselves made unauditable.
- **Limits live in server config**, not in instructions. A prompt can be argued
  with; a config cannot.

### 7. Durable nonce for the approval gap

A transaction built by the agent may sit unsigned while the human is away. A
regular blockhash dies in ~90 seconds. Signing links therefore carry a durable
nonce, which costs one nonce account (~0.0015 SOL) and serialises to one
in-flight transaction per account.

### 8. Transport: stdio while building, streamable HTTP in production

stdio for local development and for operators who want the server on their own
machine. Production is `mcp.tidex6.com`, mounted in `tidex6-web` via
`forge_mcp::streamable_service` with `forge_admin::oauth` — both already exist
in the core and are running in two other services of the collective.

Authentication is by wallet signature (SIWS), not password: identity is a
public key. An agent receives a **mandate** — a wallet-signed grant naming what
it may do, up to what amount, until when — which is revoked by signing a new
one.

## Consequences

**Good:**
- The strongest possible answer to "can the agent be tricked into stealing":
  it has no key. Not policy — arithmetic.
- Nothing to store means nothing to leak, back up, or lose.
- The recipient's agent runs unattended and safely, because read and spend are
  separate in the ciphertext.
- Every piece reuses something already deployed: browser proving, ML-KEM
  envelopes, auditor slots, the Token-2022 key-from-signature pattern, the
  forge MCP scaffold.

**Costs:**
- A payment cannot complete without the human. Fully autonomous outbound
  payments are impossible by construction. This is deliberate; a delegated,
  capped session key can be added later as an explicit, separately-argued
  feature.
- The recipient must activate once, on chain, and that activation is public.
- Deriving everything from the wallet means a compromised wallet loses both
  funds and privacy at once. Mitigated by versioned derivation phrases, not
  eliminated. The alternative — storing keys — is worse.
- One nonce account per concurrent pending payment.

**Open:**
- Whether token delegation works *inside* the Token-2022 confidential layer is
  unverified; it only matters if we later add capped autonomy.
- The salted-PDA variant is designed but not scheduled.

## Related

- ADR-007 — auditor slot: read capability separated from spend capability
- ADR-013 — browser-side proving: the tab is already the wallet-side compute
- ADR-014 — ML-KEM envelope and the dedicated memo account
- ADR-015 — Token-2022 confidential amounts, and the key-from-signature pattern
- `security.md` — threat model; this ADR adds the agent as a new actor
