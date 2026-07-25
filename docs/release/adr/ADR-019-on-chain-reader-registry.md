# ADR-019 — On-chain reader registry: a wallet address is the only thing anyone needs to know

**Status:** Accepted
**Date:** 2026-07-25
**Related:** ADR-014 (ML-KEM envelope), ADR-018 (identity derived from a wallet signature, MCP server), ADR-007 (auditor slot)

## Context

Since ADR-018 a reader's keys are derived from a wallet signature and stored
nowhere. That fixed the key-file problem and created a delivery problem: the
sender needs the recipient's **public** ML-KEM address to seal an envelope, and
that address cannot be computed from a wallet address.

The derivation runs `signature → keys`, and only the owner can produce the
signature. So the recipient can compute their own public key; nobody else can
compute it for them. Today the consequence is that the recipient copies a
2432-character hex string and hands it to the sender out of band.

That is not a rough edge, it is a broken product. A payment system where the
recipient must first transmit a wall of hex to every prospective payer will not
be used by the people it was built for. It also makes the signing link 2500
characters long — unpasteable into a chat, impossible as a QR code.

Three alternatives were considered and rejected:

- **Encrypt directly to the wallet key.** An ed25519 point converts to X25519,
  so a sender *can* derive a shared secret from a bare wallet address with no
  registration at all. Decryption then needs the wallet's private key in X25519
  form, and wallets do not expose it — Phantom offers `signMessage` and
  `signTransaction`, nothing else. Sealable but unopenable.
- **Keep the registry in our own database.** Access could then be gated by
  authentication, hiding even the fact of registration. But we become the
  component without which nothing works, able to lie or to refuse, and the
  project's whole claim is that no such component exists.
- **Store the signature instead of the public key.** Considered because it
  looks symmetric, and rejected outright: the derivation function is public, so
  a stored signature is a stored *private* key. Whoever reads it decrypts every
  envelope addressed to that person and — since withdrawal from the pool proves
  knowledge of `secret`/`nullifier` rather than wallet ownership — moves the
  money to their own address without touching the victim's wallet.

## Decision

A minimal on-chain program, `tidex6-registry`, mapping a wallet address to that
wallet's published reader address.

```
PDA seeds: [b"reader", wallet_pubkey]
contents:  owner, version, total_len, written_len, is_finalized, data
```

`data` holds the `ReaderAddress` from ADR-014 — ML-KEM-768 public key (1184
bytes) followed by the X25519 view-tag key (32 bytes).

**Written by the owner only.** The instruction requires the wallet as signer, so
nobody can publish or overwrite someone else's entry. Re-registration by the
owner is allowed and overwrites in place — that is how rotation works when the
identity version in the signed phrase is bumped.

**Read by everyone, without permission.** This is not a choice we make; it is
what a public ledger is. Every validator holds the full account set and
`getAccountInfo` takes no signature. Any design premised on gating reads at the
chain level is impossible, and one premised on gating them at our server
reintroduces the trusted party.

Which is acceptable precisely because the published value is a **lock, not a
key**. Reading the registry lets you seal a payment *to* someone. It does not
let you open one, spend one, or learn that any payment happened.

**Written in chunks**, reusing the memo pattern: 1216 bytes does not fit in a
1232-byte transaction, so `init_reader` allocates and `write_reader_chunk`
appends with an offset check, exactly as `append_memo` does in the verifier.

**Rent** is roughly 0.0097 SOL, refundable when the entry is closed. Paid once,
by the person registering.

### What this does and does not reveal

On chain: *this wallet accepts private payments, and here is its lock.* Nothing
else — no amounts, no counterparties, no history, and specifically no statement
about who may pay whom. An earlier proposal had the recipient list the wallets
allowed to pay them; that would publish the social graph, which is usually more
sensitive than the amounts, and it is unnecessary because a lock needs no
allowlist.

A salted variant (`PDA from hash(wallet ‖ salt)`) is available for anyone who
cannot reveal even the fact of registration: findable by those given the salt,
invisible to everyone else, same cost. Not the default, because it reintroduces
an out-of-band exchange — the very thing this ADR removes.

### Consequences for the API

`payment_request` takes **wallet addresses**, not reader keys:

```
recipient: "9pQr…"     auditor: "4mNv…"
```

Both are resolved through the registry. The signing link becomes
`tidex6.com/pay?r=k3n8Qf2p` and the sender copies nothing.

A new MCP tool, `register`, returns the link a person opens to publish their own
entry — so an agent can onboard a counterparty by sending one URL.

## Consequences

**Good:**
- A wallet address is the only thing people exchange, and they already do.
- Sender and recipient never interact before the payment. Registration is a
  statement about oneself, made once, serving every future payer.
- Nothing is stored anywhere: keys derive from a signature (ADR-018), the
  registry holds only the public half, and losing the registry costs nothing —
  it can be republished from the wallet.
- No trusted party anywhere in the path.

**Costs:**
- One transaction and ~0.0097 SOL of refundable rent before a person can be
  paid. Small, but it is a step that did not exist before.
- The fact of registration is public. The salted variant exists for those who
  cannot afford even that.
- Another deployed program to maintain. It touches no funds and has no
  authority over anything, which keeps its blast radius at "someone published a
  wrong lock for their own wallet".

**Open:**
- Whether to also publish the Token-2022 ElGamal key here. Currently it lives
  in the recipient's confidential-transfer account, which is already on chain
  and already keyed by wallet, so there is nothing to add.
- Whether the registry program should eventually be made immutable like the
  verifier. It holds no funds, so the argument is weaker; deferred.

## Related

- ADR-014 — `ReaderAddress`: what exactly gets published
- ADR-018 — identity from a wallet signature; the reason this gap exists
- ADR-007 — auditor slot: why an auditor's lock is safe to publish too
