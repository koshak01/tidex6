# ADR-022 — Note format v2: amount bound at entry, spend bound to the owner

**Status:** Accepted (25.09.2026, Petr)
**Date:** 2026-09-25
**Supersedes, for the sealed-amount pools:** the note format of ADR-015
(`commitment = Poseidon(secret, nullifier, amount)`)

## Context

A security review on 25.09.2026, prompted by reading *Shielded Bitcoin*
(Shikhelman, Komarov, Moskvin, 24.09.2026), found two structural defects in the
sealed-amount pools. Neither has cost anyone money: the mainnet pools held
nothing at risk when they were found. Both are properties of the design, not
bugs in one line, so they are fixed by a new note format rather than patched.

### D1 — the amount inside a note is not bound to the amount paid in

`deposit(amount, commitment)` moves `amount` tokens, but the commitment is
computed by the client and nothing checks that it encodes the same amount.
`withdraw` pays the amount the proof carries. So a note claiming a million can
be funded with one cent and withdrawn for a million, as long as the pool holds
it. The contract comment saying *"a commitment that does not match its amount
is a note nobody can ever withdraw"* is wrong: it is a note that withdraws
exactly what it claims.

Affected: the EVM hidden pools (Solidity and Stylus), the Solana
`tidex6-confidential-pool` program, and the Solana mainnet path through the pool
service, which pays the amount the client names at withdrawal
(`withdraw_browser`) with only a vault-balance check.

### D2 — a note is a bearer instrument

The withdraw circuit proves knowledge of `secret` and `nullifier` only. The
sender generates both, so the sender can spend the note before the recipient
does, a payer can withdraw their own fee note, and a sender can fund two notes
with one `nullifier` so the recipient sees two payments but can spend one
("Faerie Gold", Garman–Green–Miers 2016). The intended *refund after a window*
exists only on Solana and only as a service rule.

## Decision

### 1. Keys

The identity already derived from a wallet signature (ADR-018) yields a
spending key. From it:

```
sk_spend   = spending key, as a field element
owner_pk   = Poseidon(D_OWNER, sk_spend)
```

`owner_pk` is published in the reader registry next to the reader address, so a
sender who knows only a wallet address can bind a note to its owner (§5). A
hash-based key is enough: encryption stays ML-KEM (post-quantum), and
ownership needs only a preimage, which costs one Poseidon in the circuit.

### 2. Note

```
core   = Poseidon(D_CORE, owner_pk, rho, aux)
body   = Poseidon(core, amount)
refund = Poseidon(refund_addr, refund_after)      or 0 for "no refund"
cm     = Poseidon(body, refund)                   the leaf
```

- `rho` — fresh randomness, chosen by the sender, sealed to the recipient.
- `aux` — reserved, `0` in v2. The slot extensions bind to (hash-locks for
  atomic swaps, lineage claims for regulated pools) without a new format.
- `refund_addr`, `refund_after` — who may take the note back and from when.

### 3. The pool computes the leaf — D1 closed

The depositor sends `core` and the tokens. The **pool** computes
`body = Poseidon(core, amount)` from the amount it actually received, and
`refund` from `msg.sender` (the Solana signer) and
`refund_after = now + window`. The leaf is therefore bound to the real amount by
construction; there is nothing left to lie about. Cost: three Poseidon calls on
chain (Solana: the `sol_poseidon` syscall).

`depositWithFee` computes the fee note with `refund = 0`: the fee cannot be
taken back, whatever the payer does.

### 4. Spending

**Owner path (ZK).** The withdraw circuit proves:

1. `Poseidon(D_OWNER, sk) = owner_pk` — the spender owns the note;
2. `cm` rebuilt from `owner_pk, rho, aux, amount, refund_addr, refund_after`
   is in the tree under a known root;
3. `nf = Poseidon(D_NF, rho, pos)`, `pos` the leaf's position;
4. `0 ≤ amount < 2^64`, `amount = amount_public`;
5. recipient, relayer and fee bound as today (ADR-011).

Public inputs: `root, nf, recipient_hi, recipient_lo, relayer_hi, relayer_lo,
fee, amount` — the same eight as v1, so the verifier interface and the relayer
change nothing but the key.

**Refund path (no proof).** After `refund_after`, the address that funded the
note calls `refund(owner_pk, rho, aux, amount, refund_after)`. The pool
recomputes `cm` with `refund_addr = msg.sender`, finds its position, computes
the same `nf`, marks it spent and returns `amount`. Only the funder can do it,
only after the window, and the recipient can no longer spend it afterwards —
one note, one nullifier, whichever path is taken first.

### 5. Nullifier — D2's Faerie Gold closed

`nf = Poseidon(D_NF, rho, pos)`. The position is assigned by the pool, so two
notes can never share a nullifier even if a sender reuses `rho`. The nullifier
does not depend on a key because both paths must produce the same one.

Accepted leakage: the sender knows `rho`, so can tell *when* the recipient
spent. Nobody else can.

### 6. Join-split (1 → 2)

Inputs spent by the owner path; outputs are `cm_i = Poseidon(Poseidon(core_i,
amount_i), 0)` — no refund on notes created inside the pool — with conservation
and range proved as today.

### 7. Solana

Solana moves to the same model: a pool program that holds the tokens and
computes the leaf (the `tidex6-confidential-pool` lineage), instead of a pool
that only records hashes while the service moves wrapped tokens and names the
payout. This also removes custody from the service: no operator vault, no
operator-signed payout.

Privacy does not regress. Today the entry is already public — the sender's
plain USDC transfer to the operator — and so is the exit (the USDC payout).
Hiding the entry amount on every chain is the confidential token (Baby Jubjub
ElGamal), a later layer that feeds this same note format through a deposit proof
instead of a public amount.

### 8. Registry

Record v3: `reader (1216 bytes) ‖ owner_pk (32 bytes)`. Every recipient
re-enables receiving once per chain — one signature, one registry write. A
wallet without a v3 record cannot be paid in v2 pools, and the send page says
so instead of failing late.

### 9. Ceremony and rollout

New withdraw and join-split circuits → a new public ceremony (restart, as on
02.09). Order: EVM testnets → Solana devnet → Arc mainnet → Solana mainnet.
The v1 pools are left withdraw-only and **are not safe to hold value** (D1
applies to anything still in them); the site stops showing them once empty.

## Consequences

- Payments behave as users expect: only the named wallet can take the money;
  the sender can take it back only after the stated window; fees are final.
- Deposit costs three extra Poseidon calls; withdraw adds one Poseidon in the
  circuit. The public interface of `withdraw` is unchanged.
- Recipients re-enable once. Senders change nothing.
- A post-mortem is published after the rollout, crediting the paper that led to
  the review.
