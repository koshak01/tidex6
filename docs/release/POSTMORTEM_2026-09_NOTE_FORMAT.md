# Post-mortem: two gaps in the note format, found by our own review

**Status:** fixed by a new note format (ADR-022), live on Arc testnet and
Solana devnet; mainnet follows the public ceremony.
**Funds lost:** none. **Found by:** our own review, before anyone reported it.
**Dates:** found 25 September 2026, fixed and proven on chain 25–26 September.

## What happened

On 25 September 2026 we read *Shielded Bitcoin: Private Transfers on the
Bitcoin L1* by Clara Shikhelman, Mikhail Komarov and Aleksei Moskvin
([[alloc] init]). Their note design binds spending authority to the owner's
wallet key inside the note, derives each note's leaf from its ciphertext, and
makes the nullifier depend on the note's position — deliberately, against the
class of attack known as *Faerie Gold*.

Reading it next to our own code, we asked the same questions of tidex6 and
found two gaps in our note format:

1. **The amount inside a note was not bound to the amount paid in.** The
   pool accepted a note whose committed amount the sender chose, next to a
   token transfer the sender also chose. Nothing forced the two to agree.
2. **A note was a bearer instrument.** Whoever knew its secret could spend
   it — including the sender, after paying. That also let a sender take back
   the fee note it had just paid, and two notes could share a nullifier.

We describe them at this level on purpose: the old pools are closed to new
payments, and a recipe helps nobody.

## Why no money was at risk

- Both gaps let a note take money that other notes had put into the same
  pool. The sealed-amount pools on Arc mainnet were empty when the gaps were
  found (checked on chain), so there was nothing to take.
- The mainnet pools had only ever seen our own test payments; no third
  party's money was in them.
- Testnet pools hold test tokens only.

## The fix: note format v2 (ADR-022)

We did not patch the old format. We replaced it:

- **The pool files every note itself.** The sender hands over only the
  note's *core*; the pool computes the leaf from the amount it actually
  received: `leaf = H(H(core, amount), refund)`. A note cannot claim more
  than was paid into it.
- **Only the owner spends.** The core contains the recipient's owner key,
  `H(domain, spending_key)`, and the withdraw circuit proves knowledge of that
  spending key. The sender no longer holds anything spendable.
- **Position-bound nullifier.** `nf = H(H(domain, rho), position)` — two notes
  never share one, and withdraw and refund produce the same one, so a note is
  spent exactly once by whichever path comes first.
- **An honest way back.** A sender may choose a deadline; if the recipient has
  not collected by then, the sender takes the payment back — no proof, the
  pool rebuilds the leaf with the caller as funder. The sender's copy of the
  note travels in the envelope, sealed to the sender's own key, so nothing
  has to be stored.
- **The fee is part of the pool.** Every deposit pays 1% (at least 0.1) as a
  note the pool files for the treasury key it was deployed with; in-pool
  forwards are 1 → 3 with the fee proved in the circuit. It cannot be skipped
  or reclaimed.

The same format runs on EVM (Solidity and Arbitrum Stylus, one ABI) and on
Solana (an Anchor program that holds the tokens itself).

## What we found on the way

Building v2 end to end surfaced more, all caught before any v2 pool held
real money:

- The first testnet keys came from a development setup whose layout did not
  match the prover every client uses; no withdraw would have verified. v2
  keys now come only from ceremony states, and a self-test that rejects the
  old key guards the export.
- On Solana: forwarded notes had no envelope account (the recipient could not
  have found them); envelope accounts carried no mint (pools would have
  shared one tree); a refund closed its envelope account (a hole in every
  later proof); and a recipient collecting on their own was refused by the
  framework's duplicate-account rule.
- A refund window at the minimum was always refused: the client read the
  block time, the program checks its own clock later.

## Proof on chain

- Arc testnet: owner key published, payment filed as 2.0 + 0.1 fee, withdrawn
  by the owner key.
- Solana devnet: the same, plus a refund after the window — after which the
  recipient could no longer collect it.

Transactions are listed in [V2_PROGRESS.md](V2_PROGRESS.md).

## What is next

1. Public trusted-setup ceremony for the two v2 circuits — open now at
   ceremony.tidex6.com.
2. Mainnet rollout of v2 with the ceremony keys. The old pools stay
   withdraw-only and leave the site once empty.

## Thank you

To Clara Shikhelman, Mikhail Komarov and Aleksei Moskvin: your paper is why
we looked where we looked. Admitting a gap and fixing it properly matters
more to us than pretending there was none.
