# tidex6 v2 — progress log

Note format v2 ([ADR-022](adr/ADR-022-note-format-v2.md)): the amount is bound
by the pool, only the owner spends, refunds are verifiable, and the 1% fee
cannot be skipped. This file is the running record of the work — what is done,
with commits, and what comes next.

## Why

A security review on 25.09.2026, prompted by *Shielded Bitcoin* (Shikhelman,
Komarov, Moskvin), found two structural defects in the v1 sealed-amount pools:
a note's amount was not bound to the amount paid in, and a note was a bearer
instrument its sender could spend. No funds were lost — the mainnet pools held
nothing at risk. Both are fixed by a new note format rather than patched. A
full post-mortem follows the rollout.

## Done

| Date | What | Commit |
|---|---|---|
| 25.09 | ADR-022 accepted: note format v2 | `3f08986` |
| 25.09 | Circuits v2: withdraw (owner key, position-bound nullifier) and in-pool transfer; checked on a dev setup against a changed amount, recipient, foreign key and inflated output | `3f08986`, `c8d41ec` |
| 25.09 | EVM pool v2 (Solidity): the pool files each leaf from the amount it received; refund after the funder's window, no proof, one nullifier with withdraw | `6825dc2` |
| 25.09 | Stylus pool v2 (Arbitrum, Robinhood): same ABI | `77dd169` |
| 25.09 | The fee cannot be skipped: one way in charges 1% (rounded up, floor 0.1 token) and files the fee note for the treasury key; in-pool forwards are 1 → 3 (payment, change to self, fee) with the fee proved in the circuit | `4ddcd55`, `3c36f6a` |
| 25.09 | 15 Foundry tests for pool v2, green in CI: amount binding, refund rules, shared nullifier, fee rules | CI |
| 25.09 | Local MCP pays, finds and collects on EVM (evm_send / evm_payments / evm_collect / evm_enable), full loop on Arc testnet | `4ac15fe` |


## Next

1. Solana pool v2 — a program that holds the tokens and files the leaf, the
   same fee and refund rules; removes custody from the pool service.
2. Reader registry v3 — publish the owner key next to the reader address;
   recipients re-enable once per chain.
3. Clients — WASM prover, site, MCP, relayer and indexer on the v2 format.
4. Public ceremony for the v2 circuits (restart).
5. Rollout — EVM testnets → Solana devnet → Arc mainnet → Solana mainnet; v1
   pools become withdraw-only and leave the site once empty.
6. Post-mortem, crediting the paper that led to the review.

Later: confidential token on Baby Jubjub (hidden entry amount on every chain),
regulated pools with lineage proofs, an honest anonymity-set metric.
