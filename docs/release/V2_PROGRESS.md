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
| 25.09 | Solana pool v2: the program holds the tokens (no operator custody), files both leaves from what it charged, mandatory fee, refund after the funder's window, init reserved to the upgrade authority; dev keys until the ceremony | `02a3028` |
| 25.09 | Owner keys: `Tidex6OwnerKeys` (Solidity + Stylus, same ABI, 3 tests) and a Solana PDA in pool v2 — reader keys published so far stay valid, a recipient adds one short transaction per chain | `58f2c02` |
| 25.09 | Local MCP pays, finds and collects on EVM (evm_send / evm_payments / evm_collect / evm_enable), full loop on Arc testnet | `4ac15fe` |
| 25.09 | Clients on v2: the Rust client, CLI (`print-owner-pk`), local MCP and relayer (index, withdraw, treasury collector) speak the v2 note | `0ce958a`, relayer `72ba217` |
| 25.09 | First v2 stand on Arc testnet (dev keys): pool, owner-key registry, both verifiers; a recipient published an owner key, then a 2 USDC payment went in and the pool filed two leaves itself — payment 2.0 and fee 0.1 — from what it received | tx `0x25e0660a…b28f` |

| 25.09 | Found before the first withdraw: the stand's v2 keys came from the arkworks setup while every client proves in the snarkjs layout — no v2 withdraw would have verified. v2 keys now come only from ceremony states; the seeded setup is gone from the v2 modules | `81993c6` |
| 25.09 | Genesis keys for both v2 circuits (snarkjs setup, zero contributions; pot13 / pot15), self-tested; the self-test rejects the former key. Verifiers, Stylus, Solana program VKs and proving keys regenerated | `a7af563` |
| 25.09 | Refund without local storage: a payment with a refund window carries a funder slot sealed to the sender's own reader key; the sender rebuilds refunds from the chain on any device. MCP `evm_refund` | `72f1c87` |
| 25.09 | WASM prover 2.7.0: owner key, core, leaf, refund tag, nullifier, fee, v2 withdraw and 1 → 3 transfer provers, funder slot | `81993c6`, `72f1c87` |
| 25.09 | Full v2 loop on the redeployed Arc testnet stand (genesis keys): owner key published, 2 USDC paid (pool filed payment 2.0 with a 24 h refund window and a funder slot, fee 0.1 with none), recipient proved the withdraw locally and the relayer sent it — 2.0 out, the fee note stays for the treasury | tx `0x0bd1fc14…5edd`, `0x70859daf…17a6` |

## Next

1. Clients — WASM prover, site, MCP, relayer and indexer on the v2 format.
2. Public ceremony for the v2 circuits (restart).
3. Rollout — EVM testnets → Solana devnet → Arc mainnet → Solana mainnet; v1
   pools become withdraw-only and leave the site once empty.
4. Post-mortem, crediting the paper that led to the review.

Later: confidential token on Baby Jubjub (hidden entry amount on every chain),
regulated pools with lineage proofs, an honest anonymity-set metric.
