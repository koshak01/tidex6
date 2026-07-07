# ADR-015 — Confidential amounts: variable-amount Groth16 pool + Token-2022 confidential wrapped stable

**Status:** Accepted (design) — implementation targets the next verifier
generation; nothing in the finalized mainnet verifier `CSDD31Zm…` changes.
**Date:** 2026-07-04
**Partially supersedes:** ADR-001 (the *next-generation* pool commitment
gains an `amount` field; the current pool keeps `Poseidon(secret, nullifier)`
forever — it is immutable).

## Context

Three facts converged in early July 2026.

**1. Token-2022 confidential transfers are live again.** The ZK ElGamal
Proof program — disabled network-wide since June 2025 after the
Fiat-Shamir transcript incident — was re-enabled by feature
`zkexuyPRdyTVbZqEAREueqL2xvvoBhRgth9xGSc1tMN`, active on mainnet since
slot 424 224 000 (2026-06-04). We verified this end-to-end on mainnet
with two spikes:

- full confidential-transfer lifecycle (mint `BbNkMLu1…KShB`): deposit →
  apply → **transfer with hidden amount**
  (`3bzWixWpJit1JctpYHFt1sh5JEFh732tUxmA4iQu3WtjeXhLS7Ucw7ydWLKYVPcAPnrueJCPDBSbGjsL9FyTX1nD`)
  → withdraw. On-chain history shows this is the **first confidential
  transfer on mainnet after the re-enable** (the only prior use of the
  proof program was a two-transaction smoke test on 2026-06-08).
- confidential **mint-burn** lifecycle (mint `AupUFasK…gQwU`, crate
  `crates/tidex6-ct-lab`): a mint carrying `ConfidentialTransferMint`
  (with a native **auditor** ElGamal key) plus `ConfidentialMintBurn` —
  the token's supply itself is an ElGamal ciphertext. Confidential mint
  of 1 000 units (empty public supply, hidden emission), apply, then
  confidential burn of 400. This