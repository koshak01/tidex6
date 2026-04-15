# ADR-010: Memo transport via SPL Memo Program

**Status:** Accepted
**Date:** 2026-04-15

## Context

ADR-007 committed Shielded Memo to the MVP. That left one open question: *where do the encrypted memo bytes physically live on Solana?*

Three options were considered:

1. **Inline in the verifier's `DepositEvent`.** Add `auditor_tag: [u8; 32]` and `encrypted_memo: Vec<u8>` fields to the event and accept them as instruction arguments to `handle_deposit`. The verifier program emits them verbatim.

2. **Dedicated memo PDA.** A new instruction — either in the verifier or in a separate tiny `tidex6-memo` program — creates a PDA seeded on the commitment whose data is the ciphertext.

3. **SPL Memo Program, same transaction.** The client builds a transaction containing two instructions: the verifier `deposit` and an SPL Memo Program instruction carrying the ciphertext. Solana executes both atomically; the transaction signature binds the memo to the deposit.

ADR-005 adds a load-bearing constraint: the verifier must be non-upgradeable after lock. Any option that changes the verifier interface is a one-shot change — we get one chance to get the event layout right before losing the ability to fix it.

## Decision

**Ship option 3: memo rides in an SPL Memo Program instruction in the same transaction as the deposit.** The verifier is not modified. The memo layer is strictly application-level.

Concretely:

- `tidex6_client::DepositBuilder` builds a transaction of two instructions:
  `[ verifier::deposit(proof, commitment, …), spl_memo::process(base64_payload) ]`
- The base64 payload is the `tidex6_core::memo::MemoPayload` wire format —
  `ephemeral_pk || iv || tag || ciphertext`, base64-encoded.
- The indexer walks the transaction instruction list alongside the program logs
  and attaches `memo_base64` to each `DepositRecord` it reconstructs.
- The accountant scanner calls `try_decrypt_for_auditor` on every recovered
  `memo_base64` and keeps the ones whose AES-GCM tag validates.

## Consequences

**Positive:**

- **ADR-005 intact.** The verifier is not touched. The promise "verifier is non-upgradeable, cannot be patched post-deploy" remains load-bearing, not conditional on when we decided to add memo support.
- **Consensus-path separation.** Memo is unaudited user data; the verifier is the consensus core. Separating them at the program boundary makes the security argument concrete — even an arbitrary bug in the memo format cannot hurt the proof path.
- **Atomic binding via tx signature.** A memo and its deposit are either both on chain or neither. No timing window where the deposit lands without its memo, no orphan memos.
- **Composability.** An integrator that builds on top of `tidex6-verifier` via CPI gets memo support for free without coordinating an event-schema change with us. They attach their own SPL Memo instruction to their outer transaction and the indexer finds it the same way.
- **Explorer and wallet UX.** Phantom, Solflare, and Solana Explorer already render SPL Memo instructions. The encrypted payload appears as a compact base64 blob alongside the deposit — visibility without breaking privacy.
- **Zero additional rent.** No new PDAs, no new accounts. Memo adds a handful of bytes to the transaction fee and nothing else.

**Negative:**

- **Size ceiling.** SPL Memo caps the instruction string at ~566 UTF-8 characters. With the 60-byte fixed prefix (`ephemeral_pk || iv || tag`), base64-encoded, we have ~260 bytes of ciphertext before running out of room. `tidex6_core::memo::MAX_PLAINTEXT_LEN = 256` is the enforcement boundary; longer memos require option 2 (a dedicated PDA) in a later revision.
- **Not in the circuit.** The memo ciphertext is not covered by the withdraw proof. This is fine for the stated threat model — the memo is "privileged view onto my own activity", not "proof of what I spent on". A future v0.2 can lift the check into a circuit if needed; the wire format was chosen with that evolution in mind (shared secret is a BN254 scalar, ready for Poseidon).
- **Discovery surface.** A malicious indexer can refuse to surface memos it would rather hide. Mitigation: anyone can run their own indexer (the crate is 400 lines), and the tidex6-web reference implementation is open source.

## Related

- **ADR-005** — the non-upgradeable verifier invariant that makes option 1 unappealing.
- **ADR-007** — Shielded Memo feature commitment; this ADR is the concrete transport mechanism.
- **ADR-004** — the ECDH primitives the memo encryption builds on (Baby Jubjub, x-coordinate shared secret).
- `crates/tidex6-core/src/memo.rs` — wire format + KDF implementation.
- `crates/tidex6-client/src/deposit.rs` — the builder that assembles the two-instruction transaction.
- `crates/tidex6-client/src/accountant.rs` — the scanner that decrypts what the depositor wrote.
