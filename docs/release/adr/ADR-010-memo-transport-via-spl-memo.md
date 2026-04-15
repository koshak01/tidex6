# ADR-010: Memo lives inside the verifier program

**Status:** Accepted — Supersedes the 2026-04-15 initial revision
**Date:** 2026-04-15 (revised same day)

> Earlier revision of this document recommended an SPL Memo Program transport for the Shielded Memo payload. After user review that recommendation was rejected as architecturally compromised. The current revision records the **correct** decision: memo is a first-class field of the `deposit` instruction and the `DepositEvent`.

## Context

ADR-007 committed Shielded Memo to the MVP. That left one open question: *where on Solana does the encrypted memo physically live?*

Three options:

1. **Inline in the verifier `DepositEvent`.** Add `memo_payload` to `handle_deposit`'s arguments and to the event. The verifier emits the bytes verbatim.
2. **Dedicated memo PDA.** A new instruction creates a PDA seeded on the commitment whose data is the ciphertext. Costs per-deposit rent.
3. **SPL Memo Program, same transaction.** Client builds a transaction with two instructions: verifier `deposit` + SPL Memo carrying the ciphertext. Atomic via tx signature. Verifier not modified.

Earlier I leaned toward option 3 on the grounds that it required no redeploy. That reasoning put *convenience* ahead of *architecture*: the verifier is the canonical product artifact, memo is a first-class protocol feature, and splitting them between our program and someone else's memo program is a costruct-by-accretion pattern that bites anyone reading the code later ("where does memo actually live?" — answer should be one sentence, not three). The correct answer is option 1.

## Decision

**Option 1: memo is a field of the verifier's `deposit` instruction and of `DepositEvent`.**

Concretely:

- `tidex6_verifier::deposit(commitment, memo_payload: Vec<u8>)` — the instruction takes the raw memo bytes alongside the commitment.
- `handle_deposit` validates the payload length against `MEMO_PAYLOAD_MIN_LEN` (60 bytes — the `ephemeral_pk || iv || tag` prefix) and `MEMO_PAYLOAD_MAX_LEN` (60 + 256 bytes of ciphertext). Anything outside those bounds is rejected as `Tidex6VerifierError::InvalidMemoPayloadLength`.
- The program log `tidex6-deposit:<leaf>:<commitment>:<root>:<memo_hex>` now carries the memo as a lowercase-hex fourth field. The old three-field format is still recognised by the offchain indexer so legacy deposits from before this change remain valid history entries.
- `DepositEvent` gains `memo_payload: Vec<u8>` so integrators who subscribe to the event stream receive the memo without re-parsing the log line.
- `tidex6_client::DepositBuilder::with_auditor + .with_memo` now pack the encrypted bytes straight into the anchor instruction. No SPL Memo instruction is emitted.

Shipping this requires a verifier redeploy. Because the upgrade authority is still held (ADR-005 lock happens only after audit), the redeploy reuses the existing program ID `2qEmhLEn…` — no client-side pubkey change required.

## Consequences

**Positive:**

- **Canonical location for memo.** One instruction, one event, one log prefix. A future contributor reading the program source learns what a deposit *is* without chasing a sibling instruction in a third-party program.
- **Event stream is complete.** Subscribers to `DepositEvent` via WebSocket reconnects or historical query APIs get the memo bytes directly — no secondary fetch to reconstruct the SPL Memo instruction by tx signature.
- **Atomicity through identity, not through packaging.** The memo is part of the deposit, not a parallel artifact bundled into the same tx. "Did this deposit come with a memo?" becomes a field access, not a transaction-inspection heuristic.
- **Future in-circuit check is cleaner.** When v0.2 pulls memo validation into a ZK gadget (per ADR-007 v2 roadmap), the circuit inputs map directly onto fields the verifier already stores. No wire-format translation layer.
- **No dependency on `spl-memo` semantics.** The SPL Memo Program is owned by the SPL maintainers and its constraints (~566-char ceiling, UTF-8 enforcement) were shaping our wire format. Now we set our own bounds.

**Negative:**

- **Redeploy cost.** `anchor build` + `solana program deploy --program-id <existing>` must run before clients can send memo-carrying deposits. One-time operation.
- **Instruction data grows.** Deposit instructions now carry up to 316 extra bytes. Transactions remain well under the 1232-byte packet limit; compute-unit cost is effectively unchanged (the verifier copies the bytes into the event, nothing cryptographically expensive).
- **Legacy deposits lack memo.** Deposits recorded before this redeploy emit the three-field log line and have no memo in their (older) events. The indexer handles both formats; legacy deposits simply show up in the accountant ledger as entries without a memo.

## Migration notes

Offchain code paths updated in the same commit as the verifier change:

- `tidex6_client::DepositBuilder` — removed SPL Memo instruction construction; added `memo_payload` field to the anchor arg.
- `tidex6_indexer::PoolIndexer::fetch_deposit_history` — upgraded log parser to recognise the 4-field variant, extract memo hex, and re-emit as base64 for the accountant scanner.
- `tidex6_client::AccountantScanner` — no API change; the `memo_base64` field on `DepositRecord` is now fed from the log trailer rather than a separate instruction.
- All flight harnesses (Day-5, Day-11, Day-12, Day-22, Day-13) — now pass `tidex6_core::memo::placeholder_payload_for_harness()` to satisfy the new length requirement in tests that do not exercise the memo pipeline.

## Related

- **ADR-005** — non-upgradeable verifier. This ADR's redeploy is the *last* planned update before the `solana program set-upgrade-authority --final` lock.
- **ADR-007** — Shielded Memo feature commitment.
- **ADR-004** — Baby Jubjub ECDH primitives the memo encryption is built on.
- `programs/tidex6-verifier/src/pool.rs` — `handle_deposit`, `DepositEvent`, `MEMO_PAYLOAD_MIN_LEN`/`MAX_LEN`.
- `crates/tidex6-core/src/memo.rs` — wire format, KDF, AES-GCM wrapping.
- `crates/tidex6-client/src/deposit.rs` — builder that packs memo into the anchor instruction.
- `crates/tidex6-indexer/src/rebuild.rs` — log parser that decodes memo bytes back out of chain history.
