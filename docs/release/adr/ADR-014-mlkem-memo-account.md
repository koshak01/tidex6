# ADR-014 — Post-quantum memo in a dedicated account, new verifier

**Status:** Accepted — deployed to mainnet 2026-06-30 as
`Gt1duB4bPj2CmW9y7eiGzekeCfiR1UckjiyPGSbyWRVU` (reproducible build via
`solanafoundation/solana-verifiable-build:4.0.3`; first deploy `6VUBZ…`
was closed/retired and re-done reproducibly per Petr; OtterSec
verification + `--final` after deploy).
**Date:** 2026-06-30
**Supersedes (for new pool):** ADR-012 envelope transport via `DepositEvent.memo_payload`

## Context

The user has chosen to move **all encryption to ML-KEM-768** (post-quantum),
without backward compatibility — see roadmap A6/A8/A9 and
`tidex6-core::pqc` (already shipped: `keygen`/`seal`/`open`).

The blocker is size. An ML-KEM-768 envelope is:

```
kem_ciphertext (1088) + nonce (12) + aead_ciphertext (variable) ≈ 1.2 KB
```

and it is **incompressible** (encrypted bytes are noise). The Solana
transaction hard limit is **1232 bytes**. Today memo travels inside
`DepositEvent.memo_payload` (an event log field, bounded by
`MEMO_PAYLOAD_MIN/MAX_LEN`), which cannot carry ~1.2 KB alongside the
rest of a deposit transaction.

The current verifier `2qEm…cU9C` is **immutable forever** (ADR-005,
upgrade-authority renounced). Its `deposit` instruction and its
`MEMO_PAYLOAD_*` bounds cannot be changed. Therefore ML-KEM memo
on-chain requires a **new program**.

Crucial observation: **memo lives outside the circuit.** The verifier
stores `memo_payload` verbatim and never parses or proves anything about
it; the accountant scanner decrypts it off-chain. So moving memo to
ML-KEM does **not** change `WithdrawCircuit<20>` — the proving/verifying
key is identical. **No new trusted-setup ceremony is needed for this
change.** A ceremony is only required when the circuit itself changes
(confidential amounts / revoke — a separate later verifier).

## Decision

Deploy a **new verifier program** (new program id) that keeps the exact
`WithdrawCircuit<20>` VK of `2qEm…cU9C` but changes the **deposit** path
so the ML-KEM envelope lands in a **dedicated account**, not the event.

### Memo account

- One PDA per deposit: seeds `[b"memo", commitment]` (commitment is the
  unique 32-byte leaf already produced by the deposit).
- Account data = the raw ML-KEM envelope bytes (one or more reader
  slots, see below). Up to Solana's 10 MB account ceiling — ~1.2 KB per
  reader is comfortable.
- Written in **chunks** across 2+ instructions because a single tx
  cannot carry the whole envelope: `deposit` creates the account and
  writes chunk 0, follow-up `append_memo` instructions write the rest.
  An `is_finalized` flag closes the account to further writes.

### Reader slots — ML-KEM for everyone, by capability

The envelope is a small multi-slot container. Each slot is an
independent `pqc::seal` under one reader's ML-KEM-768 public key, and
**what is sealed differs by the reader's capability**:

- **recipient / stealth** (A9) — payload = `secret ‖ nullifier ‖ memo`.
  Carries the note's spend material so the recipient can scan the chain,
  decrypt their own slot, reconstruct the note and `withdraw` — **the
  note is never handed over** (Signal/file). This is the stealth model.
- **auditor / regulator** (A8/A5) — payload = `denomination ‖ memo`.
  Deliberately **omits `secret`/`nullifier`** so an auditor sees *what*
  (amount + memo) but **cannot spend** the deposit. One slot per auditor;
  multiple auditors/regulators each get their own.

Container wire format (off-chain shape, stored verbatim in the memo
account): `version(1) ‖ slot_count(1) ‖ [ kind(1) ‖ len(2 BE) ‖ pqc_envelope(len) ]*`,
`kind` = 0 recipient / 1 auditor.

**No view tag.** With ECDH a 1-byte view tag let a scanner skip foreign
slots without a full key exchange. ML-KEM has no such shortcut — to learn
the shared secret a reader must run a full `decapsulate` regardless — so a
view tag would save nothing. The scanner simply `decapsulate`s each slot
of its kind and lets the **AEAD authentication tag** be the "addressed to
me" filter (decrypt error = not mine), exactly the constant-time
"filter for free" trick the v1 memo already used. Nothing extra is
written on chain, so nothing extra can leak.

### Scanning (no note handoff)

Auditor and recipient both scan via `getProgramAccounts` filtered to the
memo-account discriminator, match their **view tag**, then `pqc::open`
with their secret key. The recipient recovers the note secret this way —
**no note is handed over Signal/file** (roadmap A9). Both readers are
autonomous.

### Per-deposit revoke (refund) — no ceremony

`deposit` records the **depositor pubkey**, a **unix timestamp**, and a
**per-deposit `revoke_window`** (seconds) in the memo account. The
depositor chooses the window at deposit time — not the protocol. A value
of `0` makes the deposit **irrevocable** (refund permanently disabled,
for when the depositor fully trusts the recipient).

A new `refund` instruction lets the depositor reclaim the deposit if:

1. They present `(secret, nullifier)` such that
   `Poseidon(secret, nullifier) == commitment` **and**
   `Poseidon(nullifier) == nullifier_hash` — proving ownership of *this*
   note via the onchain Poseidon syscall (the exact hash the circuit
   uses). The second check ties the blocked PDA to this note so a
   depositor cannot block someone else's.
2. `revoke_window > 0` and `now - created_ts >= revoke_window`.
3. The note's nullifier PDA does not yet exist — it is created here via
   `init`, so the note becomes **permanently spent** and can never be
   withdrawn after a refund.

No ZK proof, no circuit change, **no ceremony**. Solves "I lost the
note" / "the recipient never claimed": the sender gets their money back
on their own schedule.

### What does NOT change

- `WithdrawCircuit<20>`, its VK, the Groth16 verify path → **reused as-is**.
- Merkle tree mechanics (depth 20, root ring 30), nullifier PDAs,
  relayer fee-in-circuit (ADR-011) → **reused as-is**.
- No ceremony for this verifier.

## Consequences

- **New program id.** The current pool `2qEm…cU9C` stays as-is; the new
  pool is a separate program. **No note migration** (Petr: "everything
  that was, is past") — the old pool lives out its existing notes, the
  new pool starts from a clean slate. Redeploying a fresh program as many
  times as needed is explicitly fine.
- **Per-deposit rent.** Each memo account is rent-exempt (~1.2 KB ≈ small
  SOL). Paid by the depositor (or relayer). Document in security.md.
- **Multi-tx deposit.** Deposit becomes create + chunked append. The
  client/SDK orchestrates; the WASM/browser flow must handle the extra
  instructions.
- **Off-chain scan cost.** `getProgramAccounts` over all memo accounts;
  view tags keep per-account work O(1). Acceptable at MVP volumes;
  revisit with an indexer at scale.
- **ADR-012 envelope** (BJJ ECDH + AES, event-transport) is retired for
  the new pool. The old verifier keeps it for already-deposited notes.
- **OtterSec verify + renounce decision** repeats for the new program
  (ADR-005 applies again).

## Scope boundary

This verifier delivers **ML-KEM memo transport + stealth + 30-day
revoke**. All three avoid the circuit, so **no ceremony**. Confidential
amounts (Token-2022 CT) are deliberately **out of scope** — they change
the circuit and need a ceremony; they get their own later verifier
cycle. One new verifier, a tight set of goals that ship without a setup.

## Related

- ADR-005 — verifier immutable after deploy (why a new program is needed).
- ADR-011 — relayer fee-in-circuit (reused unchanged).
- ADR-012 — envelope memo via event (superseded for the new pool).
- `tidex6-core::pqc` — ML-KEM-768 + ChaCha20 primitive (the seal/open used here).
- Roadmap A4 (view tags), A6 (ML-KEM envelope), A8 (auditor on-chain),
  A9 (stealth — note not needed).
