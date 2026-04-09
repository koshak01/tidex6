# ADR-007: Killer features — Shielded Memo (MVP) + Association Sets (v0.2)

**Status:** Accepted
**Date:** 2026-04-09

## Context

The MVP needs at least one feature beyond "another shielded pool" that gives the demo a clear hook for the audience. Two strong candidates surfaced during the review process:

1. **Shielded Memo** — encrypted memo of up to ~200 bytes attached to each deposit. Decryptable only by the holder of the relevant viewing key. Application-layer feature, no impact on the ZK circuit. Estimated implementation: **1–2 days**.

2. **Proof of Innocence (Association Sets)** — additional ZK circuit that proves the user's deposit belongs to a curated subset of approved deposits, without revealing which specific deposit is theirs. Compliance-by-choice without KYC. Estimated implementation: **5–7 days** (new circuit, new trusted setup, offchain Association Set Provider service).

The MVP timeline cannot fit both. Picking just one creates a tradeoff:

- **Memo only** → demo has a working killer feature, but the pitch loses the strongest answer to *"how do you prove your funds are clean?"*
- **Association Sets only** → strong compliance story, but takes the entire MVP buffer and leaves no room for polish.

## Decision

**Implement both, but in different layers.**

- **Shielded Memo: ships in MVP code.** A working, demonstrable feature in the flagship example. Shows up in `examples/private-payroll/` as the encrypted memos Lena sends to her parents and her accountant later decrypts. ECDH on Baby Jubjub + AES-256-GCM. ~1–2 days of work.

- **Proof of Innocence: ships in roadmap and pitch deck, not in code.** Designed in v0.2 architecture, prominently positioned in `ROADMAP.md` and on a dedicated pitch deck slide. The pitch line: *"v0.2 ships the proof-of-innocence layer — users will be able to prove their funds are clean without revealing which deposit is theirs."*

The MVP demo has one working killer feature. The pitch deck has two — one demonstrated in code, one demonstrated in plan.

## Consequences

**Positive:**
- The demo video has a tangible "wow" moment (memo decryption on stage).
- The pitch deck has both an immediate value story (memo) and a strategic vision story (proof of innocence).
- Memo and association sets serve different audiences: memo speaks to *individual* use cases (freelancer + accountant), association sets speak to *institutional* concerns (compliance, regulators).
- Memo is application-layer, so it does not touch the circuit, the trusted setup, or the verifier. It cannot create regressions in the privacy core.

**Negative:**
- The pitch must explain that proof of innocence is "v0.2 designed but not implemented" — this is a softer claim than "shipped today". Mitigation: name the architecture, show the design in the pitch deck, commit to a specific quarter (Q3 2026).
- Two killer features increase the surface area we must explain in three minutes of demo video. Solution: memo gets the demo time, association sets gets one slide and one sentence.

**Neutral:**
- The split mirrors the architecture: memo lives in `tidex6-core::memo`, association sets will live in `tidex6-circuits::association` when it lands. Both are isolated modules, neither blocks the other.
- The decision can be revisited after the MVP. If Q3 2026 turns out to have more headroom than expected, association sets implementation moves up. If less, the timeline holds.

## Related

- [ADR-001](ADR-001-commitment-scheme.md) — memo is stored as a separate field, not inside the commitment
- [ADR-004](ADR-004-elgamal-bn254.md) — memo uses the same Baby Jubjub curve as in-circuit ECDH
- [PROJECT_BRIEF.md §5.2](../PROJECT_BRIEF.md) — Shielded Memo description
- [PROJECT_BRIEF.md §5.3](../PROJECT_BRIEF.md) — Proof of Innocence v0.2 description
- [ROADMAP.md "Next — v0.2"](../ROADMAP.md) — Proof of Innocence as v0.2 deliverable
