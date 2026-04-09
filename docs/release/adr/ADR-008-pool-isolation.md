# ADR-008: Per-program pool in MVP, shared pool in v0.3

**Status:** Accepted
**Date:** 2026-04-09

## Context

A privacy framework on Solana faces a fundamental architectural choice: how do integrator programs share (or not share) the underlying anonymity set?

Two options:

1. **Per-program pool.** Each integrator deploys a separate pool. Their users' deposits sit in their own Merkle tree, separate from every other integrator's tree. Anonymity set per pool = number of deposits in that one pool.
   - Pros: trivial to implement, no cross-program coordination, no shared state, isolated failure modes
   - Cons: anonymity set fragments across applications. A new application starts with anonymity set ≈ 1.

2. **Shared anonymity pool.** All integrators contribute deposits to one common Merkle tree. Anonymity set = total deposits across the entire ecosystem.
   - Pros: anonymity set scales linearly with adoption — every new application strengthens privacy for every existing user. Network effect
   - Cons: complex multi-program coordination — who owns the PDA, how concurrent deposits sequence, how fees are accounted across integrators, how the protocol handles versioning if one integrator wants to upgrade and another does not. Several days of architectural design work alone.

The MVP timeline cannot absorb the shared-pool complexity. But shipping per-program-only without acknowledging the anonymity-set fragmentation problem would be a strategic error — judges will ask the question, and "we didn't think about it" is the wrong answer.

## Decision

**Per-program pool in MVP. Shared anonymity pool designed as v0.3 architectural target.** The fragmentation problem is acknowledged explicitly and converted into a roadmap item with a specific framing: *network effect for privacy.*

The v0.3 design notes (preserved in ROADMAP.md):
- One singleton `tidex6-shared-pool` program
- Per-integrator deposit authority (CPI from integrator → shared pool)
- Unified nullifier set
- Append-only roots, indexer linearizes deposits
- Migration path: existing per-program pools continue to work; new integrators choose isolated or shared at deploy time; eventually shared becomes default

## Consequences

**Positive:**
- The MVP ships in time. Per-program pool is a textbook implementation pattern with no exotic complexity.
- The v0.3 framing is prepared in advance: *"the more apps integrate tidex6, the stronger privacy becomes for all users. Network effect meets privacy."* This converts the fragmentation weakness into a forward-looking strength in the pitch.
- Each integrator's pool is independent: a bug in one pool cannot affect another, a load spike in one cannot starve another, a versioning decision in one does not propagate.
- We have a prepared answer for the inevitable judge question *"but anonymity set = 5 on day one is not real privacy"* — see judge Q&A section in the demo prep notes.

**Negative:**
- Day-one anonymity in any one pool is small. A new pool with 5–50 deposits is weakly anonymous in absolute terms. The flagship example (private-payroll) deliberately shows this honestly: Lena's pool is what it is, and the demo speaks frankly about what that means and what v0.3 will fix.
- Two integrators on tidex6 cannot share an anonymity set in MVP. They sit in disjoint trees. There is no MVP workaround.
- The v0.3 architecture is non-trivial and we are committing to it without having implemented it. Risk: when we sit down to build the shared pool, some constraint we did not foresee makes it harder than expected. Mitigation: the v0.3 design will go through its own ADR before implementation.

**Neutral:**
- Per-program pool is the same model used by several production privacy applications. It works in practice, even if it has the fragmentation drawback.
- The shared-pool design is intentionally modular: it can be developed in a separate repo, tested independently, and shipped as a new program. It does not require breaking changes to per-program pools.

## Related

- [ADR-002](ADR-002-merkle-tree-storage.md) — Merkle tree storage applies to both per-program and shared models
- [ADR-005](ADR-005-non-upgradeable-verifier.md) — the verifier is shared across all pools regardless of model
- [ROADMAP.md "Later — v0.3+"](../ROADMAP.md) — shared anonymity pool listed as v0.3 deliverable
- [PROJECT_BRIEF.md §11](../PROJECT_BRIEF.md) — anonymity-set day-one warning in security posture
