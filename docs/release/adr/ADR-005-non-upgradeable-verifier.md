# ADR-005: Verifier program is non-upgradeable after deploy

**Status:** Accepted
**Date:** 2026-04-09

## Context

Anchor programs are upgradeable by default. The deployer holds an upgrade authority key and can deploy new versions of the program at the same program ID. This is convenient for development but creates two problems for a privacy protocol:

1. **Trust:** users have to trust that the upgrade authority will never deploy a malicious version of the verifier (one that, for example, accepts forged proofs and lets the upgrade authority drain the pool).

2. **Legal exposure:** in the United States, the November 2024 Fifth Circuit decision in *Van Loon v. Department of Treasury* established that **immutable onchain code cannot be sanctioned as property under IEEPA** because it cannot be owned, controlled, or excluded from use by anyone. Crucially, this protection does **not** apply to mutable onchain code — the Treasury explicitly argued that upgradeable programs remain sanctionable, and the court did not contradict this.

For a privacy protocol whose value proposition includes resistance to weaponization by authorities, immutability is not optional.

Solana provides a one-way operation: `solana program set-upgrade-authority <PROGRAM_ID> --final` permanently revokes the upgrade authority. After this, no one can deploy a new version of the program at that ID, ever. The bytecode is frozen.

## Decision

`tidex6-verifier` is locked with `solana program set-upgrade-authority --final` immediately after the initial deployment. The verifier becomes permanently immutable.

This applies to:
- The devnet deployment of the verifier (after MVP testing)
- The mainnet deployment of the verifier (when MVP is audit-ready)

It does **not** apply to:
- Integrator programs (those are owned by their respective developers)
- The reference indexer / relayer (those are offchain code, not onchain programs)
- The SDK crates (those are libraries, distributed via crates.io, versioned normally)

## Consequences

**Positive:**
- Cryptographic immutability: no one can replace the verifier with a malicious version.
- Legal protection under the *Van Loon* precedent (US Fifth Circuit jurisdiction). The verifier is property no one owns and no one can exclude from use.
- Strong message to integrators: the foundation they build on cannot be pulled out from under them.
- Trust minimisation: users do not have to trust the deployer to behave honestly forever.

**Negative:**
- **Bug fixes require deploying a new verifier program** at a new program ID. Old integrator programs that hardcode the old verifier ID will not automatically benefit from the fix.
- Pool versioning becomes a v0.2 design item: PoolV1 (using verifier-v1) and PoolV2 (using verifier-v2) coexist, and there must be a sweep mechanism for users to migrate funds from V1 to V2.
- All bugs must be caught **before** deployment. This raises the bar for the Day-1 Validation Checklist, the Fiat-Shamir discipline, and the trusted setup ceremony — see ADR-009 and the security model.
- The pre-mainnet audit becomes mandatory and load-bearing. There is no "ship and patch" option.

**Neutral:**
- The integrator's own program remains upgradeable (or not) at the integrator's discretion. tidex6 only mandates immutability for the shared verifier.
- The non-upgradeable verifier is a singleton on each network. All integrator programs CPI into the same verifier.

## Related

- [ADR-006](ADR-006-no-proc-macros.md) — the SDK is mutable, the verifier is not
- [ADR-009](ADR-009-proving-time-budget.md) — Day-8 validation gates that protect the immutable verifier from shipping with bugs
- [PROJECT_BRIEF.md §12](../PROJECT_BRIEF.md) — legal posture
- [security.md](../security.md) — security model and pre-deployment checklist
