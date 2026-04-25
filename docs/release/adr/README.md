# Architecture Decision Records

> Each file in this directory captures one architectural decision: the question being asked, the answer chosen, and the consequences of choosing it.
>
> ADRs are written **before** the code that implements them, so future contributors (and our future selves) can read why the code looks the way it does without spelunking through commit history.

## Index

| # | Title | Status |
|---|---|---|
| [ADR-001](ADR-001-commitment-scheme.md) | Commitment scheme: `Poseidon(secret, nullifier)` only | Accepted |
| [ADR-002](ADR-002-merkle-tree-storage.md) | Merkle tree offchain, root ring buffer onchain | Accepted |
| [ADR-003](ADR-003-nullifier-storage.md) | Nullifier storage: one PDA per nullifier | Accepted |
| [ADR-004](ADR-004-elgamal-bn254.md) | ElGamal on BN254 — custom dual-curve implementation | Accepted |
| [ADR-005](ADR-005-non-upgradeable-verifier.md) | Verifier program is non-upgradeable after deploy | Accepted |
| [ADR-006](ADR-006-no-proc-macros.md) | No proc macros in MVP — builder pattern instead | Accepted |
| [ADR-007](ADR-007-killer-features.md) | Killer features: Shielded Memo (MVP) + Association Sets (v0.2) | Accepted — Memo shipped |
| [ADR-008](ADR-008-pool-isolation.md) | Per-program pool in MVP, shared pool in v0.3 | Accepted |
| [ADR-009](ADR-009-proving-time-budget.md) | Proving time budget: Day-8 benchmark, 30s acceptance | Accepted |
| [ADR-010](ADR-010-memo-transport-via-spl-memo.md) | Memo transport via SPL Memo Program (not verifier redeploy) | Superseded by ADR-012 |
| [ADR-011](ADR-011-relayer-architecture.md) | Relayer architecture — fee-in-circuit with reference service | Accepted |
| [ADR-012](ADR-012-opaque-note-envelope-memo.md) | Opaque note format and envelope-encrypted memo | Accepted |

## Format

Each ADR follows the same structure:

- **Status** — Accepted / Superseded / Deprecated
- **Date** — when the decision was made
- **Context** — what question is being asked, why now, what alternatives exist
- **Decision** — what was chosen
- **Consequences** — positive, negative, neutral
- **Related** — cross-references to other ADRs and documents

## When to write a new ADR

- A non-trivial architectural choice is being made
- The decision will be hard to reverse later
- Future contributors will ask "why is this done this way?"
- A choice that looks obvious now might look wrong in six months without context

## When NOT to write an ADR

- Implementation details that can be changed without architectural impact
- Naming conventions and style decisions (use the style guide)
- Library version pins (use Cargo.toml comments)
- Bug fixes (use commit messages)
