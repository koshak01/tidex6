# ADR-002: Merkle tree offchain, root ring buffer onchain

**Status:** Accepted
**Date:** 2026-04-09

## Context

A shielded pool needs a Merkle tree of commitments. The withdrawer proves inclusion in the tree as part of their ZK proof. The question: where does the tree live?

Three options:

1. **Full tree onchain.** Every node stored as account data. Updates done in-program.
   - Pros: trustless, no external dependency
   - Cons: extremely expensive (CU and rent), concurrent deposits race, depth limited by compute budget

2. **Full tree offchain, no onchain anchor.** Indexer is the source of truth.
   - Pros: cheap, fast updates
   - Cons: trust required (indexer can lie about the tree state)

3. **Hybrid: tree offchain, recent roots onchain.** Indexer maintains the full tree; the program stores a ring buffer of recent roots and a counter for the next leaf index. Withdrawals reference any recent root.
   - Pros: cheap onchain footprint, trustless verification (proofs are checked against onchain roots), no race conditions
   - Cons: requires an indexer to compute Merkle proofs

## Decision

Hybrid: option 3.

- **Offchain (indexer):** the full Merkle tree of depth 20 (~1M leaves), rebuilt from `DepositEvent` logs by any indexer node.
- **Onchain (program state):** ring buffer of the last **30 roots** + a `next_leaf_index` counter. That is the entire onchain Merkle state.
- **Deposit flow:** the program sees the new commitment, increments `next_leaf_index`, computes the new root via the onchain Poseidon syscall (or accepts a client-computed root validated by recomputation), pushes the new root onto the ring buffer.
- **Withdraw flow:** the proof references one of the 30 roots in the buffer. The program checks the proof against that root.

## Consequences

**Positive:**
- Onchain footprint is constant: 30 × 32 bytes for roots + 8 bytes for counter ≈ 968 bytes total. Trivial.
- No race conditions on concurrent deposits — the program is the linearizer (it owns `next_leaf_index`).
- Withdrawals can use any of the 30 most recent roots, giving clients ~minutes to generate a proof without worrying about tree state changing under them.
- Withdrawal proofs are still trustless: even if the indexer lies, the proof must verify against an onchain root, which can only have come from a real `DepositEvent`.

**Negative:**
- The indexer is critical infrastructure. Without an indexer, a withdrawer cannot construct a Merkle proof and cannot withdraw. Mitigation: the indexer is reference code (`tidex6-indexer`), runs anywhere, and the protocol publishes deterministic instructions for rebuilding the tree from onchain events. Anyone can run their own.
- A client must wait for the indexer to catch up to the latest `DepositEvent` before generating a proof against the latest root. In practice this is sub-second.
- The 30-root window means a client whose proof generation takes longer than ~30 deposits in the pool will see their proof go stale and need to regenerate against a newer root.

**Neutral:**
- Tree depth 20 → ~1M leaves capacity. For MVP demo and well into v0.2, this is comfortable.
- `next_leaf_index` advances monotonically; the protocol does not support deletion of leaves (Merkle tree is append-only).

## Related

- [ADR-001](ADR-001-commitment-scheme.md) — what is stored in each leaf
- [ADR-003](ADR-003-nullifier-storage.md) — the other half of the anti-double-spend story
- [PROJECT_BRIEF.md §4.4](../PROJECT_BRIEF.md) — Merkle tree section
