# ADR-003: Nullifier storage — one PDA per nullifier

**Status:** Accepted
**Date:** 2026-04-09

## Context

A withdrawal must reveal a `nullifier_hash` so the program can prevent the same deposit from being spent twice. The question: how does the program track which nullifiers have already been used?

Three options:

1. **Bloom filter** in a single account.
   - Pros: O(1) check, fixed account size
   - Cons: false positives (a real withdrawal can be incorrectly rejected if its nullifier collides with another), filter degrades as it fills, hard to size correctly without knowing the final number of withdrawals

2. **Vector of nullifiers** in a single growing account.
   - Pros: no false positives
   - Cons: O(n) check, account grows unboundedly, hits Solana account size limits, makes the program a bottleneck

3. **One PDA per used nullifier**, deterministic seeds, empty data.
   - Pros: O(1) check (try-create-PDA), no false positives, no single account growing forever, parallelizable across withdrawals
   - Cons: per-withdrawal storage cost (~0.00089 SOL for rent-exempt PDA)

## Decision

Option 3: one PDA per used nullifier.

```rust
seeds = [b"nullifier", nullifier_hash.as_ref()]
data  = [] // empty (rent-exempt minimum, ~890 bytes)
```

- The withdrawal instruction does `try_create_pda` for the nullifier.
- If creation succeeds → nullifier was unused → withdrawal proceeds.
- If creation fails (account already exists) → nullifier was used → withdrawal rejects with `NullifierAlreadyUsed`.

## Consequences

**Positive:**
- Standard Anchor / Solana pattern. Hard to mess up. Auditable.
- O(1) lookup. No global state to coordinate. Perfectly parallelizable across withdrawals.
- No false positives. A withdrawal cannot be incorrectly rejected because of a hash collision (Poseidon collision resistance).
- Each nullifier is a separate account, so the program does not own a growing data structure that requires migration as the protocol scales.

**Negative:**
- Storage cost ~0.00089 SOL per withdrawal. At MVP scale (hundreds of withdrawals on devnet) this is negligible. At production scale (millions of withdrawals on mainnet) this adds up to thousands of SOL of locked rent. Mitigation: this is an explicit v0.3 design item — investigate compressed-account patterns to reduce per-nullifier rent.
- The accumulated nullifier PDAs grow without bound over the lifetime of the protocol. This is fundamental to the anti-double-spend property and cannot be avoided in any system that wants to permit historical withdrawals.

**Neutral:**
- Rent for nullifier PDAs is paid by the withdrawer (or by the relayer on the withdrawer's behalf, deducted from the withdrawal amount). This is the same model Tornado-style mixers have always used.
- For v0.3 we will revisit nullifier storage and consider compressed accounts or other techniques to reduce per-nullifier cost. The change will be backward compatible: old PDAs continue to work, new ones use the new mechanism.

## Related

- [ADR-001](ADR-001-commitment-scheme.md) — how the nullifier is bound to the commitment
- [ADR-002](ADR-002-merkle-tree-storage.md) — the other half of the deposit-withdraw cryptography
- [PROJECT_BRIEF.md §4.5](../PROJECT_BRIEF.md) — nullifier storage section
