# ADR-009: Proving time budget — Day-8 benchmark, 30s acceptance

**Status:** Accepted
**Date:** 2026-04-09

## Context

The cost of verifying a Groth16 proof on Solana is well-understood: under 200K compute units, deterministic, predictable. The cost of *generating* a Groth16 proof off-chain is rarely benchmarked early in a project — and that omission has bitten more than one ZK project at demo time.

For tidex6, the withdrawal circuit involves:
- Merkle inclusion proof for depth 20 (~20 hash operations inside the circuit)
- Nullifier derivation
- Poseidon hashing of multiple field elements
- All compiled to R1CS constraints

Rough estimates for arkworks Groth16 proving time:

| Circuit complexity | Constraints | Mid-range laptop |
|---|---|---|
| Toy circuit (single Poseidon) | ~5K | 1–2 sec |
| Tornado-style withdraw | ~30K | 8–15 sec |
| Withdraw + auditor proof | ~50K | 15–30 sec |
| Full withdraw, depth-20 Merkle, all features | ~100K | 30–60 sec |

A 30–60 second wait during a live demo is a UX disaster. The judge stares at a "Generating proof..." line and either loses interest or assumes the program has frozen. This needs to be measured early and budgeted explicitly.

## Decision

**Day-8 of the MVP timeline is a mandatory proving-time benchmark.** As soon as the first end-to-end withdrawal circuit compiles and produces a valid proof, run:

```bash
time cargo run --release --example prove_withdrawal
```

Acceptance threshold: **proof generation ≤ 30 seconds** on a target reference machine (M1 Mac or equivalent).

If the threshold is exceeded:

| Measured time | Action |
|---|---|
| 30–45 sec | Enable parallel features in arkworks (`rayon`). Re-benchmark. |
| 45–60 sec | Reduce Merkle depth from 20 to 16 (capacity drops to ~65K leaves, still fine for MVP). Re-benchmark. |
| > 60 sec | Reduce Merkle depth to 12 (~4K leaves, sufficient for demo only). Document the reduction in security.md. Plan to optimize for v0.2. |

The demo video must include an explicit progress indicator during proof generation (`[Generating zero-knowledge proof — ~15s on a laptop]`). This converts an awkward pause into a *demonstration of computational work* and educates the audience about ZK proving cost.

The pitch deck includes a benchmark slide with measured numbers:

```
Proof generation:  ~15 seconds (M1 laptop)
Verification:      <200K compute units (~$0.0001)
Privacy:           Complete — sender, receiver, amount hidden
Compliance:        Optional — user-controlled viewing keys
```

## Consequences

**Positive:**
- The proving-time problem is caught on day 8, not on day 30 (demo prep day).
- Concrete numbers in the pitch deck — judges trust measured benchmarks more than handwaved estimates.
- Merkle depth becomes an explicit, tunable parameter rather than a hidden constant. Future versions can revisit it.
- The demo video sets correct expectations — "this takes 15 seconds because it is real cryptography, not fake animation".

**Negative:**
- Reducing Merkle depth reduces anonymity-set capacity. This is a real privacy cost. Mitigation: document the tradeoff explicitly in `security.md`, and treat depth 20 as the v0.2 target if MVP must ship at depth 16 or lower.
- The Day-8 benchmark requires the circuit to be working end-to-end by then. This pulls the integration deadline forward and creates schedule pressure on the early phase.

**Neutral:**
- The 30-second threshold is arbitrary but defensible: it is the longest pause a live demo can absorb without losing the room.
- Proving time is a function of the prover's hardware. We benchmark on a reference machine to set the public number, but real users on slower hardware will see longer times. The pitch deck and documentation should make this explicit.

## Related

- [ADR-002](ADR-002-merkle-tree-storage.md) — Merkle depth choice
- [ADR-005](ADR-005-non-upgradeable-verifier.md) — bugs caught at Day-8 are bugs that do not ship in the immutable verifier
- [PROJECT_BRIEF.md §11](../PROJECT_BRIEF.md) — security posture references this benchmark
- [security.md](../security.md) — anonymity-set warnings tied to Merkle depth choice
