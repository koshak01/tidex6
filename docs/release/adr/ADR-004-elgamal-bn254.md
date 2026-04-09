# ADR-004: ElGamal on BN254 — custom dual-curve implementation

**Status:** Accepted
**Date:** 2026-04-09

## Context

Selective disclosure (the auditor tag in `DepositEvent`) requires asymmetric encryption: the depositor encrypts deposit metadata under the auditor's public key, and only the auditor (with their private key) can decrypt by scanning chain events.

The natural primitive is **ElGamal encryption** — additive homomorphic, well-studied, fits the curve we already use for Groth16 (BN254).

The problem: **no production-ready Rust crate exists for ElGamal on BN254.** All major Rust ElGamal implementations target Curve25519 / Ristretto, which is incompatible with our Solana syscalls and our Groth16 circuit field. We have to write our own.

A second consideration: in-circuit operations (where ElGamal randomness or auditor-key derivation needs to be done inside a Groth16 proof) are prohibitively expensive on BN254 G1 directly because BN254 group operations are not native to the BN254 scalar field. The standard fix is to use a **second curve** whose base field equals BN254's scalar field, so its scalar multiplications become cheap field operations inside the circuit. That curve is **Baby Jubjub** (a Twisted Edwards curve), available as `ark-ed-on-bn254`.

## Decision

A dual-curve approach:

- **BN254 G1 (`ark-bn254::G1Projective`)** — used for the onchain ElGamal ciphertext that the auditor decrypts offchain. Standard additive ElGamal: encode message `m` as `m·G`, encrypt as `(r·G, m·G + r·PK_auditor)`. Public key is on G1.

- **Baby Jubjub (`ark-ed-on-bn254`)** — used for in-circuit operations: ECDH key derivation for the encrypted memo, in-circuit auditor key handling, and any future selective-disclosure operations that must be proven inside the Groth16 circuit.

Both curves are wired through `tidex6-core::elgamal` with a clean API. The user of `tidex6-client` does not see the curve choice — they just call `pool.deposit().with_auditor(auditor_pubkey)` and the SDK handles the rest.

The implementation is written from scratch using arkworks primitives (`ark-bn254::G1Projective`, `ark-bn254::Fr`, `ark-ed-on-bn254`).

## Consequences

**Positive:**
- We get cheap in-circuit ECDH and key derivation via Baby Jubjub.
- We get onchain-verifiable ElGamal ciphertexts via BN254 G1.
- The two curves talk to each other through their shared scalar field, which is exactly what BN254's design supports.
- ElGamal lives in the application layer, not in the consensus path. A bug in our ElGamal implementation can leak amounts to the wrong party for users who opted into disclosure — but it cannot compromise the privacy of users who did not opt in, and it cannot enable theft.

**Negative:**
- **The ElGamal code is unaudited.** We are writing cryptographic code from scratch without independent review. Standard risks apply: timing side channels, malleability, edge cases on identity element, encoding mistakes.
- We must explicitly mark this as unaudited in:
  - The `tidex6-core::elgamal` module documentation
  - The `README.md`
  - The `security.md`
  - The pitch deck (under "honest about limitations")
- Mainnet deployment requires either an independent cryptographic audit or a switch to a vetted alternative when one becomes available.
- Two-curve dependency increases the surface area of the code that needs to be understood by reviewers.

**Neutral:**
- Baby Jubjub is the standard companion curve to BN254. Anyone who has worked on Ethereum-ecosystem ZK applications has seen this pattern before. It is not exotic.
- The user of the SDK is unaware of the dual-curve design. The complexity is contained inside `tidex6-core::elgamal`.

## Related

- [ADR-001](ADR-001-commitment-scheme.md) — auditor tag is stored separately from the commitment
- [ADR-007](ADR-007-killer-features.md) — Shielded Memo also uses Baby Jubjub for ECDH
- [PROJECT_BRIEF.md §5.1](../PROJECT_BRIEF.md) — selective disclosure description
- [security.md](../security.md) — unaudited cryptography disclaimer
