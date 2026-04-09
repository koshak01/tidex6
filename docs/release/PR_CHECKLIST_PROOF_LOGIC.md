# PR Checklist: Proof Logic Changes

> **When to use:** any pull request that touches proof logic, circuit definitions, transcript construction, or cryptographic primitives.
>
> **Why:** a single omitted value in a Fiat-Shamir transcript has been enough to forge arbitrary zero-knowledge proofs in production systems on Solana as recently as 2025. This checklist exists to catch that class of mistake before it ships.
>
> **Enforcement:** every PR that matches the scope above goes through this checklist. The author completes it in the PR description. One additional reviewer signs off on the transcript construction before merge.

---

## Rule 0

> **Anything the prover touches goes into the transcript.**

If the verifier uses a value, the transcript must bind it. If the prover computes a value that influences the proof, the transcript must absorb it **before** the challenge is derived.

This one rule catches the majority of real-world Fiat-Shamir bugs. Every item below is a specific instance of Rule 0 applied to a particular failure mode.

---

## Section 1 — CRITICAL (blocks merge)

These items block merge unconditionally. If any of them cannot be checked off truthfully, the PR is not ready.

- [ ] **Rule 0 enforcement.** Every value computed by the prover — including commitments, intermediate values, and sub-challenges in OR proofs — is absorbed into the transcript **before** the corresponding challenge is derived. No exceptions. If there is any sub-challenge anywhere in the protocol that the prover generates, it is in the transcript.

- [ ] **All public inputs absorbed.** Every public input to the verifier (nullifier hash, Merkle root, recipient address, denomination, any auditor public keys, any domain flags) is included in the transcript. Omitting a public input allows proof reuse across different statements.

- [ ] **All commitments absorbed, including intermediate ones.** In multi-round protocols or composed proofs, each commitment at each round is absorbed in the order it is produced. Special attention to sigma OR proofs and composed protocols — this is exactly where the 2025 Phantom Challenge bug lived.

- [ ] **All group elements used in the proof absorbed.** G1 and G2 points, ElGamal ciphertexts, Pedersen commitments — anything that is part of the statement being proven. An unabsorbed group element is an attack surface.

- [ ] **Domain separator present.** The transcript starts with a unique domain separator string in the format `"tidex6-v1-{circuit_name}"`. This prevents cross-protocol proof replay, where a proof valid for one circuit is accepted by another with a similar-shaped transcript.

- [ ] **No prover-controlled value used after challenge derivation without re-absorption.** If the prover computes a response after the challenge is derived, that response must not become an input to *another* challenge without being explicitly absorbed into the transcript first. This is subtle and has historically caused bugs in protocols that compose multiple challenges.

---

## Section 2 — HIGH (blocks merge without explicit justification)

These items block merge unless the author provides a written justification in the PR description explaining why the item does not apply or is handled elsewhere.

- [ ] **Transcript order matches the specification.** The order in which values are absorbed matters — different orders produce different challenges, which produce different proofs. The order is documented in code comments and matches the spec in the relevant ADR or the PROJECT_BRIEF.

- [ ] **No transcript reuse across independent proofs.** If the PR generates multiple proofs in the same transaction, each proof begins with a fresh transcript (or a clearly documented fork of a base transcript with a unique suffix).

- [ ] **Field element encoding is canonical.** Field elements (`Fr`) are absorbed in canonical form. If the code uses a non-default serialization (Montgomery form, little-endian vs big-endian), the choice is documented in a comment and is consistent across all transcript operations in the PR.

- [ ] **Curve point compression is consistent.** When absorbing G1 points into the transcript, the code uses either compressed or uncompressed encoding consistently. Mixing compressed and uncompressed produces different transcripts for mathematically identical proofs and is an immediate verification failure.

- [ ] **Public inputs to Groth16 are serialized consistently off-chain and on-chain.** The off-chain prover and the on-chain verifier must serialize public inputs in byte-for-byte the same format. A single off-by-one or a serialization convention difference silently rejects every proof.

---

## Section 3 — MEDIUM (requires review comment)

These items require a review comment from the author acknowledging that the situation has been considered, even if nothing changed.

- [ ] **Circuit constraint count is stable or the change is documented.** If the constraint count changed since the last PR on the circuit, the author notes the delta and the reason. Unexpected drops in constraint count may indicate that a security-critical check was accidentally removed.

- [ ] **No redundant constraints were removed as "optimization".** Removing "unused" constraints from a ZK circuit is one of the classic ways to silently break soundness. If any constraint was removed, the PR description explains why it was safe.

- [ ] **Witness generation code matches the circuit definition.** The off-chain code that computes witness values must apply the same operations that the circuit expects. A divergence produces a valid-looking proof that proves the wrong statement — and that proof will verify successfully, leading to silent vulnerability. The author has manually traced the witness generation path against the circuit constraints.

- [ ] **New proof types have at least one negative test.** For any new proof type or any modification to an existing proof type, there is at least one test that constructs a deliberately tampered input and verifies that the proof is rejected.

---

## Section 4 — META (merge hygiene)

- [ ] **Two reviewers have signed off on the transcript construction.** The author plus one independent reviewer. No single-approval merges on proof-critical code.

- [ ] **Regression test: honest proof verifies.** A test that constructs a valid proof and confirms the verifier accepts it. Trivial, but protects against accidental breakage.

- [ ] **Regression test: tampered public input rejects.** A test that constructs a proof and then changes one public input byte, confirming the verifier rejects it. This catches silent changes to what the proof is actually proving.

- [ ] **Regression test: reused nullifier rejects.** A test that attempts to withdraw with an already-used nullifier, confirming the double-spend check fires.

- [ ] **Documentation updated.** If the PR changes the transcript construction, the relevant ADR is updated. If the PR introduces a new circuit, a new ADR is written.

- [ ] **No unused cryptographic imports.** Dead cryptographic code is a red flag — it suggests something was partially removed and something else left dangling. The PR has no `use` statements or dependencies that are no longer referenced.

---

## Historical context

This checklist exists because Fiat-Shamir mistakes have bitten production zero-knowledge systems on Solana within the last year. In April 2025, a ZK ElGamal proof program on Solana had missing algebraic components in its Fiat-Shamir transcript. The bug was patched within 48 hours. In June 2025, the same program suffered a second, more severe bug: the "Phantom Challenge" — a prover-generated sub-challenge in a sigma OR proof for fee validation was not absorbed into the Fiat-Shamir transcript, allowing arbitrary proof forgery. This enabled unlimited token minting. The affected program was disabled on Solana mainnet at epoch 805.

Both incidents are the same class of bug: **a value the prover controls was not in the transcript**. Rule 0 above exists to catch this class of bug. The rest of the checklist is Rule 0 expanded into specific instances.

We document this historical context not to criticize anyone — the mistakes were made by competent engineers in a production system that had been reviewed. We document it so that our own future engineers understand that this category of failure is real, has happened recently, and can happen to us if we are not deliberate.

---

*tidex6.rs — I grant access, not permission.*
*See also: [security.md](security.md) section 2.1 for the vulnerability class description.*
