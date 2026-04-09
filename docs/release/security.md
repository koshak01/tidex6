# Security Model

> **Purpose:** Threat model, known limitations, vulnerability classes we guard against, and the engineering process that catches the mistakes humans make when writing zero-knowledge code.
>
> **Audience:** security researchers, auditors, grant reviewers, integrators evaluating tidex6 for production use.
>
> *tidex6.rs — I grant access, not permission.*

---

## Scope of this document

This document covers the **MVP** security posture. Items marked `v0.2` or later reference the [ROADMAP.md](ROADMAP.md).

It does **not** cover:

- Security of integrator programs built on top of tidex6 (each integrator is responsible for their own program's security).
- Security of the runtime environment (operating system, wallet, browser, network).
- Physical security of user devices where keys are stored.

It **does** cover:

- The cryptographic primitives we use and their known limitations.
- The unaudited code paths and how we isolate them.
- The trusted setup posture for MVP vs later.
- The engineering process that catches the mistakes humans make when writing ZK code.
- The vulnerability classes that have bitten similar systems and how we defend against them.

---

## 1. Known cryptographic limitations

### 1.1 BN254 — approximately 100-bit security

The BN254 pairing-friendly elliptic curve was originally estimated at 128 bits of security. Subsequent advances in the Number Field Sieve for discrete logarithms on low-embedding-degree pairing curves (the Kim–Barbulescu line of improvements published in 2015 and refined since) revised this estimate downward to approximately **100 bits** of security.

**Why we still use BN254:**
- It is the only elliptic curve with native Solana syscall support (`alt_bn128`).
- Groth16 proof verification on BN254 costs under 200,000 compute units through the `groth16-solana` crate.
- Alternatives (BLS12-381, BLS12-377) have higher security but no Solana syscalls, which would push verification cost by orders of magnitude and make onchain verification impractical.
- BN254 remains the standard for the broader Ethereum-ecosystem ZK applications, which means our stack benefits from shared tooling and shared scrutiny.

**What users should understand:**
- For short-term privacy (days, weeks, months), ~100-bit security is more than sufficient.
- For long-term confidentiality (10+ years), users should be aware that advances in NFS may further weaken BN254. Deposits made today may or may not be computationally opaque in 2040.
- Migration to a stronger curve (e.g., BLS12-381) is tracked as a roadmap item and will become feasible if and when Solana adds the corresponding syscalls.

### 1.2 arkworks "academic prototype" disclaimer

The `arkworks-rs` ecosystem — which provides our Groth16 implementation, R1CS constraint synthesis, finite field arithmetic, and curve operations — carries an explicit disclaimer from its maintainers:

> *"This repository contains an academic proof-of-concept prototype. NOT ready for production use."*

Despite this disclaimer, `arkworks` is the de facto standard Rust ZK stack. Production systems across the ecosystem (Light Protocol, sp1-solana, multiple L2s) depend on it. The 15.5M+ cumulative downloads on `ark-ec` alone reflect this.

**Our posture:**
- We pin exact minor versions where compatibility is critical.
- We monitor arkworks security advisories and apply upstream fixes promptly.
- We do not modify arkworks source; we use it as-is.
- We acknowledge the disclaimer publicly here instead of pretending it does not exist.

### 1.3 Custom unaudited ElGamal on BN254

No production-ready Rust crate exists for ElGamal encryption on BN254. All major Rust ElGamal crates target Curve25519 or Ristretto, which are incompatible with our Groth16 circuit field and our Solana syscalls. We are writing our own ElGamal from scratch using arkworks primitives.

**Risks:**
- Cryptographic code written without independent review is inherently risky. Possible classes of bugs include timing side channels, malleability, edge cases on the identity element, and encoding mistakes.

**Mitigations:**
- The ElGamal implementation lives in `tidex6-core::elgamal` and is isolated from the consensus path. The privacy layer (Merkle tree, nullifiers, Groth16 verification) uses standard well-understood primitives. A bug in our ElGamal code can leak deposit metadata to the wrong party for users who opted into disclosure — but it cannot compromise the privacy of users who did not opt in, and it cannot enable theft.
- The code is marked `unaudited` in the module documentation, in the README, and in this document.
- Independent cryptographic audit is a precondition for mainnet deployment.
- See [ADR-004](adr/ADR-004-elgamal-bn254.md) for the full rationale and the dual-curve design (BN254 G1 for onchain ElGamal, Baby Jubjub for in-circuit operations).

### 1.4 Local Phase 2 trusted setup — DEVELOPMENT ONLY

The Groth16 proving system requires a trusted setup ceremony to generate proving and verifying keys for each specific circuit. If an adversary learns the "toxic waste" secret numbers used during the ceremony, they can forge arbitrary proofs and drain the pool.

**MVP posture:**
- Phase 1 (the universal, circuit-independent half) is reused from an existing public ceremony. No new work required.
- Phase 2 (circuit-specific) is run **locally by the developer** as a single-contributor ceremony. This is fast, practical, and gets the MVP shipped — but it means the toxic waste for MVP circuits was physically present on one machine, and security depends on that machine not being compromised.

**The MVP circuits are marked `DEVELOPMENT ONLY — not for real funds` in code and in documentation.** The verifier deployed to devnet for MVP demonstration is acceptable for devnet; it is **not** acceptable for mainnet.

**Post-MVP (v0.2 target):**
- Public multi-contributor ceremony with 10–20 independent participants.
- Random beacon finalization.
- Public announcement, GitHub coordination, IPFS distribution of intermediate contributions.
- The mainnet verifier uses keys from this public ceremony, not from the local MVP ceremony.

See [ADR-005](adr/ADR-005-non-upgradeable-verifier.md) for the interaction with the non-upgradeable verifier decision (once a verifier is deployed with specific keys, those keys cannot be swapped — a new ceremony means a new verifier program).

---

## 2. Vulnerability classes we guard against

### 2.1 Incomplete Fiat-Shamir transcript (CRITICAL)

Zero-knowledge proofs using the Fiat-Shamir transform derive challenges by hashing a transcript of public values. If any value that the prover can influence is omitted from the transcript before the challenge is derived, the prover can manipulate the challenge to forge proofs.

This is not theoretical. In 2025, two separate Fiat-Shamir bugs were found in the Token-2022 Confidential Transfers program on Solana — the April incident (missing algebraic components in the transcript) and the "Phantom Challenge" incident in June (a prover-controlled sub-challenge in a sigma OR proof was not absorbed into the Fiat-Shamir transcript, allowing arbitrary proof forgery). The second bug was severe enough to disable the Confidential Transfers program on the main Solana feature set at epoch 805 while a competitive audit was arranged.

We take this as a direct engineering lesson: **our own proof logic is not immune to the same class of mistake**. Our equality proofs, our ElGamal relation proofs, and any future OR composition we introduce all have the same shape as the code that failed.

**Our defence:**
- **Rule 0:** *Anything the prover touches goes into the transcript.* This is the first line of our PR checklist.
- A dedicated Fiat-Shamir discipline checklist on every PR that modifies proof logic, circuits, or transcript construction. See [PR_CHECKLIST_PROOF_LOGIC.md](PR_CHECKLIST_PROOF_LOGIC.md).
- Two-reviewer policy on cryptographic changes. Author plus one independent reviewer must sign off on transcript construction before merge.
- Regression tests: honest proof verifies, tampered public input rejects, reused nullifier rejects.

### 2.2 Poseidon parameter mismatch (HIGH)

tidex6 hashes data offchain in the client (to compute commitments and nullifier hashes) and onchain in the program (to validate Merkle roots). If the offchain Poseidon parameters differ from the onchain parameters by even one round constant, offchain-computed commitments will not match onchain-computed commitments and the entire pool will be unusable.

The standard way this fails: using `ark-crypto-primitives::sponge::poseidon` offchain (which ships with hardcoded parameters that may not match circom / Solana conventions) while the program uses the `solana-poseidon` syscall (which is circom-compatible). The hashes differ silently. Integrators only discover the mismatch when their first proof fails verification, by which point significant time has been lost.

**Our defence:**
- Offchain Poseidon is provided exclusively through `light-poseidon::Poseidon::<Fr>::new_circom(n)`. The `new_circom` constructor locks parameters to the circom-compatible values that match `solana-poseidon` byte-for-byte.
- Day-1 of the MVP timeline has a mandatory equivalence test: hash the same input offchain and onchain, compare byte-for-byte. If the result does not match, stop everything and debug before writing any other code.
- `light-poseidon` version is pinned in `Cargo.toml` with a narrow constraint so auto-updates cannot silently change parameters.

### 2.3 BN254 weakening over time (MEDIUM, long-term)

Covered in section 1.1. The primary mitigation is documentation and user education: users should know that BN254 offers approximately 100 bits of security today, and that long-term confidentiality guarantees depend on the curve remaining computationally hard.

A secondary mitigation is the roadmap item to migrate to a stronger curve when Solana adds the necessary syscalls. Until then, BN254 is the best available option for native Solana ZK verification.

### 2.4 Trusted setup compromise (HIGH, mainnet only)

Covered in section 1.4. For MVP the trusted setup is explicitly marked DEVELOPMENT ONLY and the verifier runs on devnet only. For mainnet the risk is mitigated by the public multi-contributor ceremony planned for v0.2.

A secondary mitigation: even if the mainnet ceremony contributors are collectively compromised, an attacker who learns the toxic waste can forge proofs but cannot retroactively reveal the contents of past deposits. Privacy is preserved; only the soundness of the proof system is broken. This limits the damage to funds that are in the pool at the time of the attack.

### 2.5 ElGamal implementation bugs (HIGH, disclosure path only)

Covered in section 1.3. Bugs in our custom ElGamal code are application-layer and do not compromise the privacy core. They can, however, leak deposit metadata to the wrong party for users who opted into disclosure. The mitigation is a pre-mainnet audit and explicit marking of the code as unaudited.

### 2.6 Indexer availability and honesty (OPERATIONAL)

The Merkle tree of commitments is stored offchain in the indexer. Withdrawers need the indexer to construct their Merkle proof before they can withdraw.

**Honesty:** the indexer cannot lie undetectably about the tree state. Any Merkle proof it produces must verify against an onchain root, which the program maintains in a ring buffer. A malicious indexer can at worst refuse to serve proofs; it cannot forge them.

**Availability:** a malicious or offline indexer can block withdrawals by refusing to serve proofs. Mitigation: the indexer is reference code (`tidex6-indexer`), fully deterministic, and anyone can run their own. The protocol publishes instructions for rebuilding the tree from onchain `DepositEvent` logs. For production, integrators should run their own indexer or use a community-run multi-indexer fallback.

See [ADR-002](adr/ADR-002-merkle-tree-storage.md) for the full rationale.

### 2.7 Viewing key compromise (LIMITED)

If a user's viewing key is leaked, all past deposits encrypted under that key become visible to whoever holds the leaked key. The ciphertexts are already onchain; the viewing key unlocks them retroactively and there is no way to "revoke" it.

**Important:** viewing keys are **read-only**. A leaked viewing key reveals history to the attacker but does not allow the attacker to spend funds. The spending key is a separate value, generated and held independently.

**Mitigations:**
- Viewing keys should be treated with the same care as a tax return — shared only with trusted parties, stored encrypted at rest, transmitted over encrypted channels.
- Users who need to rotate their disclosure posture can simply stop attaching the auditor tag to future deposits. The old leaked key reveals old deposits; the new deposits are protected by a new viewing key not yet shared.
- Wallet-level viewing key management is a v0.2 roadmap item (integration with major Solana wallets for secure storage and selective sharing).

### 2.8 Anonymity set on day one (OPERATIONAL)

A shielded pool is only as anonymous as the number of deposits it contains. On day one of MVP deployment, any one pool has zero deposits. Early users will withdraw from a pool containing a small number of commitments, and the anonymity they receive is correspondingly limited.

**Mitigations and honesty:**
- This is an inherent property of per-program pools and is acknowledged in the pitch and in the flagship example. See [ADR-008](adr/ADR-008-pool-isolation.md).
- The v0.3 shared anonymity pool architecture addresses this through a network effect: all integrators contribute deposits to one common tree, and anonymity grows linearly with adoption.
- For MVP, integrators should set realistic expectations with their users: the flagship `private-payroll` example makes clear that anonymity in small pools is weak, and suggests waiting for adequate depth before relying on the pool for sensitive transfers.

---

## 3. Day-1 Validation Checklist

Before writing any production code, the following four tests must pass. This is a **kill gate** — if any of these fails, stop and debug before proceeding. The MVP timeline assumes these pass in the first two days.

```bash
# 1. Poseidon compatibility test
#    Offchain (Rust, using light-poseidon::new_circom) and
#    onchain (Solana syscall) hash the same input. Bytes must match exactly.

# 2. Groth16 pipeline smoke test
#    Write a trivial circuit ("I know x such that Poseidon(x) == y").
#    Generate a proof with ark-groth16.
#    Verify the proof with groth16-solana inside an Anchor test.
#    If this fails, debug proof format / verifying key conversion / CPI plumbing
#    before anything else.

# 3. alt_bn128 syscall availability on target network
#    Deploy a minimal program that calls the alt_bn128 syscalls.
#    Verify it executes on devnet.
#    Measure actual CU consumption and compare to expected (~200K for full Groth16).

# 4. Anchor 1.0 CPI test
#    Write two programs: caller and callee.
#    Verify CPI works with proof data passed as instruction data.
#    Check account size limits for proof bytes.
```

**If any of tests 1–4 fails, the MVP is blocked.** This is not a suggestion — the rest of the MVP depends on these four primitives working together. Debugging them at day 2 is hundreds of times cheaper than discovering a mismatch at day 20.

---

## 4. Post-MVP security roadmap

**v0.2:**
- Public Phase 2 trusted setup ceremony (10–20 independent contributors).
- External cryptographic audit (subject to grant funding).
- Bug bounty programme.
- Wallet-adapter integration for secure viewing-key storage.
- Full hierarchical key split (spending key → full viewing key → incoming-only viewing key → nullifier key).

**v0.3 and later:**
- Shared anonymity pool (network-effect anonymity set growth).
- Browser WASM prover (no need to trust a server with proof generation).
- Mobile prover for small circuits.
- Migration to a stronger curve when Solana syscalls support it.

---

## 5. Honest limitations summary

To make this document useful as a standalone read for auditors and grant reviewers, the honest summary:

- We use BN254 (~100-bit security) because it is the only option native to Solana.
- We depend on arkworks, which carries an academic-prototype disclaimer.
- Our ElGamal implementation is custom and unaudited, but isolated from the privacy-critical path.
- Our MVP trusted setup is a single-contributor ceremony marked DEVELOPMENT ONLY.
- Our day-one anonymity set is small and we say so explicitly.
- We guard against Fiat-Shamir transcript bugs with a dedicated checklist and two-reviewer policy, because this class of bug has bitten similar systems in the recent past.
- We do not ship to mainnet without a public ceremony and a cryptographic audit.

Everything else is in the ADRs and the [PROJECT_BRIEF.md](PROJECT_BRIEF.md).

---

*tidex6.rs — I grant access, not permission.*
*The Rust-native privacy framework for Solana.*
