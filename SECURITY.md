# Security Policy

## Status

tidex6 is **pre-audit, pre-mainnet** software under active development
for the Colosseum Frontier hackathon (2026-05-11). Everything in this
repository is labelled **DEVELOPMENT ONLY** until a formal audit and
multi-party Phase-2 trusted setup ceremony have been completed.

Do not deploy this code to mainnet. Do not use it to secure real funds.

The full threat model, known limitations, and vulnerability classes are
documented in [`docs/release/security.md`](docs/release/security.md).

## Reporting a vulnerability

If you believe you have found a security issue in tidex6, please **do
not** open a public GitHub issue. Instead:

- Open a **private** GitHub Security Advisory on this repository
  (`Security` tab → `Report a vulnerability`), **or**
- Contact the maintainer through GitHub directly.

Please include:

- A description of the issue and its impact.
- Steps to reproduce or a proof-of-concept (code, transaction
  signatures, circuit witnesses, etc.).
- The commit SHA or release tag the report applies to.
- Your preferred name or handle for acknowledgement, if any.

You will receive an initial response within a few days. Critical
issues are prioritised over everything else on the roadmap.

## Scope

In scope:

- The `tidex6-core`, `tidex6-circuits`, `tidex6-verifier`,
  `tidex6-caller` crates in this repository.
- The public documentation in [`docs/release/`](docs/release/).
- The onchain program deployed from this repository to devnet.

Out of scope (but still appreciated as informational reports):

- Issues in upstream dependencies (`arkworks`, `light-poseidon`,
  `groth16-solana`, `solana-poseidon`, `anchor`). These should be
  reported upstream; we will track them and pin around them where
  possible.
- Issues in third-party integrators that use the tidex6 SDK.
- Attacks that require compromising the user's private key or their
  host machine.

## Disclosure

Once a fix has been released, the reporter is credited in the release
notes unless they prefer to remain anonymous. We coordinate the
disclosure timeline with reporters and aim for publication within 90
days of the initial report, sooner for critical issues.

## Fiat-Shamir discipline

Every pull request that touches proof logic, circuit definitions,
transcript construction, or cryptographic primitives must complete the
[Fiat-Shamir PR checklist](docs/release/PR_CHECKLIST_PROOF_LOGIC.md)
before merge. Two reviewers must sign off on any change that touches
the Fiat-Shamir transcript. This is non-negotiable — the 2025
Token-2022 Confidential Transfers incidents (referenced in the threat
model) are exactly the class of bug this checklist is designed to
catch.
