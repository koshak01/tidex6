# Security Updates

This file logs every dependency advisory tidex6 has actioned, the
date the fix shipped, and the practical impact assessment for our
threat model. We surface each item even when the practical impact is
low, so reviewers can see the project is continuously maintained.

---

## 2026-04-25 — v2.5.7

GitHub Dependabot raised nine alerts against `tidex6` and the sibling
service repos (`tidex6-web`, `tidex6-relayer`). All nine are in
**off-chain** transport / utility crates; **none** affect the
on-chain Solana program (`programs/tidex6-verifier`), the Groth16
circuit, the Poseidon commitment scheme, the Merkle tree, or the
shielded-memo envelope encryption. The mainnet verifier program at
`2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C` was **not** redeployed
for this update; only the HTTPS services were rebuilt.

### Fixed

| Crate | From | To | Severity | Practical impact |
|---|---|---|---|---|
| `rustls-webpki` (CVE: DoS via panic on malformed CRL `BIT STRING`) | 0.103.10 / 0.103.11 | 0.103.13 | High | Low. Our HTTPS clients only contact known endpoints (`relayer.tidex6.com`, Helius RPC). No untrusted-server path through the affected code. Even an exploit yields a transient panic, not data leak or privacy regression. |
| `rand` (soundness with custom logger using `rand::rng()`) | 0.8.5, 0.9.2, 0.10.0 | 0.8.6, 0.9.4, 0.10.1 | Low | None. tidex6 never installs a custom rand logger. Nullifier and secret sampling go through `OsRng` directly via `Secret::random` / `Nullifier::random`, which the advisory does not touch. |
| `webpki` (name-constraint validation issues) | transitive of `rustls-webpki` | resolved by the above bump | Low | Same as `rustls-webpki`. |

### Acknowledged (not fixed in this release)

| Crate | Severity | Status |
|---|---|---|
| `tracing-subscriber` 0.2.25 (RUSTSEC-2025-0055, log poisoning via ANSI escapes) | Low | Pulled transitively by `ark-relations 0.5.1` from crates.io. Upstream **already fixed on master** ([snark commit `845ce9d`](https://github.com/arkworks-rs/snark/blob/master/relations/Cargo.toml) bumps `tracing-subscriber` to `^0.3` and makes it optional), but no new crate release has been tagged yet. Tracked upstream in [arkworks-rs/snark#413](https://github.com/arkworks-rs/snark/issues/413) (open since 2026-02-10) and [arkworks-rs/algebra#1075](https://github.com/arkworks-rs/algebra/issues/1075). |

**Why we are not pinning to `arkworks-rs/snark@master` via `[patch.crates-io]`:** master contains a series of unreleased commits beyond the `tracing-subscriber` bump. Any API-level reshuffling inside `ark-relations` could perturb the Fiat-Shamir transcript order baked into `WithdrawCircuit<20>` — exactly the class of regression that `docs/release/PR_CHECKLIST_PROOF_LOGIC.md` exists to catch, and which requires two independent reviewers to sign off on. Trading that risk for a Low-severity log-poisoning advisory that **we cannot trigger in our setup** (we never log untrusted bytes through arkworks paths, and our log sinks do not interpret ANSI escapes anyway) is not a sound engineering trade-off this close to release. We will adopt the fix the moment a tagged `ark-relations 0.5.2` / `0.6.0` ships on crates.io.

### Verification

After the dependency bump, the offchain test suite (`cargo test
--workspace`) was rerun and all 90 tests passed. The on-chain
verifier program was not touched, so the program ID
`2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C` and the deployed
binary hash
`6a3c2afa9df95ae73e201e5416235b8a3dec3480f8950c42e02afc9eecb5244e`
remain the ADR-012 deployment from 2026-04-25.

---

## Threat-model context

For tidex6 the security boundary that matters is:

1. **The Groth16 circuit and verifier** — these decide which spends
   are valid. Any bug here is catastrophic. None of the advisories in
   this log touch this layer.
2. **The shielded-memo envelope cryptography** (AES-256-GCM, Baby
   Jubjub ECDH, HKDF) — these decide who can read memos. None of the
   advisories touch this layer either.
3. **HTTPS transport between the user and the relayer** — `rustls`
   advisories fall here. The fixes in this log strengthen this layer.

The complete threat model is documented in
[`docs/release/security.md`](docs/release/security.md). The
PR-level review process for any change that *does* touch the
verifier or the circuit is in
[`docs/release/PR_CHECKLIST_PROOF_LOGIC.md`](docs/release/PR_CHECKLIST_PROOF_LOGIC.md).
