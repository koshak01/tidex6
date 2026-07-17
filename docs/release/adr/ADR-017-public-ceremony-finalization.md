# ADR-017 — Public trusted-setup ceremony: finalization and VK extraction

**Status:** Accepted
**Date:** 2026-07-17
**Related:** ADR-005 (non-upgradeable verifier), ADR-009 (proving-time budget), ADR-015 (confidential amounts — "public ceremony, ADR forthcoming"), `security.md` §1.4 / §2.4 / §5

## Context

The current on-chain `WithdrawCircuit<20>` verifying key comes from
`gen_withdraw_vk.rs` — a **single-contributor** Phase-2 setup with a fixed seed,
marked **DEVELOPMENT ONLY — not for real funds**. A single contributor means one
party knows the toxic waste and could forge proofs. For real funds the setup must
be a **multi-party Phase-2 ceremony**: secure as long as at least one contributor
is honest and destroys their randomness (1-of-N trust).

The **collection half is already built and deployed** (Rust-native, arkworks
0.5, no snarkjs in prod):

- `tidex6-circuits::mpc` — Phase-2 MPC engine (BGM17/MMORPG): `contribute`,
  `verify_extension`, `verify_chain`, PoK per contribution, Fiat-Shamir transcript
- `tidex6-prover-wasm::ceremony_contribute` — browser contribution; toxic waste
  (CSPRNG) never leaves the tab, only the new `CeremonyState` goes out
- `tidex6-web` coordinator (`src/ceremony.rs`, `ws_handlers/ceremony.rs`) —
  accepts a contribution, runs the full MPC verify, atomically promotes
  `current.state`, appends to `log.json`, one contribution per wallet
- `ceremony.html.tera` working Contribute form, `ceremony.tidex6.com` nginx vhost
- Reproducible committed `withdraw_genesis.state`

What is **missing is the output half**: turning an accumulated `CeremonyState`
into a deployed, immutable verifier.

## Decision

### 1. Beacon finalization (the honest last "contribution")

The ceremony is closed by applying a **public random beacon** ([drand] League of
Entropy) as the final, deterministic contribution. The beacon value for a
pre-announced future round is unknown to everyone while the ceremony is open, so
no contributor — not even the last human one — can bias the final parameters; yet
the value is public and verifiable afterward, so anyone can reproduce the final
step.

- Announce a target drand round `R` (future) before closing.
- When round `R` publishes, derive the finalization contribution's randomness
  **deterministically** from the beacon output (`seed = H("tidex6-ceremony-final"
  ‖ round ‖ randomness)`) and apply it via the same `contribute` path.
- Freeze `current.state`: no further contributions accepted; record the beacon
  round + value in `log.json`.

This is a deterministic `contribute`, so it reuses the existing, reviewed MPC
code — no new trusted primitive. The beacon replaces "trust the last human" with
"trust that drand is unpredictable," which is a public, auditable assumption.

### 2. VK extraction (the last mile)

A new binary extracts the on-chain artifacts from the frozen `CeremonyState`:

`current.state` → `ProvingKey` → (`ceremony::selftest_pk` proves+verifies a real
withdraw, returns the `VerifyingKey`) → `groth16_to_solana_bytes` → regenerate
`programs/tidex6-verifier/src/withdraw_vk.rs`.

`selftest_pk` already exists and returns the VK; the binary wires state→pk→VK→
solana-bytes and rewrites the VK static. Its output is byte-deterministic from the
frozen state, so any observer who downloaded the final `CeremonyState` can
reproduce the exact VK that goes on-chain.

### 3. Deploy a fresh immutable verifier on the ceremony VK

The ceremony VK is **not** hot-patched into the current verifier (ADR-005: the
current verifier `CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd` is finalized /
immutable). A **new** verifier program is deployed carrying the ceremony VK,
OtterSec-verified, then `set-upgrade-authority --final`. Pools migrate to it. The
dev-VK verifier remains historical (as v1 does today).

### 4. Public verifiability of the chain

The contribution chain (`log.json` + each `CeremonyState`) is published to GitHub
and IPFS so contributors independently re-run `verify_chain` and confirm their own
contribution is included and unaltered. The server `log.json` is not the source of
truth — the published, reproducible chain is.

### 5. Schema freeze before the ceremony

`WithdrawCircuit<20>` (amount + revoke + relayer fee + recipient binding) must be
**frozen** before the ceremony opens. Any circuit change invalidates the setup and
forces a re-run. ADR-015's confidential-amount circuit shape is the frozen target.

## Consequences

- **Beacon finalization** and the **VK-extraction binary** are the two pieces of
  code to write; both build on existing, reviewed engine code.
- `mpc.rs` is `TRUST-CRITICAL` — the finalization path goes through
  `PR_CHECKLIST_PROOF_LOGIC` with the two-reviewer policy before it secures real
  funds.
- **Bootstrap on prod** (`ceremony_bootstrap`) is a one-time manual step; it is not
  yet wired into supervisor/migrations.
- Until the ceremony runs and a new verifier ships, the on-chain VK stays
  single-contributor and the **DEVELOPMENT ONLY** markings remain in `README`,
  `security.md`, and `ROADMAP`.
- After finalization: remove the DEVELOPMENT-ONLY markings, deploy + re-audit the
  new verifier, and the 1-of-N honest-contributor guarantee replaces the
  single-party assumption.

## Implementation stages

1. Beacon finalization — deterministic drand-seeded final contribution + freeze.
2. VK-extraction binary — `CeremonyState` → `withdraw_vk.rs` (byte-reproducible).
3. Publish the contribution chain (GitHub + IPFS).
4. Deploy + OtterSec-verify + finalize the new verifier on the ceremony VK; migrate
   pools; drop DEVELOPMENT-ONLY markings.

Stages 1–2 are code in `tidex6-circuits` (this repo). Stage 3 is publication.
Stage 4 is a deploy + audit event.

[drand]: https://drand.love
