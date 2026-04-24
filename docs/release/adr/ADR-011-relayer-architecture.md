# ADR-011: Relayer architecture — fee-in-circuit with reference service

**Status:** Accepted — Supersedes the 2026-04-16 v0.2-deferred decision recorded in project memory
**Date:** 2026-04-24

> Earlier thinking scoped the relayer for v0.2 on the grounds that its utility (fee sustainability) did not justify the circuit change cost in the MVP window. After user review that reasoning was rejected: without a relayer, `unlinkability` — the property the entire shielded pool exists to provide — is silently undermined by the on-chain fee-payer requirement. Deferring the relayer is deferring the product.

## Context

A Solana transaction must be signed by at least one account that is also the fee-payer. Today `withdraw` is signed by the `payer` account in the `Withdraw` context (`programs/tidex6-verifier/src/lib.rs` line 354). In practical use that payer is the recipient or a wallet funded by the recipient. Either way, the payer's on-chain history can be correlated to the deposit address that funded it — and the entire deposit → withdraw pair stops being unlinkable.

ADR-001 through ADR-010 built a shielded pool where:

- the deposit commitment hides `(secret, nullifier)` (ADR-001),
- the Merkle tree hides the position of the spent commitment (ADR-002),
- the nullifier hides which deposit was spent (ADR-003),
- the encrypted memo hides the audit trail (ADR-010).

All of that is defeated if the on-chain withdraw transaction is signed by a wallet that publicly received funds from the original depositor's wallet. The only structural fix on a fee-based chain is to introduce a third party — a relayer — who pays the fee and submits the transaction. The user never appears on-chain as a signer of the withdraw.

Three options:

1. **No relayer (status quo).** User pays fee. Privacy compromised for every non-trivial user because wallet funding flows become visible. Cheapest engineering; worst product.
2. **Relayer as pay-through service, no circuit binding.** Anyone can relay; the tx is unsigned by the user. But without circuit binding, a front-runner in the mempool rewrites the submitted transaction to redirect funds to themselves and the proof still verifies because the recipient/payer fields are not bound by the proof. Attack class already caught on this project as Day-12 negative harness.
3. **Relayer with fee bound inside the withdraw circuit.** `relayer_address` and `relayer_fee` become additional public inputs to `WithdrawCircuit<20>`. The Groth16 proof is valid only for the exact `(recipient, relayer_address, relayer_fee)` tuple the prover committed to. A front-runner who rewrites any of those three fields in the submitted transaction invalidates the proof and loses nothing but compute.

## Decision

**Option 3. Relayer with fee bound inside the withdraw circuit, referenced implementation deployed at `relayer.tidex6.com`, with `relayer_fee = 0` as the policy of our reference service.**

Concretely:

### Circuit changes (`crates/tidex6-circuits/src/withdraw.rs`)

- `WithdrawCircuit<DEPTH>` gains two new public-input fields: `relayer_address: Option<Fr>` and `relayer_fee: Option<Fr>`.
- In `generate_constraints`:
  - Allocate both as `FpVar::<Fr>::new_input(…)` after the existing `recipient_var`. **Order matters:** public inputs are appended *after* the existing three, not inserted, so the on-chain and off-chain serialization agree.
  - Bind each with a degenerate quadratic constraint of the same shape as the existing recipient binding: `let _relayer_address_squared = &relayer_address_var * &relayer_address_var;` and `let _relayer_fee_squared = &relayer_fee_var * &relayer_fee_var;`. This prevents arkworks from optimizing the allocated public input away and forces the prover to commit to the specific value, matching the Tornado-style recipient binding.
- `WithdrawWitness` gains `relayer_address: &'a [u8; 32]` and `relayer_fee: &'a [u8; 32]` fields — both already in the BN254 canonical encoding expected by `Fr::from_be_bytes_mod_order`.
- `prove_withdraw` returns `(Proof<Bn254>, [Fr; 5])` instead of `[Fr; 3]`. The returned public-input array order is fixed as `[merkle_root, nullifier_hash, recipient, relayer_address, relayer_fee]` and documented in a doc comment.
- `verify_withdraw_proof` signature updated to accept `&[Fr; 5]`.

### Verifying-key regeneration (`crates/tidex6-circuits/src/bin/gen_withdraw_vk.rs`)

Unchanged code — `setup_withdraw_circuit` now exercises the extended circuit automatically because `WithdrawCircuit::default()` values come from the same `ConstraintSynthesizer` impl. The generator produces:

- `programs/tidex6-verifier/src/withdraw_vk.rs` with `WITHDRAW_NR_PUBLIC_INPUTS = 5` and a new VK.
- `crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin` regenerated.

Fixed seed `SETUP_SEED = 0x7715_ef25_d061_3517` is retained. Determinism requirement: two independent runs on the same Rust toolchain produce byte-identical `withdraw_vk.rs`. Verified as a CI step before the mainnet redeploy.

### Verifier program changes (`programs/tidex6-verifier/src/lib.rs` and `pool.rs`)

- `withdraw` instruction gains `relayer_fee: u64` as a new instruction argument. `relayer_address` is derived from the new `relayer: UncheckedAccount<'info>` account in the `Withdraw<'info>` struct — same pattern the existing code uses for the recipient. No need to pass the address as a raw argument.
- `Withdraw<'info>` gains `pub relayer: UncheckedAccount<'info>` (writable, `#[account(mut)]`). No signer requirement: the relayer account in this context is just the address that receives the fee; whoever signs the transaction is separate.
- `handle_withdraw` in `pool.rs`:
  - `require!(relayer_fee <= pool.denomination, Tidex6VerifierError::InvalidRelayerFee)`.
  - `recipient_fr = reduce_mod_bn254(&ctx.accounts.recipient.key().to_bytes())` as today.
  - `relayer_fr = reduce_mod_bn254(&ctx.accounts.relayer.key().to_bytes())`.
  - `relayer_fee_fr = fr_from_u64_le(relayer_fee)` — new helper that pads the little-endian bytes of a `u64` into a 32-byte big-endian field element. Same encoding the off-chain prover uses.
  - `public_inputs = [merkle_root, nullifier_hash, recipient_fr, relayer_fr, relayer_fee_fr]` — five entries, fixed order.
  - Groth16 verifier runs with `WITHDRAW_NR_PUBLIC_INPUTS = 5`.
  - On success: two system-program transfers with the vault seeded-signer:
    1. `(denomination - relayer_fee) → recipient`
    2. `relayer_fee → relayer` (skipped if zero to save CU and avoid zero-value transfer edge cases)
- `WithdrawEvent` gains `relayer: Pubkey` and `relayer_fee: u64` so off-chain indexers see the split.
- Log line format evolves to `tidex6-withdraw:<denomination>:<nullifier_hex>:<relayer_pubkey_base58>:<relayer_fee>`. The indexer's log parser updates to accept both the three-field legacy form and the new five-field form, same dual-version pattern ADR-010 introduced for `tidex6-deposit`.
- New error `Tidex6VerifierError::InvalidRelayerFee` with message `"Relayer fee must not exceed the pool denomination."`.

### Reference relayer service (`crates/tidex6-relayer/`)

A new crate in the workspace. Axum HTTP service with three endpoints:

- `POST /withdraw` — accepts `{proof, public_inputs, recipient, relayer_address, relayer_fee}`, enforces `relayer_address == RELAYER_PUBKEY_HARDCODED` and `relayer_fee == 0` (our policy), runs off-chain `ark_groth16::Groth16::verify` before submission to reject invalid proofs without spending on-chain fees, submits the transaction signed by the relayer keypair.
- `GET /health` — liveness probe.
- `GET /stats` — transparency: current hot-wallet balance in SOL, number of withdraws processed in the last 24h, current requests-per-second. No privacy-sensitive fields.

In-memory `DashMap<nullifier_hash, Instant>` with a one-hour TTL rejects replay submissions before they hit the RPC. Nginx on the deployment side supplies rate-limiting per IP; the service itself does not.

### Client SDK (`crates/tidex6-client/src/withdraw.rs`)

`WithdrawBuilder` gains two mutually-exclusive methods:

- `pub fn via_relayer(self, url: impl Into<String>, relayer_pubkey: Pubkey) -> Self`
- `pub fn direct(self) -> Self`

The default for backward compatibility is `direct` (existing behavior). A pair of constants:

```rust
pub const DEFAULT_RELAYER_URL: &str = "https://relayer.tidex6.com";
pub const DEFAULT_RELAYER_PUBKEY: Pubkey = /* filled in by the relayer deploy, see Day 12 */;
```

When `via_relayer` is used, `WithdrawBuilder::send` builds the proof with `(relayer_pubkey, 0)` as the last two public inputs, sends the proof + inputs over HTTPS to the relayer, and returns the signature from the relayer's response. The client's keypair signs nothing — it exists only to generate the proof and to derive the recipient pubkey.

### CLI (`crates/tidex6-cli/src/commands/withdraw.rs`)

New flags:

- `--relayer <url>` (optional; default `DEFAULT_RELAYER_URL`).
- `--direct` (optional; disables relayer path, user pays own fee; kept for debugging and for users who prefer minimal trust in the reference service).

### Philosophy: why `relayer_fee = 0`

The reference service eats the ~5000-lamport tx fee out of its own hot-wallet balance and charges nothing. This is not a monetization mechanism. It is a statement that the protocol's reference infrastructure is provided as a public good. The circuit and verifier are built to support any non-zero `relayer_fee` — any fork, competitor, or third-party integrator can run their own relayer and charge a fee by passing `relayer_fee > 0`. The hot-wallet fund ceiling of 0.5 SOL bounds the worst-case loss if the keypair is ever compromised.

## Consequences

**Positive:**

- **Unlinkability holds.** Withdraw transactions on-chain are signed by `relayer.tidex6.com`'s keypair. The recipient pubkey is visible (it receives the SOL), but there is no on-chain linkage back to the depositor's wallet. The full privacy promise of the shielded pool is now operational.
- **Front-run protection is architectural, not procedural.** A front-runner cannot swap `relayer_address` or `relayer_fee` in a submitted transaction because those fields are bound inside the Groth16 proof. The attack class is closed by construction.
- **Future fee models require no protocol change.** A v0.2 decision to charge `relayer_fee = 0.001 SOL` on the reference service is a configuration change in the service, not a circuit change or verifier redeploy.
- **Integrator programs are unaffected.** The `withdraw` CPI signature changes, but integrators calling via `tidex6-client` see only the new `via_relayer` / `direct` methods; the builder keeps backward compatibility.
- **Existing deposits remain spendable.** Commitments in the pool are `Poseidon(secret, nullifier)` — unchanged. Old deposit notes work under the new circuit; the prover just packs two additional public inputs. No migration required for users holding pre-ADR-011 notes.

**Negative:**

- **Verifier redeploy.** ADR-010 noted that its redeploy would be the last before `solana program set-upgrade-authority --final`. That statement is now obsolete: ADR-011's redeploy is the last. The upgrade authority is retained through Day 17 (Colosseum submission), then locked.
- **VK invalidation.** Any cached off-chain proving key is invalidated; all clients must regenerate the PK locally from the new setup run. Same pattern as any other circuit-shape change.
- **Instruction data grows by 8 bytes.** One extra `u64` argument. Negligible.
- **New on-chain account.** The `relayer` account in `Withdraw<'info>` adds one entry to the required accounts list and one pubkey to every transaction. ~32 bytes per tx. Negligible.
- **Hot-wallet operations burden.** Someone must monitor the relayer's SOL balance and top it up from cold storage. Manual procedure for MVP; automated multi-sig refill is a v0.2+ item tracked separately.
- **Service availability becomes a protocol-visible concern.** If `relayer.tidex6.com` is down, users can still use the `--direct` path but lose unlinkability. Mitigated by open-sourcing the relayer crate — any third party can run one.

## Fiat-Shamir discipline (PR_CHECKLIST_PROOF_LOGIC.md checklist)

This ADR covers a proof-logic change and therefore goes through the `PR_CHECKLIST_PROOF_LOGIC.md` in full.

Rule 0: every value the prover touches goes into the transcript. In Groth16 the "transcript" is the public-input vector; extending it with `relayer_address` and `relayer_fee` is exactly the mechanism that binds those values. If they were instruction arguments but not public inputs, a malicious prover could produce a proof for `recipient = X, relayer = Y` and replay it as `recipient = X, relayer = Z` — classic class of bug. They are public inputs precisely so that mutation invalidates the proof.

Section 1 items:

- **All public inputs absorbed.** Yes — five inputs, all appear in both `WithdrawCircuit::generate_constraints` (as `new_input` allocations) and in the on-chain `public_inputs` array passed to `Groth16Verifier`.
- **Domain separator.** The circuit's VK acts as the domain separator in Groth16: a proof generated for this VK does not verify against any other VK. Changing from 3 to 5 public inputs produces a new VK, so cross-ADR proof replay is prevented.

Section 2 — transcript order:

- **Fixed order:** `[merkle_root, nullifier_hash, recipient, relayer_address, relayer_fee]`. Documented in the doc comment on `prove_withdraw` and in `handle_withdraw` in `pool.rs`. Two code sites, one ADR — the spec.

Section 3 — constraint count:

- **Delta:** +2 allocations, +2 degenerate quadratic constraints (one per new public input). Total circuit-level compute impact is two R1CS constraints. Verified via a `cargo test -p tidex6-circuits` run that records the constraint count delta in the test log.

Section 4 — negative tests:

- **Tampered `relayer_address`:** handler rewrites the relayer account, proof rejected.
- **Tampered `relayer_fee`:** handler passes a different fee value than the prover committed to, proof rejected.
- **Front-run simulation:** Day-12 harness extended to cover relayer-field substitution.
- **Zero-fee happy path:** CLI deposit, withdraw with `fee = 0`, recipient receives full denomination.
- **Non-zero fee happy path:** synthetic test with `fee = 0.001 SOL`, split confirmed on-chain.

Two-reviewer policy: author (Claude on behalf of Koshak) and Koshak sign off before the mainnet redeploy. No single-approval merges on proof-critical code.

## Migration plan

Day-by-day implementation in `/Users/koshak01/.claude/plans/nested-humming-harp.md`. High-level phases:

1. **Circuit + VK + verifier update.** Code changes, unit tests, negative tests.
2. **Mainnet cleanup.** Withdraw existing Day-13 test deposits under the old circuit, then redeploy the verifier with the new VK.
3. **Relayer crate.** `crates/tidex6-relayer` with HTTP service, off-chain verify, replay protection.
4. **Client and CLI update.** `WithdrawBuilder::via_relayer`, `--relayer` flag.
5. **Frontend (`tidex6-web`) update.** Replace local signing with HTTPS POST to the relayer.
6. **Deploy.** `relayer.tidex6.com` subdomain, Unix-socket nginx proxy, systemd unit, 0.5 SOL fund.
7. **Videos and docs.** Pitch, demo, Week-3, README, ROADMAP, CLAUDE.md — all updated to reflect the shipped relayer.
8. **Finalize.** `solana program set-upgrade-authority --final`, Colosseum submission.

## Related

- **ADR-001** — commitment scheme. Unchanged by this ADR.
- **ADR-002** — Merkle tree storage. Unchanged.
- **ADR-003** — nullifier PDA. Unchanged.
- **ADR-005** — non-upgradeable verifier. This ADR's redeploy is now the last before the `--final` lock. ADR-010's "last redeploy" claim is superseded.
- **ADR-007** — killer features. `Shielded Memo` ships in MVP; this ADR promotes the relayer from the v0.2 roadmap item into MVP so `unlinkability` joins selective disclosure as an MVP property, not a v0.2 promise.
- **ADR-010** — memo transport. The relayer service does not interact with memo payloads in any way; deposits carry memos, withdraws do not.
- `crates/tidex6-circuits/src/withdraw.rs` — circuit that gains the two new public inputs.
- `crates/tidex6-circuits/src/bin/gen_withdraw_vk.rs` — VK regenerator, unchanged code but produces a new VK.
- `programs/tidex6-verifier/src/lib.rs`, `programs/tidex6-verifier/src/pool.rs` — instruction and handler that gain the `relayer` account, `relayer_fee` argument, second transfer, and `InvalidRelayerFee` error.
- `programs/tidex6-verifier/src/withdraw_vk.rs` — regenerated VK with `WITHDRAW_NR_PUBLIC_INPUTS = 5`.
- `crates/tidex6-client/src/withdraw.rs` — builder gains `via_relayer` and `direct` modes.
- `crates/tidex6-cli/src/commands/withdraw.rs` — `--relayer` and `--direct` flags.
- `crates/tidex6-relayer/` — new crate, HTTP service.
- `docs/release/PR_CHECKLIST_PROOF_LOGIC.md` — discipline this ADR follows for the circuit change.
