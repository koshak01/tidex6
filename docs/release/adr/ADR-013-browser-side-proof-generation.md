# ADR-013: Browser-side proof generation via WebAssembly

**Status:** Accepted
**Date:** 2026-04-26

## Context

By ADR-011 the relayer at `relayer.tidex6.com` solves the on-chain
unlinkability problem: the user no longer signs the withdraw
transaction, so wallet-funding correlation is broken. But that ADR
left a *server-side* leak in place. As shipped on 2026-04-25 the web
flow at `tidex6.com/app/` worked like this:

1. The browser sent `note_text` (the v3 deposit note containing
   `secret` and `nullifier` in the clear) to `tidex6_web` over the
   WS gateway.
2. `tidex6_solana` (a separate microservice in the same trust
   domain) parsed the note, rebuilt the Merkle tree, and ran the
   Groth16 prover.
3. The resulting proof was forwarded to the relayer for on-chain
   submission.

Steps 1 and 2 mean the operator of `tidex6.com` — that is, us —
sees every user's `secret` and `nullifier`. From the user's
perspective the privacy guarantee was cryptographic on-chain but
contractual off-chain: "trust the project owner not to log notes."
That contract is exactly the kind of guarantee privacy
infrastructure is supposed to remove.

The standard library `tidex6-client` already does the proving in
Rust. The question is whether that prover can run in the user's
browser — turning "trust the operator" into "verify the sandbox."

## Decision

Compile the existing `tidex6-circuits::withdraw::prove_withdraw`
function plus the in-circuit Poseidon hash to **WebAssembly** via
`wasm-bindgen` and ship the resulting `.wasm` artefact as a
static asset of `tidex6.com`. The browser does the entire
withdraw pipeline locally:

1. **Note parsing** — `parseNote(noteText)` decodes the v3
   blob and returns `secret`, `nullifier`, `denomination_lamports`
   from the WASM module's linear memory. Bytes never round-trip
   to JS land in raw form.
2. **Public derivation** — `commitment(secret, nullifier)` and
   `nullifierHash(nullifier)` run inside WASM via the same
   `light-poseidon` parameters the on-chain syscall uses.
3. **Merkle path lookup** — the browser sends only the *public*
   `commitment_hex` to the server, which runs the existing
   indexer code and returns siblings, leaf index, and root.
4. **Groth16 proving** — `proveWithdraw(...)` runs the full
   prover with the user's secret material as input. Output is
   the 256-byte `proof_a || proof_b || proof_c` blob in the
   on-chain `groth16-solana` byte layout.
5. **Submission** — the browser ships only the proof bytes plus
   the public inputs to the server, which forwards them to
   `relayer.tidex6.com`.

The new crate lives at `crates/tidex6-prover-wasm/`. It is
**excluded from the Cargo workspace** because its target is
`wasm32-unknown-unknown` and it pulls in browser-only crates
(`getrandom/js` v0.2 + `wasm_js` v0.4, `wasm-bindgen`, `js-sys`).
Building it from a host workspace check would otherwise force
every host build to compile WASM-only deps and fail.

## Consequences

### Positive

- **The server cannot learn `secret`/`nullifier`.** Not a policy
  promise; an architectural guarantee. The wire never carries
  that data — there is nothing to log.
- **The user can prove this themselves.** In DevTools Console:
  ```js
  WebAssembly.Module.imports(
    await WebAssembly.compileStreaming(
      fetch('/static/wasm/tidex6_prover_wasm_bg.wasm')))
  ```
  returns a list of imports. None of them are `fetch`,
  `XMLHttpRequest`, `WebSocket`, `localStorage`, or any other
  exfiltration-capable API. The WebAssembly sandbox is the
  proof — confinement is mechanical, not "trust us."
- **Reproducibility is verifiable.** The WASM crate's source is
  in the same monorepo as the rest of tidex6. A skeptical user
  runs `wasm-pack build` against the same git commit and
  byte-compares with `sha256sum`. Subresource Integrity
  (`integrity="sha384-..."`) on the loading `<script>` tag will
  give the browser the same check automatically once we wire
  it in for the Colosseum submission.
- **Same code path as the CLI.** The WASM module wraps
  `tidex6_circuits::withdraw::prove_withdraw` byte-for-byte —
  exactly the function `tidex6 withdraw` in the CLI calls.
  Two distribution channels, one prover.

### Negative

- **Bundle size.** The `.wasm` artefact is ~3.5 MB after
  `wasm-opt`, plus the 2.1 MB `withdraw_pk_depth20.bin` proving
  key. ~5.6 MB total cold-load. Both files have
  `Cache-Control: public, immutable` and are versioned via
  query string (`?v=$static_version`) so each deploy invalidates
  the cache cleanly. After first proof in a session, subsequent
  proofs in the same tab reuse the deserialised key.
- **First proof is slow on cold caches.** End-to-end ~6 s on
  M-series CPUs the first time (download + parse + prove); ~3 s
  per subsequent proof. Persistent prover across calls is a
  v0.2 optimisation.
- **Two new IPC commands.** `SolanaCommand::FetchMerklePath` and
  `SolanaCommand::SubmitWithdrawProof` replace the old monolithic
  `SolanaCommand::Withdraw` for the browser flow. The legacy
  command is kept as a fallback for environments without WASM
  support.

### Threat-model implications (security.md additions)

- Adversary can no longer obtain `secret`/`nullifier` by
  compromising `tidex6_solana` or `tidex6_web` processes.
- Adversary who compromises `tidex6_web` static-file delivery
  can substitute a malicious `.wasm` to exfiltrate. Mitigated
  by SRI hashes (planned for v0.1.1) and reproducible builds.
- Adversary controlling the user's machine still wins; that has
  always been outside the threat model.

## Related

- ADR-011 (relayer) — solved on-chain unlinkability; this ADR
  closes the matching off-chain gap.
- ADR-009 (proving time budget) — 30 s acceptance threshold is
  comfortably met (~1.7 s on consumer hardware).
- ADR-007 (Shielded Memo) — the same browser flow now also
  decrypts memos client-side, completing end-to-end privacy.
