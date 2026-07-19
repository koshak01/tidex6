# The tidex6 Trusted Setup Ceremony

> *I grant access, not permission.*

A public, multi-party Phase-2 ceremony that generates the production Groth16
parameters for `WithdrawCircuit<20>` — so that no single person can ever forge a
proof. Live at **<https://ceremony.tidex6.com>**. Architecture decision:
[ADR-017](adr/ADR-017-public-ceremony-finalization.md).

## Why a ceremony

Groth16 needs a Common Reference String generated once, up front. Generating it
produces secret randomness — the *toxic waste*. Whoever knows it can forge
proofs: withdraw money that was never deposited. A ceremony makes the setup
multi-party: each contributor mixes in their own fresh randomness and destroys
it. The final parameters are safe as long as **at least one** contributor was
honest — the 1-of-N trust model. Every additional contributor strictly
strengthens the guarantee, never weakens it.

The current on-chain verifying key is still a single-contributor development
setup (marked **DEVELOPMENT ONLY** in [`security.md`](security.md) §1.4). This
ceremony replaces it.

## How to contribute

Open <https://ceremony.tidex6.com>, connect a wallet, click **Contribute**.
Everything happens in your browser:

1. Fresh entropy is generated locally (`crypto.getRandomValues`).
2. Our Rust prover (WebAssembly, `tidex6-prover-wasm::ceremony_contribute`)
   mixes it into the current parameters. The randomness **never leaves the
   tab** — only the new parameters are uploaded.
3. The coordinator runs the full MPC verification (`mpc::verify_extension`):
   proof of knowledge for your contribution, delta-chain continuity, and that
   no other section of the setup was touched. Only then is your contribution
   promoted.

One contribution per wallet. The whole round trip takes under a minute.

## Verify — don't trust

The coordinator's log is **not** the source of truth; the published transcript
is. Anyone can download the chain and re-verify it independently:

```text
curl -O https://ceremony.tidex6.com/transcript/genesis.state
curl -O https://ceremony.tidex6.com/transcript/current.state
git clone https://github.com/koshak01/tidex6 && cd tidex6
cargo run --release -p tidex6-circuits --bin ceremony_verify -- \
    ../genesis.state ../current.state
```

`ceremony_verify` re-checks, with zero trust in the server:

- the genesis parameters are internally consistent (circuit hash matches);
- the downloaded state belongs to the same circuit;
- every contribution carries a valid proof of knowledge and the delta chain
  links genesis → … → current with nothing dropped, reordered, or tampered;
- it prints an attestation (compressed `delta_after`) per contribution — the
  same hex shown on the ceremony page. Find your wallet in the output and you
  have independently proven your randomness is part of the parameters.

## Finalization: the drand beacon

The ceremony is closed by a **public randomness beacon**, not by a human:

1. A future [drand](https://drand.love) round `R` is announced in advance. Its
   value is unknown to everyone while contributions are open, so no
   contributor — not even the last one — can bias the final parameters.
2. When round `R` publishes, its randomness is applied as the final,
   *deterministic* contribution:

   ```text
   cargo run --release -p tidex6-circuits --bin ceremony_finalize -- <round> <randomness_hex>
   ```

   The seed is `SHA-512("tidex6-ceremony-final-v1" ‖ round ‖ randomness)`,
   driving a ChaCha20 CSPRNG through the **same reviewed `contribute` path** as
   every human contribution — no new trusted primitive. Anyone can re-run this
   command on the published state and reproduce the final parameters
   bit-for-bit.
3. The state is frozen (`final.state` + `final.json` audit record); no further
   contributions are accepted.

## VK extraction and the new verifier

The on-chain verifying key is extracted from the frozen state:

```text
cargo run --release -p tidex6-circuits --bin ceremony_extract_vk -- final.state
```

The tool self-tests the proving key (proves and verifies a real withdraw), then
rewrites `programs/tidex6-verifier/src/withdraw_vk.rs`. The output is
**byte-deterministic** from the frozen state — download `final.state`, run the
extract, and `diff` the result against the deployed program.

Per [ADR-005](adr/ADR-005-verifier-non-upgradeable.md) the current verifier is
immutable and cannot be patched. A **fresh** verifier program carrying the
ceremony VK is deployed, source-verified, and its upgrade authority renounced —
immutable, exactly like its predecessor. Pools migrate to it; the dev-VK
verifier remains historical.

## Tooling summary

| Tool | Role |
|---|---|
| `ceremony_bootstrap` | one-time coordinator init: genesis → `~/.tidex6-ceremony/` |
| `tidex6-prover-wasm::ceremony_contribute` | browser-side contribution (entropy stays in the tab) |
| `ceremony_verify` | independent public verification of the full chain |
| `ceremony_finalize` | deterministic drand-beacon finalization + freeze |
| `ceremony_extract_vk` | frozen state → on-chain VK (byte-reproducible) |

All of it is Rust (arkworks 0.5) — the browser contribution, the coordinator
verification, the finalization, and the extraction share one codebase.
