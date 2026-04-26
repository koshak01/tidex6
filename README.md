<p align="center">
  <img alt="tidex6" src="brand/logo/hat-solana.svg" width="220">
</p>

<h1 align="center">tidex6</h1>

<p align="center">
  <strong>I grant access, not permission.</strong><br>
  <em>The Rust-native privacy framework for Solana.</em>
</p>

---

tidex6 is a Rust-native, open-source framework that lets Solana developers add full transaction privacy to their Anchor programs through a small SDK surface. Transactions are private by default — sender, receiver, and amount are hidden. Users can optionally share a viewing key with someone they trust (an accountant, an auditor, a family member) to selectively disclose history, on their own terms.

**Status:** full MVP product stack **live on Solana mainnet**. The privacy-core verifier program at [`2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C`](https://solscan.io/account/2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C) is OtterSec-verified. The full feature stack — deposit, ZK withdraw (Groth16 `WithdrawCircuit<20>` verified via `alt_bn128` syscalls), per-nullifier double-spend PDA, recipient-binding front-run protection, **unlinkable withdraw via reference relayer** at [`relayer.tidex6.com`](https://relayer.tidex6.com), opaque hex notes + envelope-encrypted memos with padded fixed-length plaintext, **client-side proof generation in the browser via WebAssembly** (`tidex6-prover-wasm`, ~1.7 s per proof, secret never leaves the user's tab), user-facing `tidex6` CLI, `tidex6-client` SDK, web app at [tidex6.com](https://tidex6.com), the flagship `examples/private-payroll` three-binary demo, and a **third-party CPI integration example** at [`5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`](https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x) (`tidex6-tip-jar`, ~30 lines of Rust to add privacy to any Anchor program) — all validated end-to-end on mainnet. MVP targeted for **Colosseum Frontier hackathon, 2026-05-11**.

> **DEVELOPMENT ONLY.** Pre-audit, single-contributor trusted setup, hackathon-grade trust assumptions. Verifier `upgrade-authority` is still held by the project owner and will be locked with `solana program set-upgrade-authority --final` immediately before Colosseum submission. Do not use to secure real funds. See [`docs/release/security.md`](docs/release/security.md).

---

## Quick start — CLI

Three commands, no setup beyond a Solana mainnet wallet at
`~/.config/solana/id.json`:

```bash
# Generate a tidex6 identity (spending + viewing key).
cargo run --release -p tidex6-cli -- keygen

# Make a private 0.5 SOL deposit to the shielded pool.
cargo run --release -p tidex6-cli -- deposit \
    --amount 0.5 --note-out parents.note

# Redeem the note into any recipient wallet. The CLI rebuilds
# the offchain Merkle tree from on-chain history via the
# indexer, generates a Groth16 withdraw proof, and submits it
# to the verifier program.
#
# Default is the direct path — the user signs their own tx.
# For full unlinkability (ADR-011) add `--relayer` to delegate
# the tx to a relayer service that signs and pays on the user's
# behalf:
#   --relayer https://relayer.tidex6.com \
#   --relayer-pubkey <relayer_hot_wallet_pubkey>
cargo run --release -p tidex6-cli -- withdraw \
    --note parents.note --to <recipient_pubkey>
```

## Quick start — SDK

Integrate a shielded pool into your own Rust app in a handful
of lines using the `tidex6-client` builder API:

```rust
use anchor_client::Cluster;
use tidex6_client::PrivatePool;
use tidex6_core::note::Denomination;

# fn demo(
#     payer: &solana_keypair::Keypair,
#     recipient: anchor_client::anchor_lang::prelude::Pubkey,
# ) -> anyhow::Result<()> {
let pool = PrivatePool::connect(Cluster::Devnet, Denomination::OneSol)?;

// Deposit side: get a note back to share with the recipient.
let (deposit_sig, note, _leaf_index) = pool.deposit(payer).send()?;
std::fs::write("parents.note", note.to_text())?;

// Withdraw side: rebuild the tree, prove, submit.
// Default direct path — user signs the tx themselves.
let withdraw_sig = pool
    .withdraw(payer)
    .note(note)
    .to(recipient)
    .send()?;

// Full unlinkability via the reference relayer (ADR-011): the
// user's keypair never signs the withdraw tx, the relayer pays
// fees and becomes the on-chain payer. Circuit binds the specific
// relayer so a front-runner cannot swap them in mempool.
// let withdraw_sig = pool
//     .withdraw(payer)
//     .note(note)
//     .to(recipient)
//     .via_relayer("https://relayer.tidex6.com", relayer_hot_wallet_pubkey)
//     .send()?;
# drop((deposit_sig, withdraw_sig));
# Ok(())
# }
```

## Try the flagship demo

[`examples/private-payroll`](examples/private-payroll/) is the
full story of Lena sending monthly support to her parents, with
her accountant Kai producing a tax report from a shared scan
file. Three binaries — `sender`, `receiver`, `accountant` —
hit live devnet.

```bash
cd examples/private-payroll
./scripts/run_demo.sh
```

The script splits one terminal into three tmux panes and runs
the whole flow side by side — deposit → rebuild → prove →
withdraw → report — in under a minute.

---

## Architecture at a glance

- **Groth16** zero-knowledge proofs on the **BN254** curve, verified onchain via native Solana `alt_bn128` syscalls in under 200,000 compute units per proof.
- **Poseidon** hash function, parameter-aligned between offchain (`light-poseidon`) and onchain (`solana-poseidon`) components.
- **Offchain Merkle tree** (depth 20, ~1M capacity) with an onchain root ring buffer.
- **Per-deposit selective disclosure** via ElGamal auditor tags — users choose who sees what, per transaction.
- **Shielded memos** — encrypted notes up to ~200 bytes attached to each deposit, readable only by the viewing-key holder.
- **Non-upgradeable verifier** — the core proof verifier is locked after deployment, so users do not have to trust the deployer forever.
- **Relayer unlinkability** — ADR-011: a reference HTTPS service at `relayer.tidex6.com` signs and submits withdraw transactions so the user's wallet never appears on-chain as the payer. The proof commits to the specific relayer (public input) so front-runners cannot redirect the fee. Fee policy for the reference service is zero — we pay tx fees for users as a public good; anyone may run their own relayer with any fee.
- **Client-side proof generation** — `tidex6-prover-wasm` compiles the Rust prover to WebAssembly. The browser parses the deposit note locally, derives `commitment` and `nullifier_hash` via in-WASM Poseidon, and runs Groth16 entirely on the user's machine in ~1.7 s on M-series CPUs. The user's `secret` and `nullifier` never reach our server, the relayer, or anyone else — formally provable by inspecting `WebAssembly.Module.imports(...)` of the deployed `.wasm` artefact, which contains zero `fetch` / `XMLHttpRequest` / `WebSocket` symbols. Sandbox is the proof.
- **Composable as a CPI primitive** — any Anchor program can route SOL through `tidex6_verifier::deposit` and inherit the full privacy stack. The reference example [`tidex6-tip-jar`](https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x) is live on mainnet in ~30 lines of Rust; payroll, royalty splitters, subscription protocols, and dark-pool DEX hooks follow the same pattern.
- **Built with Anchor 1.0.**

Full technical detail: [docs/release/PROJECT_BRIEF.md](docs/release/PROJECT_BRIEF.md).

---

## Technical stack

**Onchain (Anchor 1.0 program):**
- `anchor-lang = "=1.0.0"`
- `groth16-solana = "0.2"` — Groth16 verifier via `alt_bn128` syscalls
- `solana-poseidon = "4"` — native Poseidon syscall

**Offchain (client and prover):**
- `arkworks 0.5.x` — `ark-bn254`, `ark-groth16`, `ark-crypto-primitives`, `ark-r1cs-std`, `ark-relations`, `ark-ff`, `ark-ec`, `ark-serialize`, `ark-ed-on-bn254`
- `light-poseidon = "0.4"` — circom-compatible Poseidon, byte-for-byte equivalent to the onchain syscall
- `anchor-client = "1.0"`, `solana-sdk = "4.0"`

---

## Philosophy

Closed by default. Open by user choice. The protocol enforces nothing about who uses it — it builds rails where honest behaviour is the shortest path. Users who choose to prove their legitimacy do so to someone *they* picked, through a key *they* hold. There is no backdoor, no key escrow, no recovery service. The architecture has a strong opinion about *how* the tool can be used; it has no opinion about *who* uses it.

Full manifesto: [docs/release/THE_LEGEND.md](docs/release/THE_LEGEND.md).

---

## Documentation

Public documentation lives in [`docs/release/`](docs/release/):

- **[THE_LEGEND.md](docs/release/THE_LEGEND.md)** — mission, philosophy, design principles.
- **[PROJECT_BRIEF.md](docs/release/PROJECT_BRIEF.md)** — technical brief: architecture, data flow, workspace layout, developer experience.
- **[ROADMAP.md](docs/release/ROADMAP.md)** — now / next / later, shipping milestones.
- **[security.md](docs/release/security.md)** — threat model, known limitations, vulnerability classes and mitigations.
- **[PR_CHECKLIST_PROOF_LOGIC.md](docs/release/PR_CHECKLIST_PROOF_LOGIC.md)** — Fiat-Shamir discipline checklist for every PR that touches proof logic.
- **[adr/](docs/release/adr/)** — Architecture Decision Records (nine ADRs covering commitment scheme, Merkle tree storage, nullifier storage, ElGamal implementation, non-upgradeable verifier, builder pattern vs macros, killer features, pool isolation, and proving time budget).

**Russian translations** of all of the above are available in [`docs/release/ru/`](docs/release/ru/).

---

## Workspace layout

```
tidex6/
├── crates/
│   ├── tidex6-core/       — commitments, nullifiers, Merkle tree, keys, Poseidon, DepositNote
│   ├── tidex6-circuits/   — arkworks R1CS: DepositCircuit, WithdrawCircuit<20>
│   ├── tidex6-indexer/    — offchain Merkle tree rebuild from on-chain DepositEvent logs
│   ├── tidex6-client/     — Rust SDK with builder pattern API (PrivatePool, DepositBuilder, WithdrawBuilder)
│   ├── tidex6-cli/        — developer CLI: `tidex6 keygen | deposit | withdraw | accountant`
│   ├── tidex6-relayer/    — reference Axum HTTPS service (ADR-011): POST /withdraw, offchain VK verify, replay cache
│   └── tidex6-day1/       — Day-1..12 devnet flight harnesses (Day-1 gates, Day-5 deposit, Day-11 withdraw, Day-12 negative)
├── programs/
│   ├── tidex6-verifier/   — singleton non-upgradeable Anchor verifier program
│   └── tidex6-caller/     — test CPI caller used by Day-1 gate 4
├── examples/
│   └── private-payroll/   — flagship example: sender, receiver, accountant
├── brand/                  — logo assets
└── video/                  — pitch and demo video scripts

Planned for v0.2, not yet in the workspace:
  - Proof of Innocence circuit + Association Set Provider (ADR-007 v2)
  - Relayer hardening: HSM keypair, multi-sig cold wallet, federated discovery
  - Ergonomic proc macros (`#[private_withdraw]` etc.) layered over the builder API (ADR-006)
```

---

## License

Dual licensed under either **MIT** or **Apache-2.0** at your option.

This project is a public good. No token, no SaaS tier, no centralized operator.

---

## Contact

Issues and pull requests on GitHub.

*tidex6.rs — I grant access, not permission.*
