<p align="center">
  <img alt="tidex6" src="brand/logo/hat-solana.svg" width="220">
</p>

<h1 align="center">tidex6</h1>

<p align="center">
  <strong>I grant access, not permission.</strong><br>
  <em>Private stablecoin payments with disclosure by consent — one Rust
  codebase, live on Solana mainnet, on Arc and on EVM chains.</em>
</p>

---

tidex6 is a Rust-native, open-source framework that lets Solana developers add full transaction privacy to their Anchor programs through a small SDK surface. Transactions are private by default — sender, receiver, and amount are hidden. Privacy comes in **two layers**: a Groth16 shielded pool hides the *link* between sender and receiver, and a Token-2022 Confidential Transfers layer (wUSDC / wUSDT hidden-amount pools, live on mainnet and devnet) hides the *amount* itself. Users can optionally share a viewing key with someone they trust (an accountant, an auditor, a family member) to selectively disclose history, on their own terms.

**Status:** full MVP product stack **live on Solana mainnet**. The privacy-core verifier program at [`CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd`](https://solscan.io/account/CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd) is OtterSec-verified and immutable (upgrade authority renounced). The full feature stack — deposit, ZK withdraw (Groth16 `WithdrawCircuit<20>` verified via `alt_bn128` syscalls), per-nullifier double-spend PDA, recipient-binding front-run protection, **unlinkable withdraw via reference relayer** at [`relayer.tidex6.com`](https://relayer.tidex6.com), opaque hex notes + **post-quantum ML-KEM-768 encrypted memos in a dedicated on-chain account**, **stealth payments** (the recipient is never handed the note — they scan the chain with their own ML-KEM secret) and **per-deposit revoke**, **client-side proof generation in the browser via WebAssembly** (`tidex6-prover-wasm`, ~1.7 s per proof, secret never leaves the user's tab), user-facing `tidex6` CLI, `tidex6-client` SDK, web app at [tidex6.com](https://tidex6.com), the flagship `examples/private-payroll` three-binary demo, and a **third-party CPI integration example** (`tidex6-tip-jar`, ~30 lines of Rust to add privacy to any Anchor program — deployed and OtterSec-verified on mainnet at [`5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`](https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x) in April 2026, demo deployment since closed) — all validated end-to-end on mainnet. MVP shipped for the **Colosseum Frontier hackathon (2026-05-11)**; development continues — since then the **hidden-amount pools** (Token-2022 Confidential Transfers, wUSDC [`AYTRKmF8VBdqRWGZr9c6Mx582SRm2tbUEwMesFMhcPcU`](https://solscan.io/account/AYTRKmF8VBdqRWGZr9c6Mx582SRm2tbUEwMesFMhcPcU) and wUSDT [`QGPYpwyMnWhJUPGieXyJU5jhAkKsKuU7iGN53VCWPz2`](https://solscan.io/account/QGPYpwyMnWhJUPGieXyJU5jhAkKsKuU7iGN53VCWPz2)), a configurable **per-operation fee** paid on top by the sender and **collected privately** as a stealth note (ADR-016), and the live **public trusted-setup ceremony** at [ceremony.tidex6.com](https://ceremony.tidex6.com) (ADR-017) have shipped.

> **DEVELOPMENT ONLY.** Pre-audit, single-contributor trusted setup, hackathon-grade trust assumptions. Verifier `upgrade-authority` has been renounced with `solana program set-upgrade-authority --final` — the program is immutable. Do not use to secure real funds. A **public multi-party trusted-setup ceremony is live** at [ceremony.tidex6.com](https://ceremony.tidex6.com) (publicly verifiable transcript, see [CEREMONY.md](docs/release/CEREMONY.md)); the on-chain VK is replaced only when the ceremony finalizes and a fresh immutable verifier ships. See [`docs/release/security.md`](docs/release/security.md).

---

## The same circuit off Solana — Arc and the EVM chains

Solana is where this started and where the deepest integration lives, but the
proof system is not tied to it. The same Groth16 circuit and the same verifying
key run unchanged on EVM chains through a Solidity verifier and a Solidity
Poseidon (`contracts/`), against a hidden-amount pool where the value sits
inside the commitment rather than next to it. One rail, not one protocol per
chain.

**Arc** — Circle's chain, where the loop closes. The contracts needed no
modification: Arc's BN254 precompiles (`0x05`–`0x08`) were checked live before
deploying. Six contracts on chain 5042, deployed 18 September 2026:

| contract | address |
|---|---|
| HiddenPool (sealed amounts) | `0x28fbB1500875EaEbe303D195C1a3721BBed8AF5f` |
| Pool (fixed denomination) | `0x8eb05Cb1b5E46e58C8ca91E3A3738CF534c1E74f` |
| Groth16 Verifier | `0x2c94135FB49840a0D6e0985AB1A6c48EE6c140d6` |
| HiddenWithdrawVerifier | `0x6fF8E8393F0dD9D2592332e9f9adC3232FC41786` |
| HiddenTransferVerifier | `0xca4fECF177dBb1025CC64B3D3618AdfA2f44D7AD` |
| Reader-key Registry | `0x6F6F07e14E8381D13D01f99867985D8c7D23E914` |

The same addresses exist on Arc Testnet (chain 5042002) — same deployer, same
nonces — and testnet is the place to put hands on it: faucet at
[faucet.circle.com](https://faucet.circle.com), flow identical to mainnet.

What makes Arc more than another deployment target: **gas there is USDC**, the
same token the pools move and the same token the fee is charged in. Everywhere
else, a service paying its own running costs out of its own revenue has to
convert one asset into another — on Solana the fee is swapped to SOL through an
aggregator when the operator's balance falls under a threshold
(`crates/tidex6-ct-lab/src/gas.rs`). On Arc there is nothing to convert: fee in
USDC, gas in USDC, no swap, no price risk, no third party. On the remaining EVM
chains that loop is still open — fee in USDC, gas in ETH or HYPE — and closing
it is the next piece of work.

How the fee works and what it costs, including the parts that do not work yet,
is written out in [docs/release/BUSINESS.md](docs/release/BUSINESS.md).

**Arbitrum** — where the contracts are Rust rather than Solidity. The same pool
is compiled to WASM and runs on Stylus (`stylus/`), on two chains: Arbitrum
Sepolia and Robinhood Chain, an Orbit chain whose token is a tokenized stock.
Every contract is a reproducible Docker build and `cargo stylus verify` passes
on both networks, constructor included.

| contract | Arbitrum Sepolia | Robinhood Chain |
|---|---|---|
| `hidden-pool` (USDC / TSLA) | `0xe4c1f2bc121800b8e56ff11dced9a62d6ce3b383` | `0xf4029451b6988d32ed1a9de847bf3250e83a87fe` |
| `hidden-pool` (USDG) | `0x27ee24bea73088095b2898b3098e2b6040515275` | `0x73f68e1e4d02557e6cefd0292ffac13da5d18490` |
| `hidden-withdraw-verifier` | `0xe00eca003e40bb3f2df30c5b7111c73cff9d0b00` | `0x6f6c5b8e4b2f637aa7c7c47eb90c73bc18c5008d` |
| `hidden-transfer-verifier` | `0x5024f1348dccb7f612cf0f5dc08de81b99c3fbb8` | `0xeb8cfac5351089d9436fc9fc3a40c93f1aa282f4` |
| `poseidon` | `0x3454f4bb9b3bb20344bbb3cb43d6fb743a1c1d68` | `0xe9182c3b0cdf5bfb8871ac162fa28a501a3cfa82` |

Three tokens move through these pools, and the point is that the pool does not
care which: **USDC**, **TSLA** — a tokenized stock, so a salary or an invoice
can be paid in equity without publishing what anyone is paid — and **USDG**,
Paxos's dollar, added 22 September 2026 on both chains. A second token is a
second pool sharing the first one's verifiers: the proof is about the tree and
the nullifier and carries no signal about which token is inside.

Poseidon is what makes this worth doing in Rust: a depth-20 tree walk hashes
twenty times per deposit, and in Solidity one hash costs around 63 000 gas
(measured on our own deployment). On Stylus the constraint moves elsewhere —
a contract must fit 24 KB after brotli, and Poseidon's 195 round constants do
not compress — which is why the hash is a separate contract the pool calls.
`stylus/README.md` has the sizes, the deployment gas and the reasoning.

> The EVM, Arbitrum and Arc deployments carry the same caveat as Solana, and
> one more: the verifying key comes from the ceremony still in progress, so
> these pools are for review and testing, not for real money.

---

## What works, what does not yet, and what we chose not to do

Judges and integrators ask these three questions anyway; the answers are
better written down by us than discovered.

**Works — and can be run by anyone:**

- Private stablecoin payments on **Solana mainnet** in wUSDC and wUSDT: the
  Groth16 pool hides who paid whom, Token-2022 Confidential Transfers hide the
  amount. The verifier is immutable (upgrade authority renounced).
- The hidden-amount pool on **Arbitrum Sepolia, Robinhood Chain, Base Sepolia,
  HyperEVM testnet, Arc testnet and Arc mainnet**: send, receive and audit from
  the browser at [tidex6.com](https://tidex6.com); the relayer pays the gas, so
  the recipient's wallet never appears as the one that asked for the money.
- **USDG on Robinhood Chain**: a full payment and withdrawal run live on
  23 September 2026, fee note included.
- **The treasury**: every payment's 1% fee is a separate note sealed to the
  treasury; a robot on our server collects those notes, another tops up the
  relayer's gas from the treasury. Live balances and every robot transaction
  are public at [tidex6.com/treasury](https://tidex6.com/treasury/).
- 51 contract tests (Foundry) run in CI on every push.

**Does not work yet:**

- **Deposit amounts on the EVM pools are public.** Amounts inside the pool
  (join-split) are hidden; hiding them on the way in is the confidential token
  that comes next.
- **The verifying key is still a development key** until the public ceremony
  at [ceremony.tidex6.com](https://ceremony.tidex6.com) closes. The pools are
  for review and testing.
- **USDG on Arbitrum Sepolia is deployed but not run end to end**: the Paxos
  testnet faucet stopped paying out on that chain on 22 September 2026, so
  there is no test USDG to pay with.
- **No swap of fees into gas on the EVM testnets**: there is no liquidity to
  swap against. On Arc none is needed — gas is USDC, the same money the fees
  arrive in.
- **USDG on Solana is on devnet only.** The wUSDG wrapper and its pool
  (`GwZ55BcsK39KBmT3oh6jcWQpVm7EpC7p8rFNVWFUvN5U`) run on devnet since
  23 September 2026; mainnet follows when there is demand for it — the
  deployment is the same, only paid for.
- **On Solana the wrapper is custodial**: the underlying USDC/USDT sits in a
  vault under the operator's key, and the operator sees the send side. A
  wrapper program with PDA authority is the next step.

**Chosen not to do, and why:**

- **No wallet screening yet.** Nothing checks a wallet against sanctions lists
  or known-hack databases before it enables payments. The check belongs at
  Enable, where a wallet first registers; the method — an on-chain oracle
  where the chain has one, outside databases elsewhere — is not decided. It is
  not in the pool contracts, because deployed pools cannot be changed, and a
  check in the browser alone can be walked around.
- **The Solana verifier cannot be upgraded — by us either.** New rules mean a
  new program at a new address that people choose to move to; nobody can
  change the rules under money already deposited.
- **Poseidon is a separate contract on Stylus.** Its 195 round constants do
  not compress under the 24 KB brotli limit.
- **The Stylus pools have no `token()` getter.** The relayer keeps each
  pool's token address in its own table, checked against storage slot 0;
  adding the getter would mean redeploying pools that already hold funds.

---

## What builds from a clean clone

Everything in this repository builds with `cargo build --release` after a plain
`git clone`, and the on-chain programs build reproducibly in Docker via
`solana-verify build`. Three crates are deliberately outside the workspace and
build on their own terms:

| crate | how to build it | why it is separate |
|---|---|---|
| `crates/tidex6-prover-wasm` | `wasm-pack build` | targets `wasm32-unknown-unknown` and pulls browser-only crates |
| `crates/tidex6-ct-lab` | `cargo build --manifest-path crates/tidex6-ct-lab/Cargo.toml` | pinned to newer `spl-token-2022` / `solana-*` than the workspace |
| `crates/tidex6-mcp` | `cargo build --manifest-path crates/tidex6-mcp/Cargo.toml` | **needs a checkout of our internal core (`forge`) next to this repo**, so it cannot build for anyone else |

The last one is worth stating plainly rather than leaving to be discovered: the
hosted MCP server depends on a private crate outside this repository. While it
was a workspace member, `cargo build` failed in a clean clone for everybody who
does not have that checkout — which is everybody but us — and for the same reason
a program verifier could not build the repository on its own machine. It is now
its own workspace. Nothing else here depends on it: the payment protocol, the
programs, the SDK, the CLI and the local MCP server (`crates/tidex6-mcp-local`)
are all self-contained.

---

## Quick start — stablecoins (USDC / USDT)

The pools in production move **USDC and USDT with the amount hidden on chain**.
Two ways in, neither of which needs this repository built from source:

**In a browser** — [tidex6.com](https://tidex6.com), any Solana wallet. The
proof is generated inside your tab; the secret never leaves it.

**From an AI agent or the command line** — the local MCP server signs with a
key that stays on your machine, under limits enforced in code:

```bash
cargo install tidex6-mcp-local
```

```json
{ "mcpServers": { "tidex6": { "command": "tidex6-mcp-local", "args": [] } } }
```

Tools: `send`, `payments`, `collect`, `audit`, `whoami`. Full description in
[`crates/tidex6-mcp-local/README.md`](crates/tidex6-mcp-local/README.md).

## Quick start — the original SOL pool

The `tidex6` CLI below talks to the **v0.1 fixed-denomination SOL pool**, which
predates the stablecoin pools and remains available — it carries no issuer
`freeze_authority`, which is the reason to keep it. Amounts there are visible on
chain; only the link between sender and recipient is hidden. For hidden amounts
use the stablecoin path above.

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
let pool = PrivatePool::connect(Cluster::Mainnet, Denomination::OneSol)?;

// Deposit side: keep the note locally — with stealth payments the recipient
// is never handed the note; they discover the deposit by scanning the chain
// with their own ML-KEM secret.
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
hit live mainnet.

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
- **Hidden amounts** — a Token-2022 Confidential Transfers layer (wUSDC / wUSDT wrapped-mint pools, live on mainnet and devnet) hides the transferred amount itself on top of the Groth16 link-privacy pool. Two layers: the pool hides *who↔whom*, confidential transfers hide *how much*.
- **Per-deposit selective disclosure** via post-quantum ML-KEM-768 auditor tags — users choose who sees what, per transaction.
- **Shielded memos** — post-quantum ML-KEM-768 encrypted notes stored in a dedicated on-chain account (separate from the deposit event), readable only by the viewing-key holder. Supports **stealth payments** (the recipient scans the chain with their own ML-KEM secret rather than receiving the note) and **per-deposit revoke**.
- **Non-upgradeable verifier** — the core proof verifier is locked after deployment, so users do not have to trust the deployer forever.
- **Relayer unlinkability** — ADR-011: a reference HTTPS service at `relayer.tidex6.com` signs and submits withdraw transactions so the user's wallet never appears on-chain as the payer. The proof commits to the specific relayer (public input) so front-runners cannot redirect the fee. The in-circuit `relayer_fee` policy for the reference service is zero; anyone may run their own relayer with any fee. Separately, deposits carry a configurable per-operation fee (ADR-016): the sender pays it on top (it may be zero), it is shown before signing, and it is collected privately — as a stealth note to the operator inside the same shielded pool.
- **Client-side proof generation** — `tidex6-prover-wasm` compiles the Rust prover to WebAssembly. The browser parses the deposit note locally, derives `commitment` and `nullifier_hash` via in-WASM Poseidon, and runs Groth16 entirely on the user's machine in ~1.7 s on M-series CPUs. The user's `secret` and `nullifier` never reach our server, the relayer, or anyone else — formally provable by inspecting `WebAssembly.Module.imports(...)` of the deployed `.wasm` artefact, which contains zero `fetch` / `XMLHttpRequest` / `WebSocket` symbols. Sandbox is the proof.
- **Composable as a CPI primitive** — any Anchor program can route SOL through `tidex6_verifier::deposit` and inherit the full privacy stack. The reference example [`tidex6-tip-jar`](https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x) shows the pattern in ~30 lines of Rust (built and OtterSec-verified against the historical v1 verifier — re-point it at the current verifier before reuse); payroll, royalty splitters, subscription protocols, and dark-pool DEX hooks follow the same pattern.
- **Built with Anchor 1.1.2.**

Full technical detail: [docs/release/PROJECT_BRIEF.md](docs/release/PROJECT_BRIEF.md).

---

## Technical stack

**Onchain (Anchor 1.1.2 program):**
- `anchor-lang = "=1.1.2"`
- `groth16-solana = "0.2"` — Groth16 verifier via `alt_bn128` syscalls
- `solana-poseidon = "4"` — native Poseidon syscall

**Offchain (client and prover):**
- `arkworks 0.5.x` — `ark-bn254`, `ark-groth16`, `ark-crypto-primitives`, `ark-r1cs-std`, `ark-relations`, `ark-ff`, `ark-ec`, `ark-serialize`, `ark-ed-on-bn254`
- `light-poseidon = "0.4"` — circom-compatible Poseidon, byte-for-byte equivalent to the onchain syscall
- `ml-kem = "0.2"`, `chacha20poly1305 = "0.10"` — post-quantum ML-KEM-768 memo encryption
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
- **[CEREMONY.md](docs/release/CEREMONY.md)** — the public trusted-setup ceremony: how to contribute, how to verify the chain, how finalization works.
- **[PR_CHECKLIST_PROOF_LOGIC.md](docs/release/PR_CHECKLIST_PROOF_LOGIC.md)** — Fiat-Shamir discipline checklist for every PR that touches proof logic.
- **[adr/](docs/release/adr/)** — Architecture Decision Records (seventeen ADRs covering commitment scheme, Merkle tree storage, nullifier storage, ElGamal implementation, non-upgradeable verifier, builder pattern vs macros, killer features, pool isolation, proving time budget, memo transport, relayer architecture, opaque note format, browser-side proof generation, post-quantum ML-KEM memo in a dedicated account, the two-layer confidential-amount architecture, configurable fee with private collection, and public ceremony finalization).

**Russian translations** of all of the above are available in [`docs/release/ru/`](docs/release/ru/).

---

## Workspace layout

```
tidex6/
├── crates/
│   ├── tidex6-core/             — commitments, nullifiers, Merkle tree, keys, Poseidon, DepositNote, pqc (ML-KEM-768)
│   ├── tidex6-circuits/         — arkworks R1CS: DepositCircuit, WithdrawCircuit<20> with relayer binding
│   ├── tidex6-indexer/          — offchain Merkle tree rebuild from on-chain DepositEvent logs
│   ├── tidex6-client/           — Rust SDK with builder pattern API (PrivatePool, DepositBuilder, WithdrawBuilder direct + via_relayer)
│   ├── tidex6-cli/              — developer CLI: `tidex6 keygen | deposit | withdraw | accountant`
│   ├── tidex6-prover-wasm/      — ADR-013: Rust prover compiled to WebAssembly (~1.7 s in-browser proof, secret never leaves the tab); excluded from workspace, built via wasm-pack
│   ├── tidex6-notifier-client/  — bitcode IPC client for the Telegram notifier microservice (shared between tidex6-web and the relayer service)
│   ├── tidex6-ui-shared/        — shared brand/css/template assets embedded via include_dir!; single source of truth for tidex6-web and the relayer status pages
│   └── tidex6-day1/             — Day-1..15 mainnet flight harnesses (Day-1 gates, Day-5 deposit, Day-11 withdraw, Day-12 negative, Day-13 accountant)
├── programs/
│   ├── tidex6-verifier/         — singleton non-upgradeable Anchor verifier program (deployed at CSDD31Zm…sJhcd)
│   ├── tidex6-tip-jar/          — ADR-013 reference CPI integration example (deployed + OtterSec-verified Apr 2026, deployment since closed)
│   ├── tidex6-confidential-amounts/  — early v0.3 Token-2022 Confidential-Transfers exploration (not on mainnet yet)
│   └── tidex6-caller/           — test CPI caller used by Day-1 gate 4
├── examples/
│   ├── private-payroll/         — flagship example: sender, receiver, accountant binaries
│   └── confidential-amount-demo/  — companion to programs/tidex6-confidential-amounts (v0.3 exploration)
├── brand/                        — logo assets, brandbook, Solscan PNGs
└── video/                        — pitch, demo, and weekly progress scripts

External repos (sibling path-deps, not part of this workspace):
  - tidex6-web        — production website at tidex6.com (5-microservice IPC architecture)
  - tidex6-relayer    — production relayer at relayer.tidex6.com (Axum HTTPS service, ADR-011)

Planned for v0.2, not yet in the workspace:
  - Proof of Innocence circuit + Association Set Provider (ADR-007 v2)
  - Relayer hardening: HSM keypair, multi-sig cold wallet, federated discovery
  - Ergonomic proc macros (`#[private_withdraw]` etc.) layered over the builder API (ADR-006)
  - Auditor key lifecycle — BIP32-style HD derivation for forward secrecy (extends ADR-014)
```

---

## License

Dual licensed under either **MIT** or **Apache-2.0** at your option.

No token, no SaaS tier. The Groth16 verifier is a permissionless, immutable primitive anyone can integrate; the hidden-amount pools are operated deployments with a configurable (possibly zero) per-operation fee.

---

## Contact

Issues and pull requests on GitHub.

*tidex6.rs — I grant access, not permission.*
