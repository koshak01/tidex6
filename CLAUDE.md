# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

**Days 1–23 complete. ADR-012 (opaque note + envelope-encrypted memo) shipped and redeployed to mainnet 2026-04-25, commit `5c36804`, slot 415470767, executable hash `6a3c2afa9df95ae73e201e5416235b8a3dec3480f8950c42e02afc9eecb5244e`. OtterSec + on-chain PDA verification both pass. Verifier at `2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C`, upgrade authority held, not yet finalised.**

**Shielded Memo + Accountant shipped 2026-04-15** — see ADR-007 (feature commitment) and ADR-010 (transport mechanism). `tidex6-core::{elgamal,memo}`, `tidex6-client::AccountantScanner`, and `tidex6 accountant scan` are all live.

**Relayer + fee-in-circuit shipped 2026-04-24** — see ADR-011. `WithdrawCircuit<20>` now has five public inputs (`relayer_address` and `relayer_fee` added, binding rewrites of either field via the same Tornado-style constraint that already bound `recipient`). Verifier program gains a `relayer` account in the `Withdraw` context and a `relayer_fee` instruction argument; two SOL-transfer CPIs split the payout. Reference service crate `tidex6-relayer` (Axum HTTPS) accepts proofs, offchain-verifies them against the exact on-chain VK, and submits with its own keypair as fee-payer. SDK gets `WithdrawBuilder::via_relayer(url, pubkey)` and `direct()`; CLI gets `--relayer <url> --relayer-pubkey <pk>` / `--direct` flags.

- **Crypto core** (tidex6-core): Poseidon, newtype domain types with rejection sampling, append-only Merkle tree (Tornado-style filled/zero subtrees), `DepositNote` with text format, key hierarchy (SpendingKey + ViewingKey via Poseidon derivation).
- **Circuits** (tidex6-circuits): in-circuit Poseidon gadget byte-for-byte equivalent to `light-poseidon::new_circom`, `DepositCircuit`, `WithdrawCircuit<20>`, deterministic trusted setup via `gen_withdraw_vk`, full Groth16 → `groth16-solana` byte layout conversion.
- **Onchain verifier** (programs/tidex6-verifier): deployed at `2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C` on Solana devnet. Handles `init_pool`, `deposit`, `withdraw` (hardcoded WithdrawCircuit<20> VK, per-nullifier PDA double-spend protection, Tornado-style recipient binding, BN254 scalar reduction).
- **Indexer** (tidex6-indexer): `PoolIndexer::rebuild_tree` replays `tidex6-deposit:<leaf>:<commitment>:<root>` program logs into an offchain Merkle tree. Enables withdraws on non-empty pools.
- **Client SDK** (tidex6-client): `PrivatePool::connect`, `DepositBuilder::send`, `WithdrawBuilder::send` — the builder-pattern API from ADR-006 is real and used by the CLI internally.
- **CLI** (tidex6-cli): `tidex6 keygen | deposit | withdraw | accountant`, thin wrapper over the SDK. `deposit --auditor <pk> --memo <text>` attaches an encrypted memo; `accountant scan --identity <file>` decrypts every memo addressed to this identity's auditor key.
- **Flagship example** (examples/private-payroll): three binaries telling Lena's story — sender, receiver, accountant. `scripts/run_demo.sh` runs all three in a tmux session against live devnet.
- **Reference relayer** (tidex6-relayer): Axum HTTPS service, `POST /withdraw` accepts the Groth16 proof and submits with its own keypair; `GET /health`, `GET /stats` for monitoring/transparency. In-memory nullifier replay cache, offchain VK equivalence test (`tests/verify_roundtrip.rs`). Domain `relayer.tidex6.com`, Unix-socket behind nginx on the production deploy.
- **Live flight harnesses** (tidex6-day1): Day-1 kill gates, Day-5 deposit, Day-11 withdraw, Day-12 negative tests (front-run + double-spend), **Day-13 accountant** (3 memo-carrying deposits + end-to-end auditor scan).
- **Brand**: logos in `brand/`, pitch video script in `video/PITCH_VIDEO_SCRIPT.md`.
- **Website** (separate repo: tidex6-web): production site at **tidex6.com**. 5-microservice architecture (database, notifier, solana, ws_gateway, web_server). Deposit/withdraw via browser with Phantom wallet. Invite system with Telegram bot approval. tidex6-client used natively (not CLI subprocess).

**Remaining to ship:**
- Mainnet redeploy of `tidex6-verifier` with the ADR-011 circuit change and new VK (Day 5 of ADR-011 rollout). Existing Day-13 test deposits must be withdrawn under the old circuit first to clean the pool.
- Provision `relayer.tidex6.com` subdomain + nginx + systemd unit + hot wallet fund (Day 12 of ADR-011 rollout — user-side).
- Frontend replace of local signing with HTTPS POST to the relayer, in the separate `tidex6-web` repo (Day 11 of ADR-011 rollout).
- Record pitch video (2 min) and demo video (3 min) per scripts in `video/`.
- `solana program set-upgrade-authority --final` on the verifier (point of no return, executed last).
- Final Colosseum submission.

MVP deadline: Colosseum Frontier hackathon, **2026-05-11**.

Slogan: **"I grant access, not permission."**
Subtitle: **"The Rust-native privacy framework for Solana."**

## Reading order for a new session

Before touching any code, read in this order:

1. **`docs/release/THE_LEGEND.md`** — mission, philosophy, narrative identity. Don't skip — every design decision in the brief follows from this document.
2. **`docs/release/PROJECT_BRIEF.md`** — the engineering brief: architecture, data flow, workspace layout, dependency stack, developer experience.
3. **`docs/release/ROADMAP.md`** — now / next / later horizons.
4. **`docs/release/security.md`** — threat model, known limitations, vulnerability classes.
5. **`docs/release/adr/README.md`** — index of all nine architecture decision records.

Russian versions of all of the above are available in `docs/release/ru/`.

## Document structure

**Public documents** (`docs/release/`) — everything that goes to GitHub, grant committees, Colosseum judges:

```
docs/release/
├── THE_LEGEND.md                ← manifesto
├── PROJECT_BRIEF.md             ← engineering brief
├── ROADMAP.md                   ← now / next / later
├── security.md                  ← threat model
├── PR_CHECKLIST_PROOF_LOGIC.md  ← Fiat-Shamir discipline
├── adr/                         ← 9 ADRs + index
└── ru/                          ← Russian mirror of everything above
```

**Internal working documents** (`docs/` top level) — research, reviews, strategy Q&A. **Not public.** Contain references to other projects that must never be ported to public documents.

```
docs/
├── compass_artifact_wf-*.md          ← market research
├── REVIEW_AND_RECOMMENDATIONS.md     ← Claude Desktop review, round 1
└── STRATEGIC_QA_ROUND2.md            ← Claude Desktop review, round 2
```

## Principles (apply to every public document we write)

These principles were established during the paperwork phase and must be followed in every new public document:

1. **No competitor mentions.** Public documents in `docs/release/` describe what tidex6 does, not how it compares to other projects. No "unlike X", no "first to Y", no "where others failed", no tables of dead competitors. Describe the mechanism, not the positioning against anyone.
2. **No references to our own past projects either.** The same principle applies internally: the product stands on its own, without a lineage.
3. **Academic citations of cryptographic primitives are OK.** Groth16, Poseidon, ECDH, Pedersen, Fiat-Shamir — these are standard primitives and naming them is normal engineering writing, not competitive positioning.
4. **One exception:** `security.md` explicitly mentions the 2025 Token-2022 Confidential Transfers Fiat-Shamir incidents as *engineering lessons learned*. This is standard security practice — learning from known incidents — not marketing.
5. **Dual-language.** Every public document exists in English under `docs/release/` and Russian under `docs/release/ru/`. Both versions must stay synchronised.
6. **The slogan is used consistently.** `I grant access, not permission.` — header, footer, README, pitch. Never paraphrase.

## Flagship example

`examples/private-payroll/` — the story of **Lena**:

Lena lives in Amsterdam. Her elderly parents live in a country where bank transfers from Europe trigger automatic financial-intelligence flags. She supports them every month — medicine, groceries, utilities. With tidex6 she does what her grandmother did with cash in envelopes: sends dignity home, invisibly. At tax time her Dutch accountant Kai imports her viewing key, sees every transfer with memos, and prepares a compliant tax report.

Three binaries: `sender.rs` (Lena), `receiver.rs` (parents), `accountant.rs` (Kai). The demo video will show three terminal windows side by side — three actors with three different sets of capabilities and three different views of the same chain state.

This replaces every earlier story idea. Do not substitute banya, freelancers, or other metaphors.

## Actual workspace layout

```
tidex6/
├── crates/
│   ├── tidex6-core/       — Commitment, Nullifier, MerkleTree, Keys, Poseidon wrapper, DepositNote
│   ├── tidex6-circuits/   — arkworks R1CS: Poseidon gadget, DepositCircuit, WithdrawCircuit<20>, solana_bytes
│   ├── tidex6-indexer/    — PoolIndexer: replays on-chain DepositEvent logs into a fresh MerkleTree
│   ├── tidex6-client/     — Rust SDK with builder pattern (PrivatePool, DepositBuilder, WithdrawBuilder::{direct,via_relayer})
│   ├── tidex6-cli/        — keygen, deposit, withdraw, accountant (thin wrapper over the SDK)
│   ├── tidex6-relayer/    — ADR-011 reference HTTPS relayer: offchain Groth16 verify, tx signing, replay cache
│   └── tidex6-day1/       — live devnet flight harnesses (Day-1 gates, Day-5 deposit, Day-11 withdraw, Day-12 negative)
├── programs/
│   ├── tidex6-verifier/   — singleton non-upgradeable Anchor program, Groth16 via alt_bn128 syscalls
│   └── tidex6-caller/     — test CPI caller for Day-1 gate 4
├── examples/
│   └── private-payroll/   — flagship example: sender (Lena), receiver (parents), accountant (Kai)
├── brand/                  — logo assets (dark + monochrome PNGs)
└── video/                  — PITCH_VIDEO_SCRIPT.md, DEMO_VIDEO_SCRIPT.md

Planned for v0.2 (not yet in the workspace):
  - ElGamal + Baby Jubjub viewing-key machinery extensions (ADR-004, ADR-007)
  - Proof of Innocence circuit and Association Set Provider (ADR-007 v2)
  - Relayer hardening: HSM keypair, multi-sig cold wallet, federated discovery, non-zero fee policies
```

## Running the demo

Two ways to exercise the whole pipeline on devnet:

**CLI, solo:**

```bash
cargo run --release -p tidex6-cli -- keygen --force
cargo run --release -p tidex6-cli -- deposit --amount 0.5 --note-out /tmp/n.note
cargo run --release -p tidex6-cli -- withdraw --note /tmp/n.note --to <pubkey>
```

**Flagship three-actor demo (the video scene):**

```bash
cd examples/private-payroll
./scripts/run_demo.sh
```

The script splits one terminal into three tmux panes and runs
`sender` (Lena) → `receiver` (parents) → `accountant` (Kai)
sequentially against live devnet. Takes ~90 seconds from cold
cargo build.

## Architectural invariants

Fixed decisions. Changing any of these without explicit approval breaks several ADRs at once.

- **Curve:** BN254. The only curve with native Solana syscall support (`alt_bn128`). Approximately 100-bit security — documented in `security.md`.
- **Proof system:** Groth16. Verification via CPI into the singleton `tidex6-verifier` program, never embedded into integrator programs.
- **Hash:** Poseidon, circom-compatible parameters. Offchain uses `light-poseidon::Poseidon::<Fr>::new_circom(n)` exclusively. Never use `ark-crypto-primitives::sponge::poseidon` — parameters will not match the Solana syscall.
- **Commitment scheme (ADR-001):** `commitment = Poseidon(secret, nullifier)` only. Auditor tag and encrypted memo live as separate fields in `DepositEvent`, not inside the commitment. See ADR-001 for the full rationale — note that the original brief had two contradictory schemes; this ADR fixes that bug.
- **Merkle tree (ADR-002):** depth 20 (~1M capacity). Full tree offchain in the indexer. Onchain stores a ring buffer of the **last 30 roots** + a `next_leaf_index` counter.
- **Nullifier storage (ADR-003):** one PDA per used nullifier. Seeds `[b"nullifier", nullifier_hash]`, empty data, rent-exempt minimum.
- **ElGamal (ADR-004):** custom dual-curve implementation. BN254 G1 for onchain ciphertext, Baby Jubjub (`ark-ed-on-bn254`) for in-circuit operations. **Unaudited.** Isolated from the consensus path.
- **Verifier (ADR-005):** non-upgradeable. Locked with `solana program set-upgrade-authority --final` immediately after deployment. This is legally and cryptographically load-bearing — bugs cannot be patched post-deploy.
- **No proc macros in MVP (ADR-006):** builder pattern API instead. Macros are a v0.2 deliverable, built on top of the proven builder API.
- **Killer features (ADR-007):** Shielded Memo ships in MVP code; Proof of Innocence (association sets) ships in roadmap v0.2 — prominently positioned in pitch deck, not yet implemented.
- **Pool isolation (ADR-008):** per-program pool in MVP. Shared anonymity pool is a v0.3 target with the *network effect* framing: the more apps integrate tidex6, the stronger privacy becomes for all users.
- **Proving time (ADR-009):** Day-8 benchmark is mandatory. Acceptance threshold ≤30 seconds. If exceeded, reduce Merkle depth.
- **Compliance by user choice, not by backdoor:** disclosure keys are issued by the user, never by the developer or the protocol. There is no mandatory auditor, no mandatory relayer network, no key escrow.

## Dependency stack

Pinned in `docs/release/PROJECT_BRIEF.md §6`. Before adding any new dependency, check the list — anything outside it is an architectural decision requiring explicit approval.

**Onchain:** `anchor-lang = "=1.0.0"`, `anchor-spl = "=1.0.0"`, `groth16-solana = "0.2"`, `solana-poseidon = "4"`, `tidex6-core`.

**Offchain:** arkworks 0.5.x (`ark-bn254`, `ark-groth16`, `ark-crypto-primitives`, `ark-r1cs-std`, `ark-relations`, `ark-ff`, `ark-ec`, `ark-serialize`, `ark-ed-on-bn254`), `light-poseidon = "0.4"`, `anchor-client = "1.0"`, `solana-sdk = "4.0"`.

**Explicitly not in MVP:** no SP1, no RISC0, no SPL tokens (SOL only), no range proofs, no proc macros.

## Day-1 Validation Checklist (kill gate)

Before writing any production code, four tests must pass. If any fails, **stop and debug** — do not proceed:

1. **Poseidon equivalence** — offchain `light-poseidon::new_circom` and onchain `solana-poseidon` syscall hash the same input and produce byte-for-byte identical results.
2. **Groth16 pipeline smoke test** — trivial circuit proves, verifies through `groth16-solana` inside an Anchor test.
3. **alt_bn128 availability** — minimal program calling the syscalls runs on devnet with expected CU consumption.
4. **Anchor 1.0 CPI with proof data** — caller and callee programs exchange proof bytes as instruction data.

Full text: `docs/release/security.md §3`.

## Fiat-Shamir discipline

Every PR that touches proof logic, circuit definitions, transcript construction, or cryptographic primitives must complete `docs/release/PR_CHECKLIST_PROOF_LOGIC.md`. The checklist starts with **Rule 0**: *"Anything the prover touches goes into the transcript."*

Two-reviewer policy: author plus one independent reviewer must sign off on transcript construction before merge. This is non-negotiable — the 2025 Token-2022 CT incidents (referenced in `security.md §2.1`) are exactly the class of bug this checklist catches.

## Build / test / lint

Not configured yet — no `Cargo.toml` exists. Do not invent commands that do not exist. Once the workspace is bootstrapped, the expected flow is standard Rust (`cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt`) plus `anchor build` / `anchor test` for onchain programs. Update this section with the real commands after the workspace lands.

## Language and style

- **Public documentation** is in English under `docs/release/`. Russian translations live under `docs/release/ru/`.
- **Conversation with the user** in a Claude Code session is in Russian (global rule in `~/.claude/rules/common/general.md`).
- **Rust code** must follow the global Rust rules in `~/.claude/rules/rust/`: idiomatic imports, `thiserror` in library crates / `anyhow` in binaries, no `unwrap()` on production paths, newtype domain types instead of raw primitives, actor pattern over `Arc<Mutex<_>>` for shared mutable state.

## ADR index

All nine architecture decision records live in `docs/release/adr/`. Each is a short, focused document (Status / Date / Context / Decision / Consequences / Related):

- **ADR-001** — Commitment scheme: `Poseidon(secret, nullifier)` only
- **ADR-002** — Merkle tree offchain, root ring buffer onchain
- **ADR-003** — Nullifier storage: one PDA per nullifier
- **ADR-004** — ElGamal on BN254, custom dual-curve implementation
- **ADR-005** — Verifier program is non-upgradeable after deploy
- **ADR-006** — No proc macros in MVP, builder pattern instead
- **ADR-007** — Killer features: Shielded Memo (MVP) + Association Sets (v0.2)
- **ADR-008** — Per-program pool in MVP, shared pool in v0.3
- **ADR-009** — Proving time budget: Day-8 benchmark, 30s acceptance
- **ADR-010** — Memo transport via SPL Memo Program (not verifier redeploy)
- **ADR-011** — Relayer architecture: fee-in-circuit + reference service at relayer.tidex6.com

When a new architectural decision is made, write a new ADR before writing code that implements it.

## References

- **Primary (read first):** `docs/release/THE_LEGEND.md`, `docs/release/PROJECT_BRIEF.md`.
- **Planning:** `docs/release/ROADMAP.md`, `docs/release/adr/`.
- **Security:** `docs/release/security.md`, `docs/release/PR_CHECKLIST_PROOF_LOGIC.md`.
- **Repository README:** `README.md` (root of the repo, public-facing landing).
- **Global rules:** `~/.claude/rules/rust/` and `~/.claude/rules/common/` — style, imports, error handling, naming conventions.
