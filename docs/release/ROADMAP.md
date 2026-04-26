# tidex6 Roadmap

> Three horizons: what we ship now, what comes next, what we plan for later.
> The philosophy lives in [THE_LEGEND.md](THE_LEGEND.md).
> The engineering decisions behind each item live in [adr/](adr/).

---

## Now — v0.1 MVP (Colosseum Frontier, May 11 2026)

The minimum coherent system. Everything in this layer ships in working code, runs **live on Solana mainnet**, and is demonstrated end-to-end in one flagship example.

### Core protocol
- Shielded pool with fixed denominations (0.1 / 1 / 10 SOL)
- Groth16 verifier as a singleton, non-upgradeable Anchor program (CPI from integrator programs)
- Deposit / Withdraw flow via Groth16 zero-knowledge proofs
- Nullifier storage as one PDA per nullifier (anti double-spend)
- Offchain Merkle tree (depth 20, ~1M capacity) with onchain root ring buffer (last 30 roots)
- Local Phase 2 trusted setup ceremony, marked **DEVELOPMENT ONLY — not for real funds**

### Selective disclosure
- Per-deposit ElGamal auditor tag (BN254 G1 group + Baby Jubjub for in-circuit derivation)
- One-level viewing key (hierarchical derivation, simplified for MVP)
- Auditor scanning tool (CLI)
- Offchain key sharing (hex format)

### Shielded Memo — shipped 2026-04-15, redesigned 2026-04-25 (ADR-012)
- Envelope-encrypted memo up to 256 bytes attached to each deposit
- One AES-256-GCM ciphertext, two wrap-K slots: recipient (key derived from the note's secret material) and optional auditor (Baby Jubjub ECDH)
- Three valid modes: (memo + auditor) / (memo only, recipient-decryptable) / (anonymous deposit with placeholder envelope)
- Padded to a fixed 286-byte ciphertext block — every on-chain envelope has identical size, no length leak about plaintext
- Charset whitelist: Latin + Cyrillic only. Emoji and CJK rejected at SDK boundary
- CLI: `tidex6 accountant scan` for browser-less usage
- Web: `/accountant/` page on tidex6.com (spec in `docs/release/spec/ACCOUNTANT_WEB_SPEC.md`)

### Developer SDK
- `tidex6-core` — primitives (Commitment, Nullifier, MerkleTree, Keys, Poseidon wrapper, ElGamal)
- `tidex6-circuits` — arkworks R1CS (DepositCircuit, WithdrawCircuit)
- `tidex6-verifier` — singleton Anchor program
- `tidex6-client` — builder-pattern API (ProofBuilder, TransactionBuilder, KeyManager, viewing-key import/export)
- `tidex6-cli` — four commands: `keygen`, `deposit`, `withdraw`, `accountant`

### DepositNote
- First-class `DepositNote` concept in the SDK
- Opaque hex wire format (ADR-012): 132 lowercase hex chars, no `tidex6-` prefix, no embedded memo, no separators — looks like any other random base16 string when copy-pasted into a chat
- Offchain transferable (file, clipboard, encrypted message, QR via library)

### Infrastructure
- **Indexer** — in-memory, WebSocket subscription to program events, offchain Merkle tree rebuild
- **Relayer** — reference HTTPS service at `relayer.tidex6.com` (ADR-011): accepts withdraw proofs, offchain-verifies them, signs and submits the tx as the on-chain fee-payer. Circuit binds `(recipient, relayer_address, relayer_fee)` so front-runners cannot redirect the fee. Our policy is `relayer_fee = 0` — we pay tx fees for users as a public good. Open-source; anyone can run their own instance with any fee policy.
- **Browser-side prover** — `tidex6-prover-wasm` compiles the Rust prover to WebAssembly. The browser parses the deposit note locally and runs Groth16 proving in ~1.7 s on M-series CPUs; `secret` and `nullifier` never leave the user's tab. Deployed at `tidex6.com/app/`. The WASM module's import set contains zero network APIs — confinement is provable, not asserted.

### Flagship examples
- `examples/private-payroll/` — full scenario with `sender`, `receiver`, and `accountant` binaries
- `programs/tidex6-tip-jar/` (deployed at [`5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`](https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x)) — third-party Anchor program that uses `tidex6_verifier::deposit` via CPI. Demonstrates that any Solana protocol — DAO payroll, NFT royalty splitter, subscription protocol, dark-pool DEX hook — can adopt tidex6 as a privacy primitive in ~30 lines of Rust.

### Documentation
- Manifesto, README with Quick Start, architecture overview, security model, ADRs, this roadmap

### Engineering rules
- **Day-1 Validation Checklist** as a kill-gate before any production code
- **Fiat-Shamir discipline checklist** on every PR that touches proof logic
- Two-reviewer policy on cryptographic changes

---

## Next — v0.2 (Q3 2026)

Built on top of the MVP. Each item is designed in MVP architecture and implemented after the hackathon.

### Proof of Innocence
- Additional circuit: prove inclusion in a curated subset of deposits without revealing which deposit is yours
- Reference Association Set Provider (offchain service)
- Ragequit mechanism — public withdrawal if a user declines disclosure
- Compliance-compatible privacy without KYC

### Relayer hardening
- HSM-backed hot wallet
- Multi-sig cold wallet with scripted auto-top-up
- Federated relayer discovery (well-known endpoint listing active third-party relayers for client-side failover)
- Optional non-zero `relayer_fee` policy for operators that need to cover their own infrastructure cost

### Ergonomic macros
- `#[privacy_program]` — module-level macro
- `#[private_deposit]`, `#[private_withdraw]`, `#[with_auditor]` — function-level macros
- Auto-generation of PDA structures, CPI calls, IDL integration
- The builder API stays — macros are sugar on top, not a replacement

### Full key hierarchy
- Hierarchical key split: spending key → full viewing key → incoming-only viewing key + nullifier key
- Incoming-only viewing key for tax-office-level disclosure (sees deposits but not spends)
- Wallet-adapter integration for major Solana wallets

### Public trusted setup ceremony
- 10–20 independent contributors
- Public coordination via GitHub and IPFS
- Random beacon for finalization
- Launched as a community event

### Additional examples
*The reference `tidex6-tip-jar` CPI integration shipped in MVP. Next-tier examples:*
- `examples/private-donations/` — anonymous donor flow with cryptographically verified transparency reports
- `examples/private-voting/` — DAO governance with hidden ballots
- `examples/private-grants/` — research grant disbursement with audit trail

### Security
- External cryptographic audit (subject to grant funding)
- Bug-bounty programme

---

## Later — v0.3 and beyond (Q4 2026 +)

Strategic direction. Research and engineering bets that compound the MVP.

### Shared anonymity pool
- One pool, all integrators
- Anonymity set grows linearly with adoption
- Network effect: every new application strengthens privacy for every existing user
- Coordinated via a singleton shared-pool program

### Multi-asset support
- SPL tokens in addition to SOL
- Per-asset generator points for unified pool
- One pool, many assets, one anonymity set

### Variable denominations
- Range proofs inside the deposit circuit
- Pedersen commitments for amounts
- New circuit, new trusted setup

### Performance & UX
- Persistent browser prover — keep the deserialised proving key in WASM memory across calls (currently re-deserialised per proof, ~30 % of total time)
- GPU-accelerated proving on consumer hardware where feasible
- Mobile prover for small circuits

### Ecosystem
- Grants for integrators building on tidex6
- Educational materials (course modules, workshops)
- Research partnerships with academic groups working on privacy primitives

---

## What we will not do

- No token. No ICO. No SaaS tier. No paid service.
- No centralized operator. No protocol-level fees.
- No KYC.
- No backdoor of any kind. No key escrow. No recovery service.

We are a public good. The protocol earns adoption by being useful. Anything else is a distraction from the mission.

---

*tidex6.rs — I grant access, not permission.*
*The Rust-native privacy framework for Solana.*
