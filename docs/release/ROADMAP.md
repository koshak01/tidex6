# tidex6 Roadmap

> Three horizons: what we ship now, what comes next, what we plan for later.
> The philosophy lives in [THE_LEGEND.md](THE_LEGEND.md).
> The engineering decisions behind each item live in [adr/](adr/).

---

## Shipped — v0.1 MVP (Colosseum Frontier, May 11 2026)

The minimum coherent system. Everything in this layer ships in working code, runs **live on Solana mainnet**, and is demonstrated end-to-end in one flagship example.

### Core protocol
- Shielded pool with fixed denominations (0.1 / 1 / 10 SOL) — the original v0.1 SOL pool
- Groth16 verifier as a singleton, non-upgradeable Anchor program (CPI from integrator programs)
- Deposit / Withdraw flow via Groth16 zero-knowledge proofs
- Nullifier storage as one PDA per nullifier (anti double-spend)
- Offchain Merkle tree (depth 20, ~1M capacity) with onchain root ring buffer (last 30 roots)
- Local Phase 2 trusted setup ceremony, marked **DEVELOPMENT ONLY — not for real funds**

### Selective disclosure
- Per-deposit ML-KEM-768 auditor slot (post-quantum) sealed with ChaCha20-Poly1305 — the slot omits secret/nullifier, so an auditor can read but never spend (legacy v1 pool used ElGamal on BN254 G1 + Baby Jubjub)
- One-level viewing key (hierarchical derivation, simplified for MVP)
- Auditor scanning tool — both CLI (`tidex6 accountant scan`) and web UI at `tidex6.com/accountant/`
- Offchain key sharing (hex format)

### Shielded Memo — shipped 2026-04-15, post-quantum redesign (ADR-014, supersedes ADR-012)
- Sealed memo up to 256 bytes in a dedicated per-deposit memo account (not the DepositEvent)
- ML-KEM-768 (post-quantum, NIST FIPS 203) key encapsulation + ChaCha20-Poly1305 AEAD
- Two sealed slots: a recipient slot that seals the note (secret + nullifier), and an optional auditor slot that seals memo + metadata but OMITS secret/nullifier — an auditor can read but never spend
- Stealth delivery: the note is never handed to the recipient — they scan the chain with their own ML-KEM secret key and reconstruct the deposit
- Per-deposit revoke: the depositor can close a deposit's dedicated memo account, removing the sealed slots from chain state
- Charset whitelist: Latin + Cyrillic only. Emoji and CJK rejected at SDK boundary
- CLI: `tidex6 accountant scan` for browser-less usage
- Web: `/accountant/` page on tidex6.com (spec in `docs/release/spec/ACCOUNTANT_WEB_SPEC.md`)

### Developer SDK
- `tidex6-core` — primitives (Commitment, Nullifier, MerkleTree, Keys, Poseidon wrapper, pqc (ML-KEM-768 + ChaCha20-Poly1305); ElGamal legacy v1)
- `tidex6-circuits` — arkworks R1CS (DepositCircuit, WithdrawCircuit)
- `tidex6-verifier` — singleton Anchor program
- `tidex6-client` — builder-pattern API (ProofBuilder, TransactionBuilder, KeyManager, viewing-key import/export)
- `tidex6-cli` — four commands: `keygen`, `deposit`, `withdraw`, `accountant`

### DepositNote
- First-class `DepositNote` concept in the SDK
- Opaque hex wire format (ADR-012): 132 lowercase hex chars, no `tidex6-` prefix, no embedded memo, no separators — looks like any other random base16 string when copy-pasted into a chat
- Offchain transferable (file, clipboard, encrypted message, QR via library)
- Stealth delivery (ADR-014): the note need not be transferred at all — the recipient reconstructs it by scanning the chain with their own ML-KEM secret key

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

### Shipped after MVP (June–July 2026)
- **Two-layer privacy** (ADR-015): Token-2022 Confidential Transfers hidden-amount pools — wUSDC [`AYTRKmF8VBdqRWGZr9c6Mx582SRm2tbUEwMesFMhcPcU`](https://solscan.io/account/AYTRKmF8VBdqRWGZr9c6Mx582SRm2tbUEwMesFMhcPcU) and wUSDT [`QGPYpwyMe2xBTteFm3EBrHZZhVNuP8mZAvXjDm8QX2yh`](https://solscan.io/account/QGPYpwyMe2xBTteFm3EBrHZZhVNuP8mZAvXjDm8QX2yh) — live on **mainnet and devnet**. The Groth16 pool hides the *link*; confidential transfers hide the *amount*. Honest disclosure: the underlying stablecoin mints retain their issuers' `freeze_authority` — a property of the mint, not of tidex6.
- **Configurable per-operation fee** (ADR-016): the sender pays it on top (it may be zero), the recipient receives the exact amount, the quote is shown before signing — and the fee is **collected privately**, as a stealth note to the operator inside the same shielded pool.
- **Public trusted-setup ceremony infrastructure** (ADR-017), live at [ceremony.tidex6.com](https://ceremony.tidex6.com): browser contributions through our Rust prover compiled to WebAssembly (entropy never leaves the tab), full MPC verification per contribution, a public transcript anyone can download, a zero-trust `ceremony_verify` tool, and deterministic drand-beacon finalization + byte-reproducible VK extraction. The open step: gather contributions, finalize, and ship a fresh immutable verifier on the ceremony VK.
- **Regulated-pools code** (ADR-007 v2): N pool-level auditor slots per deposit, config-driven — activation pending.

---

## Next — v0.2 (Q3 2026)

Built on top of the MVP. Each item is designed in MVP architecture and implemented after the hackathon.

### Proof of Innocence
- Additional circuit: prove inclusion in a curated subset of deposits without revealing which deposit is yours
- Reference Association Set Provider (offchain service)
- Ragequit mechanism — public withdrawal if a user declines disclosure
- Compliance-compatible privacy without KYC

### Stablecoin pools (USDT, USDC) — **shipped**, see above
- Shipped in a stronger form than originally planned: instead of separate plain-token verifiers per mint, both stablecoins run as Token-2022 Confidential Transfers **hidden-amount** wrapped-mint pools (ADR-015) — the amount is hidden, not just the link
- Pool family still lets the user choose trust assumption: SOL pool (no third-party freeze risk) vs stablecoin pools (broadest liquidity, issuer `freeze_authority` honestly disclosed)

### Regulated pools (multi-auditor viewing keys)
- Extension of ADR-007 (Shielded Memo) from one auditor per deposit to **N pool-level auditors**, including optional regulator-class auditor
- Each deposit's memo is encrypted under N pubkeys via the existing envelope construction — any holder of a corresponding private key can decrypt, none can block or modify
- Pool deployments by audit-set: a Black Pool (no auditor), a Montenegro Pool (viewing key with CBM + APML), an EU Pool (MiCA-compliant local financial authority), a Charity Pool (NGO/auditor viewing key) — one codebase, distinct deployments
- The protocol gives the regulator a read-only audit path **without** ceding freeze authority, key escrow, or any modification right. Cooperation through audit, not through backdoor
- Offchain-only encryption change — no circuit modification, no new trusted setup, no new VK; the existing finalized verifier continues to be used by every deployment
- Slogan in practice: *"I grant access, not permission."* The user grants read-access to a chosen auditor set by depositing into a chosen pool; nobody — neither the protocol nor a regulator — gains permission to block

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

### Auditor key lifecycle (forward secrecy via HD derivation)
- BIP32-style hierarchical-deterministic auditor keys: fund publishes one Master Public Key + chain code; donors derive `epoch_pk = MPK + H(chain_code, epoch) · G` locally, fund derives the matching `epoch_sk = msk + H(chain_code, epoch)` only when the audit window opens
- Math-grade isolation between epochs: leaking `epoch_sk_2026` exposes only 2026 deposits — `master_sk` and other epochs remain mathematically uncompromised, no key-destruction discipline required to bound the blast radius (epoch_sk leaks **cannot** be used to derive sibling epochs by the one-way property of the derivation hash)
- Note: this HD-derivation math applies to the legacy v1 elliptic-curve envelope stack (Baby Jubjub ECDH + AES-GCM); the current pool seals envelopes with ML-KEM-768 (ADR-014), where key encapsulation does not support additive public-key derivation — the epoch-key design must be reworked for the ML-KEM stack before implementation
- Backward-compatible: v0.1 single-key envelopes continue to decrypt unchanged; v0.2 introduces the derivation as an opt-in upgrade path
- Bounds the v0.1 limit documented in `security.md` §3A: leak of an auditor secret no longer reveals "every past memo" — only the single epoch it was issued for

### Public trusted setup ceremony — **infrastructure shipped**, see above
- Live at [ceremony.tidex6.com](https://ceremony.tidex6.com): browser Rust-WASM contributions, public transcript, zero-trust chain verification, drand-beacon finalization tooling
- Remaining: gather 10–20+ independent contributions as a community event, announce the drand round, finalize, and deploy a fresh immutable verifier carrying the ceremony VK

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

### Universal shared pool (multi-asset)
- Evolution of the per-asset stablecoin pools shipped in v0.2: a single shared pool that accepts multiple SPL tokens through `mint`-encoded commitments — `commitment = Poseidon(secret, nullifier, mint, amount)`
- One anonymity set across all integrators and all supported assets — anonymity grows linearly with cross-asset adoption
- Per-asset generator points for the unified balance accounting
- Requires a new circuit, new VK, new finalized verifier program (separate from v0.1 SOL verifier and v0.2 per-asset verifiers, all of which continue to operate)

### Variable denominations
- Amount hiding is already live via the Token-2022 Confidential Transfers layer (see Shipped); this item now covers **in-circuit** amounts for the Groth16 pool itself
- Range proofs inside the deposit circuit, Pedersen commitments for amounts
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

- No token. No ICO. No SaaS tier.
- The verifier primitive takes no fee and has no operator — it is a permissionless, immutable program anyone can integrate. Operated pool deployments may charge a configurable per-operation fee; ours is always shown before signing and may be zero.
- No KYC.
- No backdoor of any kind. No key escrow. No recovery service.

We are a public good. The protocol earns adoption by being useful. Anything else is a distraction from the mission.

---

*tidex6.com — I grant access, not permission.*
*The Rust-native privacy framework for Solana.*
