# Project Brief: tidex6.rs

> **The Rust-native privacy framework for Solana.**
>
> *I grant access, not permission.*

---

## TL;DR

tidex6 is a Rust-native, open-source framework that lets a Solana developer add full payment privacy to an Anchor program with a small, well-defined SDK surface. Transactions are private by default — sender, receiver, and amount are hidden. The user can optionally share a viewing key with someone they trust (an accountant, an auditor, a family member) to selectively disclose history, on their own terms, without compromising anyone else.

- **Target user:** Solana developers who want to ship a privacy-enabled application without a six-month ZK learning curve.
- **Delivery:** Rust crates + Anchor-friendly builder API + a pre-deployed verifier program + CLI tools + a flagship example application + documentation.
- **Timeline:** MVP submission to Colosseum Frontier hackathon by **2026-05-11**.
- **License:** MIT or Apache-2.0. Public goods positioning.
- **No token. No SaaS. No centralized operator.** See [ROADMAP.md](ROADMAP.md) section *"What we will not do"*.

The mission, philosophy, and ethical stance live in [THE_LEGEND.md](THE_LEGEND.md). This brief is the **engineering** document.

---

## 1. The Gap

The Solana zero-knowledge stack is now mature enough to build production privacy on top of it:

- `groth16-solana` provides Groth16 proof verification on Solana via the native `alt_bn128` syscalls in under 200,000 compute units per proof.
- `solana-poseidon` exposes a native Poseidon syscall on the BN254 scalar field, parameter-aligned with the standard `light-poseidon` Rust implementation.
- `arkworks 0.5` provides a complete Rust toolchain for Groth16 over BN254 — proving system, R1CS constraint synthesis, finite field arithmetic, serialization.
- `Anchor 1.0` is stable and the standard for Solana program development.

Despite this mature foundation, **a developer-facing privacy framework does not exist on Solana today.** Privacy applications exist as standalone end-user tools. Developers who want to embed privacy features inside their own Anchor programs have no library to call into. They have to either build the entire ZK stack from scratch or skip privacy entirely.

tidex6 fills this gap. It is a **library**, not an application. It is a **building block**, not a destination.

---

## 2. Vision

The full philosophy is in [THE_LEGEND.md](THE_LEGEND.md). The short version:

**Open Privacy.** Closed by default — no one sees transactions. Open by user choice — the user decides who sees what, when, and on what terms. The protocol enforces nothing about who uses it; it builds rails where honest behaviour is the shortest path.

The user is sovereign. The system honours that sovereignty cryptographically, not by trust.

---

## 3. Technical Heritage

tidex6 stands on standard cryptographic primitives:

- **Groth16** zero-knowledge proofs over the **BN254** elliptic curve, chosen for native Solana syscall support and proof size (~256 bytes) suitable for on-chain verification.
- **Poseidon** hash function with circom-compatible parameters, used both off-chain (`light-poseidon`) and on-chain (`solana-poseidon` syscall) with byte-for-byte equivalence.
- **R1CS** constraint synthesis via the arkworks ecosystem.
- **Hierarchical key derivation** — spending key, full viewing key, incoming-only viewing key, nullifier key.
- **Pedersen commitments** with **Merkle tree** inclusion proofs for the shielded set.
- **ElGamal encryption** on BN254 G1 for selective disclosure tags. Baby Jubjub (`ark-ed-on-bn254`) for in-circuit key derivation.
- **Association set proofs** as a roadmap item for v0.2 — allowing users to prove fund legitimacy without revealing which specific deposit is theirs.

These are standard building blocks of modern shielded-pool design. tidex6 combines them into a single Rust-native developer framework targeting Solana.

---

## 4. Architecture Overview

### 4.1 Components

```
DEVELOPER (uses our SDK)
│
│  use tidex6::PrivatePool;
│
│  let pool = PrivatePool::new(&ctx)
│      .denomination(LAMPORTS_PER_SOL)
│      .with_auditor(auditor_pubkey)
│      .build()?;
│
│  pool.deposit(&signer, secret, nullifier)?;
│
└─→ tidex6-client (Rust SDK)
    │
    ├── ProofBuilder
    ├── TransactionBuilder
    ├── KeyManager
    └── ViewingKey import / export
        │
        └─→ tidex6-core (shared primitives)
            │
            ├── Commitment
            ├── Nullifier
            ├── MerkleTree
            ├── Keys (SK / FVK / IVK / NK)
            ├── Poseidon wrapper
            └── ElGamal on BN254
                │
                └─→ tidex6-circuits (arkworks R1CS)
                    │
                    ├── DepositCircuit
                    └── WithdrawCircuit
                        │
                        ↓
                    SOLANA DEVNET / MAINNET
                    │
                    Pre-deployed:
                    ├── tidex6-verifier
                    │   (Groth16 verifier, singleton, non-upgradeable)
                    │
                    Developer-deployed:
                    └── Their own Anchor program
                        (uses tidex6-client SDK)
```

### 4.2 Data flow — private transfer

```
1. DEPOSITOR (Alice)
   ├── Locally: secret = random_32_bytes()
   ├── Locally: nullifier = random_32_bytes()
   ├── Locally: commitment = Poseidon(secret, nullifier)
   ├── Optionally: auditor_tag = ElGamal(auditor_pubkey, deposit_metadata)
   ├── Optionally: encrypted_memo = AES-GCM(ECDH-derived key, memo_text)
   └── Send to program: commitment, auditor_tag (opt), encrypted_memo (opt) + SOL

2. PROGRAM (uses tidex6-client SDK)
   ├── Receives commitment + transfers SOL into pool vault
   ├── Adds commitment to Merkle tree (off-chain via indexer)
   ├── Updates on-chain root ring buffer (last 30 roots)
   └── Emits DepositEvent { commitment, root, auditor_tag?, encrypted_memo? }

3. WITHDRAWER (Bob, possibly Alice with a fresh address)
   ├── Receives DepositNote off-chain (text format with secret + nullifier)
   ├── Indexer provides Merkle proof for the commitment
   ├── Generates Groth16 proof locally
   │   ├── Public inputs:  nullifier_hash, root, recipient
   │   ├── Private inputs: secret, nullifier, merkle_path
   │   └── Statement: "I know a commitment in the Merkle tree
   │                   whose nullifier hashes to nullifier_hash"
   └── Submits to program: proof + public inputs

4. PROGRAM
   ├── Verifies Groth16 proof via CPI to tidex6-verifier
   ├── Checks nullifier PDA does not exist (anti double-spend)
   ├── Creates nullifier PDA (marks nullifier as used)
   └── Transfers amount from vault to recipient

OBSERVER SEES:
   ─ Alice deposited into the pool.
   ─ A fresh address withdrew from the pool.
   ─ No link between the two events.
   ─ No access to amounts beyond the fixed denomination.
   ─ No access to the encrypted memo (unless they have the viewing key).
```

### 4.3 Commitment scheme

```
commitment = Poseidon(secret, nullifier)
```

Two ingredients only. Amount is implicit because of the fixed-denomination model — the program physically sees how much SOL was transferred, so it does not need to be inside the commitment. The auditor tag and encrypted memo are stored as **separate fields** in `DepositEvent`, not inside the commitment. This separation of concerns:

- Keeps the ZK circuit simple — fewer constraints, lower CU cost, smaller attack surface.
- Decouples the privacy layer (Merkle tree + nullifiers) from the disclosure layer (auditor tag + memo).
- A bug in the disclosure layer cannot compromise the privacy layer, and vice versa.

### 4.4 Merkle tree

- **Depth:** 20 (~1M commitments capacity, sufficient for MVP and well into v0.2)
- **On-chain storage:** ring buffer of the last 30 roots + a counter for the next leaf index
- **Off-chain storage:** the full tree, maintained by the indexer
- **Updates:** the indexer rebuilds the tree from `DepositEvent` logs and serves Merkle proofs to clients on demand
- **Concurrency:** because the program only stores roots and a counter, concurrent deposits do not race — the indexer linearizes them

### 4.5 Nullifier storage

One PDA per used nullifier:

```
seeds = [b"nullifier", nullifier_hash.as_ref()]
data  = empty (rent-exempt minimum, ~890 bytes → ~0.00089 SOL)
```

Anti-double-spend check: `try_create_pda`. If the PDA already exists, the withdrawal is rejected. If it does not exist, the PDA is created in the same instruction that processes the withdrawal.

### 4.6 Verifier program

`tidex6-verifier` is a **singleton, non-upgradeable** Anchor program deployed once on devnet (and later on mainnet). All integrator programs call into it via CPI for Groth16 proof verification. This approach:

- Saves bytecode space in every integrator program (the verifier is shared)
- Ensures consistent security properties across all integrators
- Provides legal protection — non-upgradeable code is harder to weaponize against developers

The verifier is locked with `solana program set-upgrade-authority --final` immediately after deployment.

---

## 5. Killer Features

### 5.1 Per-deposit selective disclosure

The user attaches an optional ElGamal-encrypted tag to each deposit. The tag carries deposit metadata (amount, timestamp, descriptor) encrypted under an auditor's public key. The auditor — and only the auditor — can decrypt by scanning chain events with their private key.

Properties:
- **Per-deposit granularity** — the user picks a different auditor (or no auditor) for each transaction
- **No on-chain coordination** — the auditor scans events off-chain, no protocol-level disclosure mechanism
- **No backdoor** — protocol developers cannot decrypt anything
- **Revocable in spirit** — the user simply stops attaching the auditor tag to future deposits; past disclosures cannot be undone (this is a fundamental property of any encryption-based disclosure system)

### 5.2 Shielded Memo

Each deposit can carry an encrypted memo of up to ~200 bytes. The memo is encrypted via ECDH key exchange on Baby Jubjub plus AES-256-GCM. Only the holder of the viewing key can decrypt.

Use cases:
- "Invoice #3847, January development work"
- "Monthly support — medicine + groceries"
- "Donation: legal defence fund"
- "Salary: October, contractor 12"

The memo is **not part of the ZK circuit**. It is an application-layer field stored in `DepositEvent`. This keeps the circuit simple and the memo flexible (no circuit changes when memo schema evolves).

### 5.3 Proof of Innocence (roadmap v0.2)

In v0.2, users will be able to prove that their funds belong to a curated subset of approved deposits without revealing which specific deposit is theirs. Curation is done by an off-chain Association Set Provider that scans publicly available data sources. Users who decline disclosure can ragequit via public withdrawal — they keep their funds, they lose privacy.

This is the compliance layer. It is the answer to *"how do you prove your funds are clean without KYC?"*

---

## 6. Tech Stack

### 6.1 On-chain (Anchor program)

```toml
[dependencies]
anchor-lang     = "=1.0.0"
anchor-spl      = "=1.0.0"   # for SPL token deposits in v0.3
groth16-solana  = "0.2"      # Groth16 verifier via alt_bn128 syscalls
solana-poseidon = "4"        # native Poseidon syscall
tidex6-core     = { path = "../tidex6-core" }
```

### 6.2 Off-chain (client and prover)

```toml
[dependencies]
# arkworks 0.5.x — coordinated batch release
ark-bn254              = "0.5"
ark-groth16            = "0.5"
ark-crypto-primitives  = { version = "0.5", features = ["r1cs", "crh", "merkle_tree", "sponge"] }
ark-r1cs-std           = "0.5"
ark-relations          = "0.5"
ark-ff                 = "0.5"
ark-ec                 = "0.5"
ark-serialize          = "0.5"
ark-ed-on-bn254        = "0.5"   # Baby Jubjub for in-circuit key derivation

light-poseidon         = "0.4"   # MUST match on-chain syscall byte-for-byte
                                 # Use Poseidon::<Fr>::new_circom(n) only.

anchor-client          = "1.0"
solana-sdk             = "3.0"

tidex6-core            = { path = "../tidex6-core" }
tidex6-client          = { path = "../tidex6-client" }
```

Pinned exact versions where compatibility is critical (`anchor-lang`). Strict version policy on `light-poseidon` to guarantee on-chain / off-chain hash equivalence.

### 6.3 What we are not adding to the MVP

- Proc-macro framework (`#[privacy_program]` etc) — designed for v0.2, the MVP uses a builder pattern API instead. See ADR-006.
- zkVM dependencies (SP1, RISC0) — the MVP targets pure arkworks Groth16. zkVM is a future escape hatch, not a current dependency.
- Multi-asset support — SOL only in MVP, SPL tokens in v0.3.
- Range proofs — fixed denominations only in MVP.

---

## 7. Workspace Layout

```
tidex6/
├── Cargo.toml                      # workspace
│
├── tidex6-core/                    # shared primitives
│   └── src/
│       ├── commitment.rs           # Commitment type, Poseidon wrapper
│       ├── nullifier.rs            # Nullifier type
│       ├── keys.rs                 # SpendingKey, ViewingKey (one-level for MVP)
│       ├── merkle.rs               # Merkle tree (off-chain) + root verification helpers
│       ├── elgamal.rs              # ElGamal on BN254 G1 + Baby Jubjub helpers
│       ├── note.rs                 # DepositNote (first-class concept)
│       ├── memo.rs                 # ECDH + AES-GCM helpers for shielded memo
│       └── lib.rs
│
├── tidex6-circuits/                # arkworks R1CS circuits
│   └── src/
│       ├── deposit.rs              # DepositCircuit
│       ├── withdraw.rs             # WithdrawCircuit (Merkle inclusion + nullifier)
│       └── lib.rs
│
├── tidex6-verifier/                # singleton non-upgradeable Anchor program
│   ├── Cargo.toml
│   └── programs/verifier/
│       └── src/lib.rs              # CPI-callable Groth16 verifier
│
├── tidex6-client/                  # Rust SDK (builder pattern, no macros)
│   └── src/
│       ├── pool.rs                 # PrivatePool builder
│       ├── proof.rs                # ProofBuilder
│       ├── transaction.rs          # TransactionBuilder
│       ├── keys.rs                 # KeyManager
│       ├── viewing.rs              # Viewing key import / export
│       └── lib.rs
│
├── tidex6-cli/                     # developer CLI (3 commands)
│   └── src/
│       ├── keygen.rs               # generate spending key + viewing key
│       ├── setup.rs                # local Phase 2 trusted setup
│       ├── scan.rs                 # auditor scans chain with viewing key
│       └── main.rs
│
├── tidex6-indexer/                 # in-memory indexer (WebSocket)
│   └── src/
│       ├── tree.rs                 # off-chain Merkle tree rebuild
│       ├── events.rs               # DepositEvent / WithdrawEvent listeners
│       └── main.rs
│
├── tidex6-relayer/                 # minimal HTTP relayer
│   └── src/
│       └── main.rs                 # POST /relay endpoint
│
├── examples/
│   └── private-payroll/            # flagship example (Lena's story)
│       ├── README.md
│       ├── src/
│       │   ├── lib.rs
│       │   └── bin/
│       │       ├── sender.rs       # depositor side
│       │       ├── receiver.rs     # withdrawer side
│       │       └── accountant.rs   # auditor side
│       └── scripts/
│           └── run_demo.sh
│
└── docs/
    ├── THE_LEGEND.md               # philosophy / mission
    ├── PROJECT_BRIEF.md            # this file
    ├── ROADMAP.md                  # now / next / later
    ├── security.md                 # threat model and known limitations
    ├── adr/                        # architecture decision records
    └── ru/                         # Russian translations of all the above
```

---

## 8. Developer Experience

### 8.1 Goal

A developer who already knows Anchor should be able to integrate privacy into their program in **under one hour and under ten lines of new code**, without learning ZK theory.

### 8.2 Code shape

The MVP uses a **builder pattern** SDK, not procedural macros. Macros (`#[privacy_program]`, `#[private_deposit]` etc) are designed in v0.2 architecture and intentionally cut from the MVP — see [ADR-006](adr/ADR-006-no-proc-macros.md).

Integrator program:

```rust
use anchor_lang::prelude::*;
use tidex6::PrivatePool;

declare_id!("...");

#[program]
pub mod my_program {
    use super::*;

    pub fn init_pool(ctx: Context<InitPool>) -> Result<()> {
        let _pool = PrivatePool::new(&ctx)
            .denomination(LAMPORTS_PER_SOL)
            .with_auditor(auditor_pubkey()?)
            .build()?;
        Ok(())
    }

    pub fn contribute(
        ctx: Context<Contribute>,
        secret: [u8; 32],
        nullifier: [u8; 32],
    ) -> Result<()> {
        ctx.accounts.pool.deposit(&ctx.accounts.signer, secret, nullifier)
    }

    pub fn withdraw(
        ctx: Context<Withdraw>,
        proof: tidex6::Proof,
        recipient: Pubkey,
    ) -> Result<()> {
        ctx.accounts.pool.withdraw(proof, recipient)
    }
}
```

Client side:

```rust
use tidex6::{DepositNote, PrivatePool, Denomination};

let pool = PrivatePool::connect(&rpc, my_program::ID).await?;

// Deposit
let note = pool
    .deposit(&wallet)
    .denomination(Denomination::OneSol)
    .with_memo("Invoice #3847")
    .with_auditor(accountant_viewing_key)
    .send()
    .await?;

// Save the note locally — it is the only way to spend
note.save_to_file("./notes/october_invoice.note")?;

// Later, withdraw to a fresh address
let withdrawal = pool
    .withdraw()
    .note(DepositNote::load_from_file("./notes/october_invoice.note")?)
    .recipient(fresh_address)
    .send()
    .await?;
```

The library handles: key derivation, commitment computation, Merkle proof generation, ZK proof generation, transaction assembly, fee abstraction via the relayer.

---

## 9. Flagship Example

`examples/private-payroll/` demonstrates the full flow through one concrete story.

**The story.** Lena lives in Amsterdam and works as a software engineer. Her elderly parents live in a country where bank transfers from Europe trigger automatic financial-intelligence-unit flags. She supports them every month — medicine, groceries, utilities. With tidex6 she does what her grandmother did with cash in envelopes: sends dignity home, invisibly. At tax time her Dutch accountant Kai imports her viewing key and sees every transfer with memos, prepares the tax filing, and the family-support deduction is preserved.

**What the example demonstrates.** Every MVP feature, end to end:

| Feature | Where it shows up |
|---|---|
| Fixed-denomination deposit | 10 deposits of 1 SOL each, monthly |
| Deposit notes off-chain | Lena sends notes to her parents via encrypted message |
| Shielded memo | "October support — medicine + groceries" |
| Per-deposit auditor tag | Each deposit tagged with Kai's viewing key |
| Withdraw with ZK proof | Parents withdraw to fresh wallets |
| Unlinkability | Observer cannot connect Lena to her parents |
| Viewing key export | Lena exports a hex viewing key, sends to Kai |
| Auditor scan | Kai runs `tidex6 scan --viewing-key lena.vk` and sees full history |
| Compliance preservation | Kai prepares Belastingdienst-acceptable tax report |

The example ships as three separate binaries — `sender.rs`, `receiver.rs`, `accountant.rs` — so the demo video can show three terminal windows side by side, three actors with three different sets of capabilities and three different views of the same chain state.

---

## 10. Roadmap (overview)

Three horizons, full detail in [ROADMAP.md](ROADMAP.md):

- **Now — v0.1 MVP (May 2026):** core shielded pool, selective disclosure, shielded memo, builder SDK, indexer, relayer, flagship example, local Phase 2 trusted setup.
- **Next — v0.2 (Q3 2026):** Proof of Innocence (association sets), ergonomic macros, full hierarchical key split, public trusted setup ceremony, additional examples, security audit.
- **Later — v0.3+ (Q4 2026 +):** shared anonymity pool, multi-asset support, variable denominations, browser WASM prover, ecosystem grants.

---

## 11. Security Posture

Full threat model and known limitations in [security.md](security.md). Highlights:

- **BN254 ~100-bit security level** — documented limitation. BN254 is chosen for native Solana syscall support; alternatives lose order-of-magnitude on verification cost.
- **arkworks "academic prototype" disclaimer** — acknowledged. arkworks is the de facto Rust ZK standard despite the disclaimer. Pinned versions, security advisories monitored.
- **Custom ElGamal on BN254** — written from scratch because no production-ready crate exists. Marked unaudited in code and docs. Isolated from the consensus path (privacy layer uses standard Groth16; ElGamal is application layer).
- **Local Phase 2 trusted setup** — MVP only. Marked DEVELOPMENT ONLY. Mainnet deployment requires the public ceremony scheduled for v0.2.
- **Fiat-Shamir discipline** — every PR touching proof logic goes through a dedicated transcript-construction checklist with two-reviewer policy. See [PR_CHECKLIST_PROOF_LOGIC.md](PR_CHECKLIST_PROOF_LOGIC.md).
- **Viewing-key compromise is not recoverable** — documented. Viewing keys are read-only, so compromise reveals history but does not enable theft.
- **Day-1 anonymity set is small** — documented. Per-program pool fragments anonymity; shared pool in v0.3 fixes this with a network effect.

---

## 12. Legal Posture

- **Immutable verifier.** `tidex6-verifier` is locked with `solana program set-upgrade-authority --final` immediately after deployment.
- **No revenue collection.** The protocol takes no fee from deposits or withdrawals.
- **No DAO governance.** No legal entity. No multisig with custodial powers.
- **No centralized operator.** The relayer is reference code, not a service. Integrators run their own relayers or use community ones.
- **Compliance by user choice.** Viewing keys live in the user's hands; the protocol cannot reveal anything the user has not chosen to reveal.
- **MIT or Apache-2.0** licence. Public goods. No commercial layer.

This posture is the legal expression of the philosophy in [THE_LEGEND.md](THE_LEGEND.md).

---

*tidex6.rs — I grant access, not permission.*
*The Rust-native privacy framework for Solana.*
*Public goods. MIT / Apache-2.0. No token. No centralized operator.*
