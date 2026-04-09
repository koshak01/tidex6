# tidex6

> **I grant access, not permission.**
>
> *The Rust-native privacy framework for Solana.*

---

tidex6 is a Rust-native, open-source framework that lets Solana developers add full transaction privacy to their Anchor programs through a small SDK surface. Transactions are private by default — sender, receiver, and amount are hidden. Users can optionally share a viewing key with someone they trust (an accountant, an auditor, a family member) to selectively disclose history, on their own terms.

**Status:** paperwork phase complete, code in progress. MVP targeted for **Colosseum Frontier hackathon, 2026-05-11**.

---

## Quick Start

Add privacy to an existing Anchor program in five lines of Rust:

```rust
use anchor_lang::prelude::*;
use tidex6::{PrivatePool, DepositNote};

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
}
```

Client side:

```rust
use tidex6::{PrivatePool, Denomination};

let pool = PrivatePool::connect(&rpc, my_program::ID).await?;

let note = pool
    .deposit(&wallet)
    .denomination(Denomination::OneSol)
    .with_memo("Invoice #3847")
    .with_auditor(accountant_viewing_key)
    .send()
    .await?;

note.save_to_file("./october_invoice.note")?;
```

---

## Architecture at a glance

- **Groth16** zero-knowledge proofs on the **BN254** curve, verified onchain via native Solana `alt_bn128` syscalls in under 200,000 compute units per proof.
- **Poseidon** hash function, parameter-aligned between offchain (`light-poseidon`) and onchain (`solana-poseidon`) components.
- **Offchain Merkle tree** (depth 20, ~1M capacity) with an onchain root ring buffer.
- **Per-deposit selective disclosure** via ElGamal auditor tags — users choose who sees what, per transaction.
- **Shielded memos** — encrypted notes up to ~200 bytes attached to each deposit, readable only by the viewing-key holder.
- **Non-upgradeable verifier** — the core proof verifier is locked after deployment, so users do not have to trust the deployer forever.
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

## Workspace layout (planned)

```
tidex6/
├── tidex6-core/       — commitments, nullifiers, Merkle tree, keys, Poseidon, ElGamal, DepositNote
├── tidex6-circuits/   — arkworks R1CS: DepositCircuit, WithdrawCircuit
├── tidex6-verifier/   — singleton non-upgradeable Anchor verifier program
├── tidex6-client/     — Rust SDK with builder pattern API
├── tidex6-cli/        — developer CLI: keygen, setup, scan
├── tidex6-indexer/    — in-memory indexer, offchain Merkle tree rebuild
├── tidex6-relayer/    — minimal HTTP relayer for fee abstraction
└── examples/
    └── private-payroll/ — flagship example
```

---

## License

Dual licensed under either **MIT** or **Apache-2.0** at your option.

This project is a public good. No token, no SaaS tier, no centralized operator.

---

## Contact

Issues and pull requests on GitHub.

*tidex6.rs — I grant access, not permission.*
