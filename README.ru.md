# tidex6

> **I grant access, not permission.**
>
> *Я даю доступ — не прошу разрешения.*
>
> *Rust-native фреймворк приватности для Solana.*

---

tidex6 — это Rust-native, open-source фреймворк, который позволяет Solana-разработчикам добавить полную приватность транзакций в свои Anchor-программы через небольшой SDK. Транзакции приватны по умолчанию — отправитель, получатель и сумма скрыты. Пользователи могут опционально поделиться viewing key с тем, кому доверяют (бухгалтер, аудитор, член семьи), чтобы избирательно раскрыть историю — на своих условиях.

**Статус:** paperwork фаза завершена, код в разработке. MVP нацелен на **Colosseum Frontier hackathon, 2026-05-11**.

---

## Quick Start

Добавить приватность в существующую Anchor-программу за пять строк Rust:

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

Сторона клиента:

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

## Архитектура кратко

- **Groth16** zero-knowledge доказательства на кривой **BN254**, верифицируемые on-chain через нативные Solana `alt_bn128` syscalls — меньше 200 000 compute units на доказательство.
- **Poseidon** хеш-функция, параметры согласованы между off-chain (`light-poseidon`) и on-chain (`solana-poseidon`) компонентами.
- **Off-chain Merkle tree** (глубина 20, ~1M ёмкости) с on-chain ring buffer корней.
- **Per-deposit selective disclosure** через ElGamal auditor tags — пользователи выбирают кто что видит, по каждой транзакции.
- **Shielded memos** — зашифрованные заметки до ~200 байт прикреплённые к каждому депозиту, читаемые только владельцем viewing key.
- **Non-upgradeable verifier** — основной proof verifier блокируется после deployment, поэтому пользователям не нужно доверять deployer'у навсегда.
- **Построено на Anchor 1.0.**

Полный технический разбор: [docs/release/ru/PROJECT_BRIEF.md](docs/release/ru/PROJECT_BRIEF.md).

---

## Технический стек

**On-chain (Anchor 1.0 программа):**
- `anchor-lang = "=1.0.0"`
- `groth16-solana = "0.2"` — Groth16 verifier через `alt_bn128` syscalls
- `solana-poseidon = "4"` — нативный Poseidon syscall

**Off-chain (client и prover):**
- `arkworks 0.5.x` — `ark-bn254`, `ark-groth16`, `ark-crypto-primitives`, `ark-r1cs-std`, `ark-relations`, `ark-ff`, `ark-ec`, `ark-serialize`, `ark-ed-on-bn254`
- `light-poseidon = "0.4"` — circom-compatible Poseidon, byte-for-byte эквивалентно on-chain syscall
- `anchor-client = "1.0"`, `solana-sdk = "3.0"`

---

## Философия

Закрыто по умолчанию. Открыто по выбору пользователя. Протокол ничего не enforce'ит о том, кто им пользуется — он строит рельсы, где честное поведение это самый короткий путь. Пользователи, которые выбирают доказать свою легитимность, делают это тому, кого *они* выбрали, через ключ, который *они* держат. Никакого backdoor, никакого key escrow, никакого recovery service. У архитектуры есть сильное мнение о том, *как* можно пользоваться инструментом; у неё нет мнения о том, *кто* им пользуется.

Полный манифест: [docs/release/ru/THE_LEGEND.md](docs/release/ru/THE_LEGEND.md).

---

## Документация

Публичная документация живёт в [`docs/release/`](docs/release/) (английская) и [`docs/release/ru/`](docs/release/ru/) (русская):

- **[THE_LEGEND.md](docs/release/ru/THE_LEGEND.md)** — миссия, философия, принципы дизайна.
- **[PROJECT_BRIEF.md](docs/release/ru/PROJECT_BRIEF.md)** — технический brief: архитектура, data flow, workspace layout, developer experience.
- **[ROADMAP.md](docs/release/ru/ROADMAP.md)** — now / next / later, milestones поставок.
- **[security.md](docs/release/ru/security.md)** — threat model, известные ограничения, классы уязвимостей и mitigations.
- **[PR_CHECKLIST_PROOF_LOGIC.md](docs/release/ru/PR_CHECKLIST_PROOF_LOGIC.md)** — Fiat-Shamir discipline checklist для каждого PR который затрагивает proof logic.
- **[adr/](docs/release/ru/adr/)** — Architecture Decision Records (девять ADRs покрывающих commitment scheme, Merkle tree storage, nullifier storage, ElGamal имплементацию, non-upgradeable verifier, builder pattern vs macros, killer features, pool isolation, proving time budget).

Английские версии всего вышеперечисленного доступны в [`docs/release/`](docs/release/).

---

## Workspace layout (планируемый)

```
tidex6/
├── tidex6-core/       — commitments, nullifiers, Merkle tree, keys, Poseidon, ElGamal, DepositNote
├── tidex6-circuits/   — arkworks R1CS: DepositCircuit, WithdrawCircuit
├── tidex6-verifier/   — singleton non-upgradeable Anchor verifier program
├── tidex6-client/     — Rust SDK с builder pattern API
├── tidex6-cli/        — developer CLI: keygen, setup, scan
├── tidex6-indexer/    — in-memory indexer, off-chain Merkle tree rebuild
├── tidex6-relayer/    — минимальный HTTP relayer для fee abstraction
└── examples/
    └── private-payroll/ — flagship пример
```

---

## Лицензия

Двойная лицензия — либо **MIT**, либо **Apache-2.0** на ваш выбор.

Этот проект — public good. Никакого токена, никакого SaaS уровня, никакого централизованного оператора.

---

## Контакт

Issues и pull requests на GitHub.

*tidex6.rs — I grant access, not permission.*
*Я даю доступ — не прошу разрешения.*
