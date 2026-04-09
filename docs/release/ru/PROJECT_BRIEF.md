# Project Brief: tidex6.rs

> **Rust-native фреймворк приватности для Solana.**
>
> *I grant access, not permission. — Я даю доступ, не прошу разрешения.*

---

## TL;DR

tidex6 — это Rust-native open-source фреймворк, который позволяет Solana-разработчику добавить полную приватность платежей в Anchor-программу через небольшой и хорошо определённый SDK. Транзакции приватны по умолчанию — отправитель, получатель и сумма скрыты. Пользователь может опционально поделиться viewing key с тем, кому доверяет (бухгалтер, аудитор, член семьи), чтобы избирательно раскрыть историю — на своих условиях, не компрометируя никого другого.

- **Целевой пользователь:** Solana-разработчики, которые хотят выпустить privacy-enabled приложение без шестимесячной кривой обучения ZK.
- **Поставка:** Rust crates + Anchor-friendly builder API + предразвернутая verifier-программа + CLI tools + flagship-пример + документация.
- **Таймлайн:** MVP submission на Colosseum Frontier hackathon до **2026-05-11**.
- **Лицензия:** MIT или Apache-2.0. Public goods позиционирование.
- **Без токена. Без SaaS. Без централизованного оператора.** См. [ROADMAP.md](ROADMAP.md), секция *"Чего мы делать не будем"*.

Миссия, философия и этическая позиция живут в [THE_LEGEND.md](THE_LEGEND.md). Этот brief — **инженерный** документ.

---

## 1. Gap

Solana zero-knowledge стек теперь достаточно зрелый чтобы строить production-приватность поверх него:

- `groth16-solana` обеспечивает Groth16 верификацию на Solana через нативные `alt_bn128` syscalls в пределах 200 000 compute units на доказательство.
- `solana-poseidon` экспонирует нативный Poseidon syscall на BN254 scalar field, parameter-aligned со стандартной Rust-имплементацией `light-poseidon`.
- `arkworks 0.5` предоставляет полный Rust toolchain для Groth16 над BN254 — proving system, R1CS constraint synthesis, finite field arithmetic, serialization.
- `Anchor 1.0` стабилен и является стандартом для разработки Solana программ.

Несмотря на этот зрелый фундамент, **developer-facing privacy фреймворк на Solana сегодня не существует.** Privacy приложения существуют как standalone end-user инструменты. Разработчики, которые хотят встроить privacy фичи внутрь своих Anchor-программ, не имеют библиотеки которую можно вызвать. Им приходится либо строить весь ZK стек с нуля, либо отказаться от privacy полностью.

tidex6 закрывает этот gap. Это **библиотека**, не приложение. Это **building block**, не destination.

---

## 2. Видение

Полная философия — в [THE_LEGEND.md](THE_LEGEND.md). Короткая версия:

**Open Privacy.** Закрыто по умолчанию — никто не видит транзакции. Открыто по выбору пользователя — пользователь решает кто видит, что и на каких условиях. Протокол не enforce'ит ничего о том, кто им пользуется; он строит рельсы где честное поведение — самый короткий путь.

Пользователь — суверен. Система чтит этот суверенитет криптографически, а не через доверие.

---

## 3. Технический фундамент

tidex6 стоит на стандартных криптографических примитивах:

- **Groth16** zero-knowledge доказательства над эллиптической кривой **BN254**, выбранной за нативную поддержку Solana syscalls и размер доказательства (~256 байт) подходящий для on-chain верификации.
- **Poseidon** хеш-функция с circom-совместимыми параметрами, используемая и off-chain (`light-poseidon`), и on-chain (`solana-poseidon` syscall) с byte-for-byte эквивалентностью.
- **R1CS** constraint synthesis через arkworks ecosystem.
- **Иерархическая деривация ключей** — spending key, full viewing key, incoming-only viewing key, nullifier key.
- **Pedersen commitments** с **Merkle tree** inclusion proofs для shielded set.
- **ElGamal encryption** на BN254 G1 для тегов selective disclosure. Baby Jubjub (`ark-ed-on-bn254`) для in-circuit деривации ключей.
- **Association set proofs** как roadmap элемент для v0.2 — позволяет пользователям доказать легитимность средств не раскрывая какой именно депозит их.

Это стандартные building blocks современного shielded-pool дизайна. tidex6 объединяет их в единый Rust-native developer фреймворк нацеленный на Solana.

---

## 4. Обзор архитектуры

### 4.1 Компоненты

```
РАЗРАБОТЧИК (использует наш SDK)
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
        └─→ tidex6-core (общие примитивы)
            │
            ├── Commitment
            ├── Nullifier
            ├── MerkleTree
            ├── Keys (SK / FVK / IVK / NK)
            ├── Poseidon wrapper
            └── ElGamal на BN254
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
                    └── Их собственная Anchor программа
                        (использует tidex6-client SDK)
```

### 4.2 Поток данных — приватный перевод

```
1. ОТПРАВИТЕЛЬ (Лена)
   ├── Локально: secret = random_32_bytes()
   ├── Локально: nullifier = random_32_bytes()
   ├── Локально: commitment = Poseidon(secret, nullifier)
   ├── Опционально: auditor_tag = ElGamal(auditor_pubkey, deposit_metadata)
   ├── Опционально: encrypted_memo = AES-GCM(ECDH-derived key, memo_text)
   └── Отправить в программу: commitment, auditor_tag (опц), encrypted_memo (опц) + SOL

2. ПРОГРАММА (использует tidex6-client SDK)
   ├── Получает commitment + переводит SOL в pool vault
   ├── Добавляет commitment в Merkle tree (off-chain через indexer)
   ├── Обновляет on-chain root ring buffer (последние 30 корней)
   └── Эмитит DepositEvent { commitment, root, auditor_tag?, encrypted_memo? }

3. ПОЛУЧАТЕЛЬ (родители Лены, или Лена со свежим адресом)
   ├── Получает DepositNote off-chain (текстовый формат с secret + nullifier)
   ├── Indexer предоставляет Merkle proof для commitment
   ├── Генерирует Groth16 proof локально
   │   ├── Public inputs:  nullifier_hash, root, recipient
   │   ├── Private inputs: secret, nullifier, merkle_path
   │   └── Утверждение: "Я знаю commitment в Merkle tree
   │                     чей nullifier хешируется в nullifier_hash"
   └── Отправляет в программу: proof + public inputs

4. ПРОГРАММА
   ├── Верифицирует Groth16 proof через CPI в tidex6-verifier
   ├── Проверяет что nullifier PDA не существует (анти double-spend)
   ├── Создаёт nullifier PDA (помечает nullifier как использованный)
   └── Переводит сумму из vault получателю

OBSERVER ВИДИТ:
   ─ Лена сделала депозит в pool.
   ─ Свежий адрес сделал withdraw из pool.
   ─ Никакой связи между двумя событиями.
   ─ Никакого доступа к суммам сверх фиксированной деноминации.
   ─ Никакого доступа к зашифрованному memo (если нет viewing key).
```

### 4.3 Commitment scheme

```
commitment = Poseidon(secret, nullifier)
```

Только два ингредиента. Amount имплицитен из-за модели фиксированных деноминаций — программа физически видит сколько SOL переведено, поэтому это не нужно класть внутрь commitment. Auditor tag и encrypted memo хранятся как **отдельные поля** в `DepositEvent`, не внутри commitment. Это разделение concerns:

- Держит ZK circuit простым — меньше constraints, ниже CU cost, меньше attack surface.
- Разделяет privacy слой (Merkle tree + nullifiers) от disclosure слоя (auditor tag + memo).
- Баг в disclosure слое не может скомпрометировать privacy слой, и наоборот.

### 4.4 Merkle tree

- **Глубина:** 20 (~1M commitments capacity, достаточно для MVP и хорошо в v0.2)
- **On-chain хранение:** ring buffer последних 30 корней + counter для следующего leaf index
- **Off-chain хранение:** полное дерево, поддерживается indexer'ом
- **Обновления:** indexer перестраивает дерево из логов `DepositEvent` и обслуживает Merkle proofs клиентам по требованию
- **Concurrency:** поскольку программа хранит только корни и counter, конкурентные depositы не race'ятся — indexer их линеаризует

### 4.5 Хранение nullifier'ов

Один PDA на использованный nullifier:

```
seeds = [b"nullifier", nullifier_hash.as_ref()]
data  = пусто (rent-exempt minimum, ~890 байт → ~0.00089 SOL)
```

Анти-double-spend проверка: `try_create_pda`. Если PDA уже существует — withdrawal отклонён. Если не существует — PDA создаётся в той же инструкции которая обрабатывает withdrawal.

### 4.6 Verifier program

`tidex6-verifier` — это **singleton, non-upgradeable** Anchor program развёрнутая один раз на devnet (а потом и на mainnet). Все integrator-программы вызывают её через CPI для Groth16 верификации. Этот подход:

- Экономит bytecode space в каждой integrator-программе (verifier shared)
- Обеспечивает консистентные security свойства для всех интеграторов
- Даёт юридическую защиту — non-upgradeable код труднее weaponize против разработчиков

Verifier блокируется через `solana program set-upgrade-authority --final` сразу после deployment.

---

## 5. Killer Features

### 5.1 Per-deposit selective disclosure

Пользователь прикрепляет опциональный ElGamal-зашифрованный тег к каждому депозиту. Тег несёт deposit metadata (сумма, timestamp, описание) зашифрованные под публичным ключом аудитора. Аудитор — и только аудитор — может расшифровать сканируя события chain'а своим приватным ключом.

Свойства:
- **Per-deposit granularity** — пользователь выбирает разного аудитора (или ни одного) для каждой транзакции
- **No on-chain coordination** — аудитор сканирует события off-chain, нет protocol-level disclosure механизма
- **No backdoor** — разработчики протокола не могут расшифровать ничего
- **Revocable in spirit** — пользователь просто перестаёт прикреплять auditor tag к будущим depositам; прошлые disclosures отменить нельзя (это фундаментальное свойство любой encryption-based disclosure системы)

### 5.2 Shielded Memo

Каждый депозит может нести зашифрованное memo до ~200 байт. Memo шифруется через ECDH key exchange на Baby Jubjub плюс AES-256-GCM. Только владелец viewing key может расшифровать.

Use cases:
- "Invoice #3847, январская разработка"
- "Ежемесячная поддержка — лекарства + продукты"
- "Donation: legal defence fund"
- "Зарплата: октябрь, contractor 12"

Memo **не часть ZK circuit**. Это application-layer поле хранящееся в `DepositEvent`. Это держит circuit простым а memo гибким (никаких изменений circuit при эволюции memo schema).

### 5.3 Proof of Innocence (roadmap v0.2)

В v0.2 пользователи смогут доказать что их средства принадлежат курируемому подмножеству одобренных депозитов не раскрывая какой именно депозит их. Курация делается off-chain Association Set Provider'ом который сканирует публично доступные источники данных. Пользователи которые отказываются от disclosure могут ragequit через публичный withdrawal — они сохраняют средства, теряют privacy.

Это compliance слой. Это ответ на *"как ты докажешь что твои средства чисты без KYC?"*

---

## 6. Tech Stack

### 6.1 On-chain (Anchor program)

```toml
[dependencies]
anchor-lang     = "=1.0.0"
anchor-spl      = "=1.0.0"   # для SPL token deposits в v0.3
groth16-solana  = "0.2"      # Groth16 verifier через alt_bn128 syscalls
solana-poseidon = "4"        # нативный Poseidon syscall
tidex6-core     = { path = "../tidex6-core" }
```

### 6.2 Off-chain (client и prover)

```toml
[dependencies]
# arkworks 0.5.x — координированный batch release
ark-bn254              = "0.5"
ark-groth16            = "0.5"
ark-crypto-primitives  = { version = "0.5", features = ["r1cs", "crh", "merkle_tree", "sponge"] }
ark-r1cs-std           = "0.5"
ark-relations          = "0.5"
ark-ff                 = "0.5"
ark-ec                 = "0.5"
ark-serialize          = "0.5"
ark-ed-on-bn254        = "0.5"   # Baby Jubjub для in-circuit key derivation

light-poseidon         = "0.4"   # ОБЯЗАН matchить on-chain syscall byte-for-byte
                                 # Использовать ТОЛЬКО Poseidon::<Fr>::new_circom(n).

anchor-client          = "1.0"
solana-sdk             = "3.0"

tidex6-core            = { path = "../tidex6-core" }
tidex6-client          = { path = "../tidex6-client" }
```

Зафиксированные точные версии где совместимость критична (`anchor-lang`). Строгая version policy на `light-poseidon` для гарантии on-chain / off-chain hash эквивалентности.

### 6.3 Что мы НЕ добавляем в MVP

- Proc-macro framework (`#[privacy_program]` и т.д.) — спроектировано в архитектуре для v0.2, MVP использует builder pattern API. См. ADR-006.
- Зависимости zkVM (SP1, RISC0) — MVP таргетит чистый arkworks Groth16. zkVM это будущий escape hatch, не текущая зависимость.
- Multi-asset support — только SOL в MVP, SPL tokens в v0.3.
- Range proofs — только фиксированные деноминации в MVP.

---

## 7. Workspace Layout

```
tidex6/
├── Cargo.toml                      # workspace
│
├── tidex6-core/                    # общие примитивы
│   └── src/
│       ├── commitment.rs           # Commitment type, Poseidon wrapper
│       ├── nullifier.rs            # Nullifier type
│       ├── keys.rs                 # SpendingKey, ViewingKey (одноуровневый для MVP)
│       ├── merkle.rs               # Merkle tree (off-chain) + helpers для верификации корней
│       ├── elgamal.rs              # ElGamal на BN254 G1 + Baby Jubjub helpers
│       ├── note.rs                 # DepositNote (first-class concept)
│       ├── memo.rs                 # ECDH + AES-GCM helpers для shielded memo
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
├── tidex6-client/                  # Rust SDK (builder pattern, без macros)
│   └── src/
│       ├── pool.rs                 # PrivatePool builder
│       ├── proof.rs                # ProofBuilder
│       ├── transaction.rs          # TransactionBuilder
│       ├── keys.rs                 # KeyManager
│       ├── viewing.rs              # Viewing key import / export
│       └── lib.rs
│
├── tidex6-cli/                     # developer CLI (3 команды)
│   └── src/
│       ├── keygen.rs               # генерация spending key + viewing key
│       ├── setup.rs                # локальный Phase 2 trusted setup
│       ├── scan.rs                 # аудитор сканирует chain с viewing key
│       └── main.rs
│
├── tidex6-indexer/                 # in-memory indexer (WebSocket)
│   └── src/
│       ├── tree.rs                 # off-chain Merkle tree rebuild
│       ├── events.rs               # DepositEvent / WithdrawEvent listeners
│       └── main.rs
│
├── tidex6-relayer/                 # минимальный HTTP relayer
│   └── src/
│       └── main.rs                 # POST /relay endpoint
│
├── examples/
│   └── private-payroll/            # flagship пример (история Лены)
│       ├── README.md
│       ├── src/
│       │   ├── lib.rs
│       │   └── bin/
│       │       ├── sender.rs       # сторона отправителя
│       │       ├── receiver.rs     # сторона получателя
│       │       └── accountant.rs   # сторона аудитора
│       └── scripts/
│           └── run_demo.sh
│
└── docs/
    ├── THE_LEGEND.md               # философия / миссия
    ├── PROJECT_BRIEF.md            # этот файл
    ├── ROADMAP.md                  # now / next / later
    ├── security.md                 # threat model и known limitations
    ├── adr/                        # architecture decision records
    └── ru/                         # русские переводы всего вышеперечисленного
```

---

## 8. Developer Experience

### 8.1 Цель

Разработчик который уже знает Anchor должен быть способен интегрировать privacy в свою программу за **меньше часа и меньше десяти строк нового кода**, без изучения ZK теории.

### 8.2 Форма кода

MVP использует **builder pattern** SDK, не процедурные macros. Macros (`#[privacy_program]`, `#[private_deposit]` и т.д.) спроектированы в архитектуре для v0.2 и намеренно вырезаны из MVP — см. [ADR-006](adr/ADR-006-no-proc-macros.md).

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

Сторона клиента:

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

// Сохрани note локально — это единственный способ потратить
note.save_to_file("./notes/october_invoice.note")?;

// Позже, withdraw на свежий адрес
let withdrawal = pool
    .withdraw()
    .note(DepositNote::load_from_file("./notes/october_invoice.note")?)
    .recipient(fresh_address)
    .send()
    .await?;
```

Библиотека обрабатывает: key derivation, commitment computation, Merkle proof generation, ZK proof generation, transaction assembly, fee abstraction через relayer.

---

## 9. Flagship Пример

`examples/private-payroll/` демонстрирует полный flow через одну конкретную историю.

**История.** Лена живёт в Амстердаме и работает software engineer'ом. Её пожилые родители живут в стране где банковские переводы из Европы триггерят автоматические флаги от financial intelligence unit. Она поддерживает их каждый месяц — лекарства, продукты, коммуналка. С tidex6 она делает то что её бабушка делала с наличными в конвертах: посылает достоинство домой, невидимо. В налоговую сезон её голландский бухгалтер Каi импортирует её viewing key и видит каждый перевод с memos, готовит налоговую декларацию, и family-support вычет сохранён.

**Что демонстрирует пример.** Каждую MVP фичу, end to end:

| Feature | Где появляется |
|---|---|
| Fixed-denomination deposit | 10 депозитов по 1 SOL каждый, ежемесячно |
| Deposit notes off-chain | Лена шлёт notes родителям через зашифрованное сообщение |
| Shielded memo | "October support — medicine + groceries" |
| Per-deposit auditor tag | Каждый депозит помечен viewing key Каi |
| Withdraw с ZK proof | Родители выводят на свежие кошельки |
| Unlinkability | Observer не может связать Лену с её родителями |
| Viewing key export | Лена экспортирует hex viewing key, шлёт Каi |
| Auditor scan | Каi запускает `tidex6 scan --viewing-key lena.vk` и видит полную историю |
| Сохранение compliance | Каi готовит Belastingdienst-приемлемый налоговый отчёт |

Пример поставляется как три отдельных binaries — `sender.rs`, `receiver.rs`, `accountant.rs` — чтобы demo video могло показать три terminal окна side by side, три actor'а с тремя разными наборами capabilities и тремя разными views на одно и то же chain state.

---

## 10. Roadmap (обзор)

Три горизонта, полная детализация в [ROADMAP.md](ROADMAP.md):

- **Now — v0.1 MVP (май 2026):** базовый shielded pool, selective disclosure, shielded memo, builder SDK, indexer, relayer, flagship пример, локальный Phase 2 trusted setup.
- **Next — v0.2 (Q3 2026):** Proof of Innocence (association sets), эргономичные macros, полная иерархия ключей, публичный trusted setup ceremony, дополнительные примеры, security audit.
- **Later — v0.3+ (Q4 2026 +):** shared anonymity pool, multi-asset support, переменные деноминации, browser WASM prover, ecosystem grants.

---

## 11. Security Posture

Полная threat model и known limitations — в [security.md](security.md). Highlights:

- **BN254 ~100-bit security level** — задокументированное ограничение. BN254 выбран за нативную поддержку Solana syscalls; альтернативы теряют order-of-magnitude на стоимости верификации.
- **arkworks "academic prototype" disclaimer** — признано. arkworks является de facto Rust ZK стандартом несмотря на disclaimer. Зафиксированные версии, security advisories мониторятся.
- **Custom ElGamal на BN254** — написан с нуля потому что нет production-ready крейта. Помечено как unaudited в коде и docs. Изолировано от consensus path (privacy слой использует стандартный Groth16; ElGamal — application layer).
- **Локальный Phase 2 trusted setup** — только для MVP. Помечен DEVELOPMENT ONLY. Mainnet deployment требует публичной ceremony запланированной на v0.2.
- **Fiat-Shamir discipline** — каждый PR затрагивающий proof logic проходит через специальный transcript-construction checklist с two-reviewer policy. См. [PR_CHECKLIST_PROOF_LOGIC.md](PR_CHECKLIST_PROOF_LOGIC.md).
- **Компрометация viewing-key не recoverable** — задокументировано. Viewing keys read-only, поэтому компрометация раскрывает историю но не позволяет красть.
- **Day-1 anonymity set малый** — задокументировано. Per-program pool фрагментирует anonymity; shared pool в v0.3 чинит это сетевым эффектом.

---

## 12. Legal Posture

- **Immutable verifier.** `tidex6-verifier` блокируется через `solana program set-upgrade-authority --final` сразу после deployment.
- **No revenue collection.** Протокол не берёт fee с depositов или withdrawals.
- **No DAO governance.** Никакого юридического лица. Никакого multisig с custodial powers.
- **No centralized operator.** Relayer — это reference code, не сервис. Интеграторы запускают свои собственные relayers или используют community ones.
- **Compliance by user choice.** Viewing keys живут в руках пользователя; протокол не может раскрыть ничего что пользователь сам не выбрал раскрыть.
- **MIT или Apache-2.0** лицензия. Public goods. Никакого коммерческого слоя.

Эта позиция — юридическое выражение философии из [THE_LEGEND.md](THE_LEGEND.md).

---

*tidex6.rs — I grant access, not permission.*
*Rust-native фреймворк приватности для Solana.*
*Public goods. MIT / Apache-2.0. Без токена. Без централизованного оператора.*
