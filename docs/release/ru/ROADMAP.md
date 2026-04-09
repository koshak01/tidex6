# Roadmap tidex6

> Три горизонта: что мы выпускаем сейчас, что приходит следующим, что планируем потом.
> Философия живёт в [THE_LEGEND.md](THE_LEGEND.md).
> Инженерные решения за каждым пунктом — в [adr/](adr/).

---

## Now — v0.1 MVP (Colosseum Frontier, 11 мая 2026)

Минимальная связная система. Всё в этом слое поставляется в работающем коде, запускается на devnet и демонстрируется end-to-end в одном flagship-примере.

### Базовый протокол
- Shielded pool с фиксированными деноминациями (0.1 / 1 / 10 SOL)
- Groth16 verifier как singleton, non-upgradeable Anchor program (CPI из программ интеграторов)
- Поток Deposit / Withdraw через Groth16 zero-knowledge proofs
- Хранение nullifier'ов как один PDA на каждый nullifier (анти double-spend)
- Offchain Merkle tree (глубина 20, ~1M ёмкости) с onchain root ring buffer (последние 30 корней)
- Локальный Phase 2 trusted setup ceremony, помечен **DEVELOPMENT ONLY — не для реальных средств**

### Selective disclosure
- Per-deposit ElGamal auditor tag (BN254 G1 group + Baby Jubjub для in-circuit derivation)
- Одноуровневый viewing key (упрощённая иерархическая деривация для MVP)
- Auditor scanning tool (CLI)
- Offchain передача ключей (hex format)

### Shielded Memo
- Зашифрованное memo до ~200 байт прикреплённое к каждому депозиту
- ECDH key exchange на Baby Jubjub + AES-256-GCM
- Расшифровывается только владельцем viewing key
- Application-layer фича — не часть ZK circuit

### Developer SDK
- `tidex6-core` — примитивы (Commitment, Nullifier, MerkleTree, Keys, Poseidon wrapper, ElGamal)
- `tidex6-circuits` — arkworks R1CS (DepositCircuit, WithdrawCircuit)
- `tidex6-verifier` — singleton Anchor program
- `tidex6-client` — builder-pattern API (ProofBuilder, TransactionBuilder, KeyManager, viewing-key import/export)
- `tidex6-cli` — три команды: `keygen`, `setup`, `scan`

### DepositNote
- First-class `DepositNote` концепт в SDK
- Текстовый формат: `tidex6-note-v1:<denomination>:<secret>:<nullifier>`
- Передаваема offchain (файл, clipboard, зашифрованное сообщение, QR через библиотеку)

### Инфраструктура
- **Indexer** — in-memory, WebSocket подписка на события программы, offchain Merkle tree rebuild
- **Relayer** — минимальный HTTP сервер, fee-payer abstraction

### Flagship пример
- `examples/private-payroll/` — полный сценарий с binaries `sender`, `receiver`, `accountant`

### Документация
- Манифест, README с Quick Start, обзор архитектуры, security model, ADRs, этот roadmap

### Инженерные правила
- **Day-1 Validation Checklist** как kill-gate перед любым production-кодом
- **Fiat-Shamir discipline checklist** на каждый PR затрагивающий proof logic
- Two-reviewer policy на криптографические изменения

---

## Next — v0.2 (Q3 2026)

Построено поверх MVP. Каждый пункт спроектирован в архитектуре MVP и реализуется после хакатона.

### Proof of Innocence
- Дополнительный circuit: доказать вхождение в курируемое подмножество депозитов, не раскрывая какой именно депозит твой
- Reference Association Set Provider (offchain сервис)
- Ragequit механизм — публичный withdrawal если пользователь отказывается от disclosure
- Compliance-compatible privacy без KYC

### Эргономичные macros
- `#[privacy_program]` — module-level macro
- `#[private_deposit]`, `#[private_withdraw]`, `#[with_auditor]` — function-level macros
- Auto-generation PDA структур, CPI вызовов, IDL интеграция
- Builder API остаётся — macros это сахар поверх, не замена

### Полная иерархия ключей
- Иерархический key split: spending key → full viewing key → incoming-only viewing key + nullifier key
- Incoming-only viewing key для disclosure уровня налоговой (видит депозиты, не видит spends)
- Wallet-adapter интеграция с основными Solana кошельками

### Публичный trusted setup ceremony
- 10–20 независимых контрибьюторов
- Публичная координация через GitHub и IPFS
- Random beacon для финализации
- Запущен как community event

### Дополнительные примеры
- `examples/private-donations/` — анонимный donor flow с криптографически верифицированными transparency-отчётами
- `examples/private-voting/` — DAO governance со скрытыми голосами
- `examples/private-grants/` — выплата research grants с audit trail

### Безопасность
- Внешний криптографический аудит (при условии grant funding)
- Bug-bounty программа

---

## Later — v0.3 и далее (Q4 2026+)

Стратегическое направление. Research и инженерные ставки которые компаундят MVP.

### Shared anonymity pool
- Один pool, все интеграторы
- Anonymity set растёт линейно с adoption
- Network effect: каждое новое приложение усиливает privacy для каждого существующего пользователя
- Координируется через singleton shared-pool program

### Multi-asset support
- SPL tokens в дополнение к SOL
- Per-asset generator points для unified pool
- Один pool, много активов, один anonymity set

### Переменные деноминации
- Range proofs внутри deposit circuit
- Pedersen commitments для сумм
- Новый circuit, новый trusted setup

### Performance & UX
- Browser WASM prover (proving в браузере, без server side)
- GPU-accelerated proving на consumer hardware где возможно
- Mobile prover для маленьких circuits

### Экосистема
- Гранты для интеграторов строящих на tidex6
- Образовательные материалы (модули курсов, workshops)
- Research-партнёрства с академическими группами работающими над privacy primitives

---

## Чего мы делать не будем

- Никакого токена. Никакого ICO. Никакого SaaS уровня. Никакого платного сервиса.
- Никакого централизованного оператора. Никаких protocol-level fees.
- Никакого KYC.
- Никакого backdoor любого вида. Никакого key escrow. Никакого recovery service.

Мы — public good. Протокол зарабатывает adoption тем, что он полезен. Всё остальное — отвлечение от миссии.

---

*tidex6.rs — I grant access, not permission.*
*Rust-native фреймворк приватности для Solana.*
