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

### Shielded Memo — отгружен 2026-04-15
- Зашифрованное memo до 256 байт прикреплённое к каждому депозиту
- ECDH key exchange на Baby Jubjub + AES-256-GCM
- Транспорт: SPL Memo Program инструкция в той же транзакции что и deposit (см. ADR-010)
- Один auditor на deposit, выбирается при отправке; расшифровывает тот, у кого есть `AuditorSecretKey`
- CLI: `tidex6 accountant scan` для использования без браузера
- Web: страница `/accountant/` на tidex6.com (спецификация в `docs/release/spec/ACCOUNTANT_WEB_SPEC.md`)

### Developer SDK
- `tidex6-core` — примитивы (Commitment, Nullifier, MerkleTree, Keys, Poseidon wrapper, ElGamal)
- `tidex6-circuits` — arkworks R1CS (DepositCircuit, WithdrawCircuit)
- `tidex6-verifier` — singleton Anchor program
- `tidex6-client` — builder-pattern API (ProofBuilder, TransactionBuilder, KeyManager, viewing-key import/export)
- `tidex6-cli` — четыре команды: `keygen`, `deposit`, `withdraw`, `accountant`

### DepositNote
- First-class `DepositNote` концепт в SDK
- Текстовый формат: `tidex6-note-v1:<denomination>:<secret>:<nullifier>`
- Передаваема offchain (файл, clipboard, зашифрованное сообщение, QR через библиотеку)

### Инфраструктура
- **Indexer** — in-memory, WebSocket подписка на события программы, offchain Merkle tree rebuild
- **Relayer** — референс HTTPS-сервис на `relayer.tidex6.com` (ADR-011): принимает withdraw-доказательства, offchain-проверяет их, подписывает и отправляет tx как on-chain fee-payer. Circuit связывает `(recipient, relayer_address, relayer_fee)` — front-runner не может перенаправить fee. Наша политика — `relayer_fee = 0` (мы платим tx fees как public good). Open-source; любой может запустить свой инстанс с любой fee policy.
- **Browser-side prover** — `tidex6-prover-wasm` компилирует Rust-прувер в WebAssembly. Браузер парсит deposit note локально и запускает Groth16-доказательство за ~1.7 с на M-серии CPU. `secret` и `nullifier` никогда не покидают вкладку пользователя. Развёрнут на `tidex6.com/app/`. Импорты WASM-модуля не содержат network APIs — конфайнмент доказуем формально, не на словах.

### Flagship примеры
- `examples/private-payroll/` — полный сценарий с binaries `sender`, `receiver`, `accountant`
- `programs/tidex6-tip-jar/` (развёрнут на mainnet [`5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`](https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x)) — третья сторона Anchor-программа, использует `tidex6_verifier::deposit` через CPI. Демонстрация: любой Solana-протокол (DAO payroll, NFT royalty splitter, subscription) может подключить tidex6 как privacy primitive в ~30 строках Rust.

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

### Stablecoin-пулы (USDT, USDC)
- Per-asset деплой: отдельный finalized verifier program под каждый mint, общий circuit и crypto core (`tidex6-circuits` + `tidex6-core` без изменений)
- **USDT первым**, **USDC вторым** — диктуется P2P-ликвидностью в целевых регионах (USDT доминирует в retail off-ramps Восточной Европы, Балкан, СНГ, ЮВ Азии; USDC доминирует в DeFi)
- Семейство пулов даёт пользователю выбор trust assumption: SOL pool (нет third-party freeze risk), USDT pool (самая широкая stablecoin ликвидность), USDC pool (DeFi-friendly)
- Каждый pool — свой finalized, non-upgradeable program, независимый от SOL верификатора `2qEm…cU9C`
- Открытая декларация риска `freeze_authority` для stablecoin-пулов в `security.md` — Circle и Tether сохраняют техническую возможность заморозить pool ATA; это свойство самого mint, а не tidex6

### Regulated pools (multi-auditor viewing keys)
- Расширение ADR-007 (Shielded Memo): от одного auditor per deposit к **N pool-level auditors**, включая опциональный regulator-класс
- Memo каждого депозита шифруется под N pubkeys через существующий envelope-механизм — любой обладатель соответствующего private key может расшифровать, никто не может блокировать или модифицировать
- Деплои пулов по audit-set: Black Pool (без аудитора), Montenegro Pool (viewing key у CBM + APML), EU Pool (MiCA-compliant local financial authority), Charity Pool (viewing key у NGO/аудитора) — один codebase, разные деплои
- Протокол даёт регулятору read-only путь к audit **без** передачи freeze authority, key escrow или права модификации. Cooperation through audit, not through backdoor
- Изменение только в offchain-шифровании — circuit не меняется, новый trusted setup не нужен, VK не меняется; существующий finalized верификатор продолжает использоваться всеми деплоями
- Слоган в действии: *«I grant access, not permission.»* Пользователь грантит read-access выбранному audit-set, кладя в выбранный pool; ни протокол, ни регулятор не получают permission блокировать

### Эргономичные macros
- `#[privacy_program]` — module-level macro
- `#[private_deposit]`, `#[private_withdraw]`, `#[with_auditor]` — function-level macros
- Auto-generation PDA структур, CPI вызовов, IDL интеграция
- Builder API остаётся — macros это сахар поверх, не замена

### Полная иерархия ключей
- Иерархический key split: spending key → full viewing key → incoming-only viewing key + nullifier key
- Incoming-only viewing key для disclosure уровня налоговой (видит депозиты, не видит spends)
- Wallet-adapter интеграция с основными Solana кошельками

### Жизненный цикл аудиторских ключей (forward secrecy через HD-derivation)
- BIP32-style hierarchical-deterministic auditor keys: фонд публикует один Master Public Key + chain code; donors локально вычисляют `epoch_pk = MPK + H(chain_code, epoch) · G`, фонд вычисляет соответствующий `epoch_sk = msk + H(chain_code, epoch)` только в момент открытия audit-окна
- Математически строгая изоляция эпох: утечка `epoch_sk_2026` раскрывает только депозиты 2026 года — `master_sk` и другие эпохи остаются криптографически защищены, дисциплина уничтожения ключей не требуется чтобы ограничить blast radius (утечка `epoch_sk` **не позволяет** derive sibling-эпохи в силу one-way property функции derivation hash)
- Стек уже имеется: Poseidon hash + Baby Jubjub ECDH + AES-GCM. Никакой новой криптографической математики, никаких pairing-схем, никакого academic-grade FSE/HIBE
- Backward-compatible: v0.1 однокорневые envelope-ключи продолжают расшифровываться без изменений; v0.2 добавляет derivation как opt-in upgrade path
- Закрывает v0.1 ограничение задокументированное в `security.md` §3A: утечка auditor secret больше не раскрывает «всю историю memo» — только одну эпоху, под которую этот ключ был выпущен

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

### Universal shared pool (multi-asset)
- Эволюция per-asset stablecoin-пулов из v0.2: один общий pool, принимающий несколько SPL-токенов через `mint`-encoded commitments — `commitment = Poseidon(secret, nullifier, mint, amount)`
- Один anonymity set между всеми интеграторами и всеми поддерживаемыми активами — anonymity растёт линейно с cross-asset adoption
- Per-asset generator points для unified balance accounting
- Требует новый circuit, новую VK, новый finalized verifier program (отдельно от v0.1 SOL верификатора и v0.2 per-asset верификаторов — все они продолжают работать)

### Переменные деноминации
- Range proofs внутри deposit circuit
- Pedersen commitments для сумм
- Новый circuit, новый trusted setup

### Performance & UX
- Persistent browser prover — держать десериализованный proving key в WASM-памяти между вызовами (сейчас десериализуется на каждое доказательство, ~30 % суммарного времени)
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
