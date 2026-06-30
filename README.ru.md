<p align="center">
  <img alt="tidex6" src="brand/logo/hat-solana.svg" width="220">
</p>

<h1 align="center">tidex6</h1>

<p align="center">
  <strong>I grant access, not permission.</strong><br>
  <em>Я даю доступ — не прошу разрешения.</em><br>
  <em>Rust-native фреймворк приватности для Solana.</em>
</p>

---

tidex6 — это Rust-native, open-source фреймворк, который позволяет Solana-разработчикам добавить полную приватность транзакций в свои Anchor-программы через небольшой SDK. Транзакции приватны по умолчанию — отправитель, получатель и сумма скрыты. Пользователи могут опционально поделиться viewing key с тем, кому доверяют (бухгалтер, аудитор, член семьи), чтобы избирательно раскрыть историю — на своих условиях.

**Статус:** полный MVP стек **в продакшене на Solana mainnet**. Verifier-программа [`2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C`](https://solscan.io/account/2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C) проверена OtterSec. Полный набор фичей — deposit, ZK-withdraw (Groth16 `WithdrawCircuit<20>` через `alt_bn128` syscalls), per-nullifier double-spend PDA, recipient-binding защита от front-run, **unlinkable withdraw через релаер** [`relayer.tidex6.com`](https://relayer.tidex6.com), opaque hex-ноты + envelope-шифрованные memo фиксированной длины, **генерация proof целиком в браузере через WebAssembly** (`tidex6-prover-wasm`, ~1.7 секунды на M-серии CPU, secret никогда не покидает вкладку пользователя), CLI `tidex6`, SDK `tidex6-client`, веб-приложение [tidex6.com](https://tidex6.com), флагманский demo `examples/private-payroll`, и **референс CPI-интеграция** [`5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`](https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x) (`tidex6-tip-jar`, ~30 строк Rust для подключения приватности к любой Anchor-программе) — всё провалидировано end-to-end на mainnet. MVP нацелен на **Colosseum Frontier hackathon, 2026-05-11**.

> **DEVELOPMENT ONLY.** Pre-audit, single-contributor trusted setup, hackathon-grade trust assumptions. Verifier `upgrade-authority` на момент публикации этого README ещё держится у автора и будет заблокирован командой `solana program set-upgrade-authority --final` непосредственно перед Colosseum submission. Не использовать для реальных средств. См. [`docs/release/security.md`](docs/release/security.md).

---

## Quick start — CLI

Три команды, ничего кроме mainnet-кошелька в `~/.config/solana/id.json`:

```bash
# Сгенерировать tidex6-идентичность (spending + viewing key).
cargo run --release -p tidex6-cli -- keygen

# Сделать приватный депозит 0.5 SOL в shielded pool.
cargo run --release -p tidex6-cli -- deposit \
    --amount 0.5 --note-out parents.note

# Погасить ноту в любой кошелёк-получатель. CLI восстанавливает
# offchain Merkle tree из истории чейна через индексер, генерирует
# Groth16 withdraw proof, отправляет в верификатор.
#
# По умолчанию — direct path: пользователь подписывает свою tx сам.
# Для полной unlinkability (ADR-011) добавь `--relayer` чтобы
# делегировать tx релаер-сервису, который подпишет и заплатит fee
# вместо пользователя:
#   --relayer https://relayer.tidex6.com \
#   --relayer-pubkey <relayer_hot_wallet_pubkey>
cargo run --release -p tidex6-cli -- withdraw \
    --note parents.note --to <recipient_pubkey>
```

## Quick start — SDK

Подключить shielded pool в свой Rust-проект пятью строками
через builder API `tidex6-client`:

```rust
use anchor_client::Cluster;
use tidex6_client::PrivatePool;
use tidex6_core::note::Denomination;

# fn demo(
#     payer: &solana_keypair::Keypair,
#     recipient: anchor_client::anchor_lang::prelude::Pubkey,
# ) -> anyhow::Result<()> {
let pool = PrivatePool::connect(Cluster::Mainnet, Denomination::OneSol)?;

// Депозит: получаем ноту чтобы передать получателю.
let (deposit_sig, note, _leaf_index) = pool.deposit(payer).send()?;
std::fs::write("parents.note", note.to_text())?;

// Withdraw: восстановить дерево, доказать, отправить.
// Default direct path — пользователь сам подписывает tx.
let withdraw_sig = pool
    .withdraw(payer)
    .note(note)
    .to(recipient)
    .send()?;

// Полная unlinkability через референс-релаер (ADR-011): keypair
// пользователя никогда не подписывает withdraw tx, релаер платит
// fee и становится on-chain payer'ом. Circuit связывает
// конкретный relayer pubkey, чтобы front-runner не подменил его
// в mempool.
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

## Запустить флагманский demo

[`examples/private-payroll`](examples/private-payroll/) — это
полная история Лены, отправляющей родителям ежемесячную поддержку,
со своим бухгалтером Кай, который собирает налоговый отчёт из
расшаренного scan-файла. Три бинарника — `sender`, `receiver`,
`accountant` — работают с live mainnet.

```bash
cd examples/private-payroll
./scripts/run_demo.sh
```

Скрипт делит один терминал на три tmux-панели и прогоняет весь
flow side-by-side — deposit → rebuild → prove → withdraw → отчёт —
менее чем за минуту.

---

## Архитектура кратко

- **Groth16** zero-knowledge доказательства на кривой **BN254**, верифицируемые onchain через нативные Solana `alt_bn128` syscalls — меньше 200 000 compute units на доказательство.
- **Poseidon** хеш-функция, параметры согласованы между offchain (`light-poseidon`) и onchain (`solana-poseidon`) компонентами.
- **Offchain Merkle tree** (глубина 20, ~1M ёмкости) с onchain ring buffer корней.
- **Per-deposit selective disclosure** через ElGamal auditor tags — пользователи выбирают кто что видит, по каждой транзакции.
- **Shielded memos** — envelope-зашифрованные сообщения до 256 байт прикреплённые к каждому депозиту, padded к фиксированной длине (нет утечки длины через chain), читаемые только владельцем viewing key и/или auditor key.
- **Non-upgradeable verifier** — основной proof verifier блокируется после deployment, поэтому пользователям не нужно доверять deployer'у навсегда.
- **Relayer unlinkability** — ADR-011: референс HTTPS-сервис на `relayer.tidex6.com` подписывает и отправляет withdraw-транзакции, поэтому кошелёк пользователя никогда не появляется on-chain как payer. Proof коммитит к конкретному relayer (public input), фронтраннер не может перенаправить fee. Fee-policy для референс-сервиса — ноль; платим за пользователей как public good. Любой может запустить свой релаер с любой fee.
- **Browser-side генерация proof** — `tidex6-prover-wasm` компилирует Rust prover в WebAssembly. Браузер парсит ноту локально, derive'ит `commitment` и `nullifier_hash` через in-WASM Poseidon, и запускает Groth16 целиком на машине пользователя за ~1.7 с на M-серии CPU. `secret` и `nullifier` не доходят до сервера, релаера или кого-либо ещё — формально проверяемо инспекцией `WebAssembly.Module.imports(...)` развёрнутого `.wasm` (zero `fetch` / `XMLHttpRequest` / `WebSocket` symbols). Sandbox — это и есть доказательство.
- **Композиция через CPI** — любая Anchor-программа может маршрутизировать SOL через `tidex6_verifier::deposit` и унаследовать весь приватный стек. Референс-пример [`tidex6-tip-jar`](https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x) живёт на mainnet, ~30 строк Rust; payroll, royalty splitters, subscription-протоколы, dark-pool DEX-хуки идут по тому же паттерну.
- **Построено на Anchor 1.0.**

Полный технический разбор: [docs/release/ru/PROJECT_BRIEF.md](docs/release/ru/PROJECT_BRIEF.md).

---

## Технический стек

**Onchain (Anchor 1.0 программа):**
- `anchor-lang = "=1.0.0"`
- `groth16-solana = "0.2"` — Groth16 verifier через `alt_bn128` syscalls
- `solana-poseidon = "4"` — нативный Poseidon syscall

**Offchain (client и prover):**
- `arkworks 0.5.x` — `ark-bn254`, `ark-groth16`, `ark-crypto-primitives`, `ark-r1cs-std`, `ark-relations`, `ark-ff`, `ark-ec`, `ark-serialize`, `ark-ed-on-bn254`
- `light-poseidon = "0.4"` — circom-compatible Poseidon, byte-for-byte эквивалентно onchain syscall
- `anchor-client = "1.0"`, `solana-sdk = "4.0"`

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
- **[adr/](docs/release/adr/)** — Architecture Decision Records (тринадцать ADRs покрывающих commitment scheme, Merkle tree storage, nullifier storage, ElGamal имплементацию, non-upgradeable verifier, builder pattern vs macros, killer features, pool isolation, proving time budget, memo transport, relayer architecture, opaque note format, browser-side proof generation).

Английские версии всего вышеперечисленного доступны в [`docs/release/`](docs/release/).

---

## Workspace layout

```
tidex6/
├── crates/
│   ├── tidex6-core/             — commitments, nullifiers, Merkle tree, keys, Poseidon, DepositNote, ElGamal
│   ├── tidex6-circuits/         — arkworks R1CS: DepositCircuit, WithdrawCircuit<20> с relayer-binding
│   ├── tidex6-indexer/          — offchain Merkle tree rebuild из on-chain DepositEvent логов
│   ├── tidex6-client/           — Rust SDK с builder pattern API (PrivatePool, DepositBuilder, WithdrawBuilder direct + via_relayer)
│   ├── tidex6-cli/              — developer CLI: `tidex6 keygen | deposit | withdraw | accountant`
│   ├── tidex6-prover-wasm/      — ADR-013: Rust prover скомпилированный в WebAssembly (~1.7 с in-browser proof, secret не покидает вкладку); вне основного workspace, собирается через wasm-pack
│   ├── tidex6-notifier-client/  — bitcode IPC client для Telegram-нотификатора (используется и tidex6-web, и релаер)
│   ├── tidex6-ui-shared/        — общие brand/css/template ассеты embed-нутые через include_dir!; единый источник для tidex6-web и status-страниц релаера
│   └── tidex6-day1/             — Day-1..15 mainnet flight harness (Day-1 gates, Day-5 deposit, Day-11 withdraw, Day-12 negative, Day-13 accountant)
├── programs/
│   ├── tidex6-verifier/         — singleton non-upgradeable Anchor verifier (deployed at 2qEmhLEn…nBcU9C)
│   ├── tidex6-tip-jar/          — ADR-013 референс CPI-интеграция (deployed at 5WohQRRz…Ui9b9x, OtterSec-verified)
│   ├── tidex6-confidential-amounts/  — ранний v0.3 эксперимент с Token-2022 Confidential Transfers (не на mainnet)
│   └── tidex6-caller/           — тестовый CPI caller для Day-1 gate 4
├── examples/
│   ├── private-payroll/         — флагманский пример: sender, receiver, accountant бинарники
│   └── confidential-amount-demo/  — companion для programs/tidex6-confidential-amounts (v0.3 explore)
├── brand/                        — лого-ассеты, brandbook, Solscan PNG'и
└── video/                        — pitch, demo, и weekly progress сценарии

Внешние репозитории (sibling path-deps, не часть этого workspace):
  - tidex6-web        — production-сайт на tidex6.com (5-микросервисная IPC-архитектура)
  - tidex6-relayer    — production-релаер на relayer.tidex6.com (Axum HTTPS, ADR-011)

Запланировано на v0.2 (ещё не в workspace):
  - Proof of Innocence circuit + Association Set Provider (ADR-007 v2)
  - Hardening релаера: HSM keypair, multi-sig cold wallet, federated discovery
  - Эргономичные proc-макросы (`#[private_withdraw]` и т.п.) поверх builder API (ADR-006)
  - Auditor key lifecycle — BIP32-style HD-derivation для forward secrecy (расширение ADR-012)
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
