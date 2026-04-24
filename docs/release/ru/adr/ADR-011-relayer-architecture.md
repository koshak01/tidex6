# ADR-011: Архитектура релаера — fee внутри circuit + reference-сервис

**Статус:** Принят — перекрывает решение 2026-04-16 о переносе релаера в v0.2 (см. project memory)
**Дата:** 2026-04-24

> Предыдущее решение относило релаер к v0.2 на том основании, что польза (fee sustainability) не оправдывала стоимость изменения circuit в MVP-окне. После обзора у пользователя эта логика была отклонена: без релаера свойство `unlinkability` — то, ради чего вообще существует shielded-pool — незаметно ломается требованием on-chain fee-payer'а. Откладывать релаер = откладывать продукт.

## Контекст

Любая Solana-транзакция должна быть подписана хотя бы одним аккаунтом, который одновременно является fee-payer'ом. Сегодня `withdraw` подписывается аккаунтом `payer` в контексте `Withdraw` (`programs/tidex6-verifier/src/lib.rs` строка 354). На практике этот payer — либо сам получатель, либо кошелёк, пополненный получателем. В любом случае история этого on-chain pubkey коррелируется с адресом депозитора, который его фондировал — и вся пара deposit → withdraw перестаёт быть unlinkable.

ADR-001..010 построили shielded pool где:

- commitment скрывает `(secret, nullifier)` (ADR-001),
- Merkle tree скрывает позицию потраченного commitment'а (ADR-002),
- nullifier скрывает какой именно депозит был потрачен (ADR-003),
- зашифрованное memo скрывает audit trail (ADR-010).

Всё это бесполезно, если on-chain withdraw tx подписана кошельком, который публично получал средства от кошелька исходного депозитора. Единственный структурный фикс на fee-based chain — ввести третью сторону (релаер), которая платит комиссию и отправляет tx. Пользователь никогда не появляется on-chain как signer withdraw'а.

Три варианта:

1. **Без релаера (статус-кво).** Пользователь платит fee. Приватность скомпрометирована для любого нетривиального пользователя, потому что flow фондирования кошелька виден публично. Дешевле всего инженерно; худший продукт.
2. **Релаер как pay-through сервис, без binding в circuit.** Любой может relay'ить; tx не подписана пользователем. Но без binding в circuit front-runner в mempool переписывает отправленную транзакцию на свой адрес получения, и proof всё равно верифицируется — поля recipient/payer не связаны с proof. Класс атак уже пойман на этом проекте как Day-12 negative harness.
3. **Релаер с fee, связанным внутри withdraw circuit.** `relayer_address` и `relayer_fee` становятся дополнительными public inputs для `WithdrawCircuit<20>`. Groth16 proof валиден только для конкретного tuple `(recipient, relayer_address, relayer_fee)`, который prover закоммитил. Front-runner, переписавший любое из этих полей в отправленной tx, инвалидирует proof и теряет только compute.

## Решение

**Вариант 3. Релаер с fee, связанным внутри withdraw circuit, reference-реализация развёрнута на `relayer.tidex6.com`, с `relayer_fee = 0` как policy нашего референсного сервиса.**

Конкретно:

### Изменения в circuit (`crates/tidex6-circuits/src/withdraw.rs`)

- `WithdrawCircuit<DEPTH>` получает два новых public-input поля: `relayer_address: Option<Fr>` и `relayer_fee: Option<Fr>`.
- В `generate_constraints`:
  - Аллокировать оба через `FpVar::<Fr>::new_input(…)` **после** существующего `recipient_var`. **Порядок важен:** новые public inputs добавляются в конец, а не вставляются, чтобы on-chain и off-chain сериализация совпадали.
  - Связать каждый вырожденным квадратичным constraint той же формы, что существующий binding recipient: `let _relayer_address_squared = &relayer_address_var * &relayer_address_var;` и `let _relayer_fee_squared = &relayer_fee_var * &relayer_fee_var;`. Это не даёт arkworks'у оптимизировать аллокированный public input и заставляет prover'а commit'иться к конкретному значению — тот же Tornado-style binding что и у recipient.
- `WithdrawWitness` получает поля `relayer_address: &'a [u8; 32]` и `relayer_fee: &'a [u8; 32]` — оба уже в BN254 каноническом big-endian кодировании, ожидаемом `Fr::from_be_bytes_mod_order`.
- `prove_withdraw` возвращает `(Proof<Bn254>, [Fr; 5])` вместо `[Fr; 3]`. Порядок public inputs в массиве зафиксирован как `[merkle_root, nullifier_hash, recipient, relayer_address, relayer_fee]` и задокументирован в doc-комментарии.
- Сигнатура `verify_withdraw_proof` обновлена и принимает `&[Fr; 5]`.

### Регенерация verifying key (`crates/tidex6-circuits/src/bin/gen_withdraw_vk.rs`)

Код генератора не меняется — `setup_withdraw_circuit` автоматически работает с расширенным circuit, потому что `WithdrawCircuit::default()` значения приходят из того же `ConstraintSynthesizer` impl. Генератор производит:

- `programs/tidex6-verifier/src/withdraw_vk.rs` с `WITHDRAW_NR_PUBLIC_INPUTS = 5` и новый VK.
- `crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin` регенерирован.

Фиксированный seed `SETUP_SEED = 0x7715_ef25_d061_3517` сохраняется. Требование детерминизма: два независимых запуска на одном Rust toolchain производят байт-в-байт идентичный `withdraw_vk.rs`. Проверяется как CI-шаг перед mainnet-редеплоем.

### Изменения в программе верификатора (`programs/tidex6-verifier/src/lib.rs` и `pool.rs`)

- Инструкция `withdraw` получает новый аргумент `relayer_fee: u64`. `relayer_address` берётся из нового `relayer: UncheckedAccount<'info>` аккаунта в `Withdraw<'info>` — тот же паттерн, что использует существующий recipient. Не надо передавать адрес как raw-аргумент.
- `Withdraw<'info>` получает `pub relayer: UncheckedAccount<'info>` (writable, `#[account(mut)]`). Signer не требуется: relayer-аккаунт в этом контексте — просто адрес, куда уходит fee; тот кто подписывает tx — отдельный.
- `handle_withdraw` в `pool.rs`:
  - `require!(relayer_fee <= pool.denomination, Tidex6VerifierError::InvalidRelayerFee)`.
  - `recipient_fr = reduce_mod_bn254(&ctx.accounts.recipient.key().to_bytes())` как сегодня.
  - `relayer_fr = reduce_mod_bn254(&ctx.accounts.relayer.key().to_bytes())`.
  - `relayer_fee_fr = fr_from_u64_le(relayer_fee)` — новый хелпер, который пакует little-endian байты `u64` в 32-байтовый big-endian field element. То же кодирование, что использует off-chain prover.
  - `public_inputs = [merkle_root, nullifier_hash, recipient_fr, relayer_fr, relayer_fee_fr]` — пять записей, фиксированный порядок.
  - Groth16 verifier работает с `WITHDRAW_NR_PUBLIC_INPUTS = 5`.
  - При успехе: два system-program transfer'а с vault seeded-signer:
    1. `(denomination - relayer_fee) → recipient`
    2. `relayer_fee → relayer` (пропускается если ноль, чтобы сэкономить CU и избежать edge-case zero-value transfer'а)
- `WithdrawEvent` получает поля `relayer: Pubkey` и `relayer_fee: u64`, чтобы off-chain индексеры видели split.
- Формат log-линии меняется на `tidex6-withdraw:<denomination>:<nullifier_hex>:<relayer_pubkey_base58>:<relayer_fee>`. Парсер индексера обновляется и принимает оба варианта: legacy three-field и новый five-field — тот же dual-version паттерн, что ADR-010 ввёл для `tidex6-deposit`.
- Новая ошибка `Tidex6VerifierError::InvalidRelayerFee` с сообщением `"Relayer fee must not exceed the pool denomination."`.

### Референсный релаер-сервис (`crates/tidex6-relayer/`)

Новый крейт в workspace. Axum HTTP-сервис с тремя endpoint'ами:

- `POST /withdraw` — принимает `{proof, public_inputs, recipient, relayer_address, relayer_fee}`, проверяет что `relayer_address == RELAYER_PUBKEY_HARDCODED` и `relayer_fee == 0` (наша policy), запускает off-chain `ark_groth16::Groth16::verify` до submission чтобы отклонять невалидные proof'ы без траты on-chain fee, отправляет транзакцию подписанную релаер-keypair'ом.
- `GET /health` — liveness probe.
- `GET /stats` — transparency: текущий баланс hot-wallet в SOL, количество withdraw за 24ч, текущий rps. Никаких privacy-sensitive полей.

In-memory `DashMap<nullifier_hash, Instant>` с TTL один час отклоняет replay submission'ы до того как они попадают в RPC. Nginx на deploy-стороне обеспечивает rate-limiting per IP; сервис сам этого не делает.

### Client SDK (`crates/tidex6-client/src/withdraw.rs`)

`WithdrawBuilder` получает два взаимоисключающих метода:

- `pub fn via_relayer(self, url: impl Into<String>, relayer_pubkey: Pubkey) -> Self`
- `pub fn direct(self) -> Self`

Default для backward-совместимости — `direct` (существующее поведение). Пара констант:

```rust
pub const DEFAULT_RELAYER_URL: &str = "https://relayer.tidex6.com";
pub const DEFAULT_RELAYER_PUBKEY: Pubkey = /* заполняется релаер-деплоем, см. Day 12 */;
```

Когда используется `via_relayer`, `WithdrawBuilder::send` строит proof с `(relayer_pubkey, 0)` как последними двумя public inputs, отправляет proof + inputs по HTTPS в релаер, возвращает signature из ответа релаера. Keypair клиента ничего не подписывает — он существует только для генерации proof и derivation recipient pubkey.

### CLI (`crates/tidex6-cli/src/commands/withdraw.rs`)

Новые флаги:

- `--relayer <url>` (опциональный; default `DEFAULT_RELAYER_URL`).
- `--direct` (опциональный; отключает релаер-путь, пользователь платит свой fee; оставлен для отладки и для пользователей, предпочитающих минимальное доверие к референсному сервису).

### Философия: почему `relayer_fee = 0`

Референсный сервис ест ~5000-lamport tx fee из собственного hot-wallet баланса и ничего не берёт. Это не механизм монетизации. Это заявление о том, что референсная инфраструктура протокола предоставляется как public good. Circuit и верификатор построены так, чтобы поддерживать любой `relayer_fee > 0` — любой fork, конкурент или сторонний интегратор может поднять свой релаер и брать fee, передавая `relayer_fee > 0`. Потолок фонда hot-wallet'а в 0.5 SOL ограничивает worst-case потерю при компрометации keypair'а.

## Последствия

**Положительные:**

- **Unlinkability держится.** Withdraw-транзакции on-chain подписаны keypair'ом `relayer.tidex6.com`. Recipient pubkey виден (получает SOL), но нет on-chain связи обратно к кошельку депозитора. Полное обещание приватности shielded pool теперь operational.
- **Front-run protection архитектурна, а не процедурна.** Front-runner не может подменить `relayer_address` или `relayer_fee` в отправленной транзакции, потому что эти поля связаны внутри Groth16 proof. Класс атак закрыт by construction.
- **Будущие fee-модели не требуют изменения протокола.** Решение в v0.2 брать `relayer_fee = 0.001 SOL` на референсном сервисе — это изменение конфигурации сервиса, а не circuit или редеплой верификатора.
- **Интегратор-программы не затронуты.** CPI-сигнатура `withdraw` меняется, но интеграторы, зовущие через `tidex6-client`, видят только новые `via_relayer` / `direct` методы; builder сохраняет обратную совместимость.
- **Существующие депозиты остаются spendable.** Commitment'ы в пуле — `Poseidon(secret, nullifier)` — не изменились. Старые deposit-note работают под новым circuit; prover просто пакует два дополнительных public input. Миграция для пользователей с pre-ADR-011 note не нужна.

**Отрицательные:**

- **Редеплой верификатора.** ADR-010 заявил, что его редеплой будет последним до `solana program set-upgrade-authority --final`. Это утверждение теперь устарело: редеплой ADR-011 — последний. Upgrade authority сохраняется до Day 17 (Colosseum submission), потом блокируется.
- **Инвалидация VK.** Любой закэшированный off-chain proving key инвалидируется; все клиенты должны перегенерить PK локально из нового setup run. Тот же паттерн, что для любого другого изменения circuit-shape.
- **Instruction data растёт на 8 байт.** Один дополнительный `u64`-аргумент. Ничтожно.
- **Новый on-chain аккаунт.** Аккаунт `relayer` в `Withdraw<'info>` добавляет одну запись в обязательный список аккаунтов и один pubkey в каждую tx. ~32 байта на tx. Ничтожно.
- **Нагрузка на hot-wallet operations.** Кто-то должен мониторить SOL-баланс релаера и пополнять его из cold storage. Ручная процедура для MVP; автоматический multi-sig refill — v0.2+ item, отслеживается отдельно.
- **Доступность сервиса становится видимой протоколу концерном.** Если `relayer.tidex6.com` лежит, пользователи могут использовать `--direct` путь, но теряют unlinkability. Митигация — open-source релаер-крейт, любая третья сторона может поднять свой.

## Fiat-Shamir discipline (PR_CHECKLIST_PROOF_LOGIC.md)

Эта ADR затрагивает proof-logic и проходит `PR_CHECKLIST_PROOF_LOGIC.md` полностью.

Rule 0: всё, к чему прикасается prover, идёт в transcript. В Groth16 «transcript» это public-input vector; его расширение `relayer_address` и `relayer_fee` — именно механизм, связывающий эти значения. Если бы они были instruction-аргументами, но не public inputs, злонамеренный prover мог бы сгенерить proof для `recipient = X, relayer = Y` и проиграть его как `recipient = X, relayer = Z` — классический класс бага. Они именно public inputs, чтобы мутация инвалидировала proof.

Section 1 items:

- **Все public inputs absorbed.** Да — пять inputs, все появляются в `WithdrawCircuit::generate_constraints` (как `new_input` аллокации) и в on-chain массиве `public_inputs`, передаваемом в `Groth16Verifier`.
- **Domain separator.** VK circuit'а действует как domain separator в Groth16: proof, сгенерённый для этого VK, не верифицируется ни против какого другого VK. Изменение с 3 на 5 public inputs производит новый VK, так что cross-ADR proof replay предотвращён.

Section 2 — порядок transcript:

- **Фиксированный порядок:** `[merkle_root, nullifier_hash, recipient, relayer_address, relayer_fee]`. Задокументирован в doc-комментарии `prove_withdraw` и в `handle_withdraw` в `pool.rs`. Два места в коде, одна ADR — это spec.

Section 3 — count constraint'ов:

- **Delta:** +2 аллокации, +2 вырожденных квадратичных constraint'а (по одному на новый public input). Общее воздействие на compute — два R1CS constraint'а. Проверяется через `cargo test -p tidex6-circuits`, который логирует delta count'а.

Section 4 — negative tests:

- **Подмена `relayer_address`:** handler переписывает релаер-аккаунт, proof отклонён.
- **Подмена `relayer_fee`:** handler передаёт другое значение fee, чем prover committed, proof отклонён.
- **Симуляция front-run:** Day-12 harness расширен для substitution релаер-полей.
- **Zero-fee happy path:** CLI deposit, withdraw с `fee = 0`, recipient получает полную denomination.
- **Non-zero fee happy path:** синтетический тест с `fee = 0.001 SOL`, split подтверждён on-chain.

Two-reviewer policy: author (Claude от имени Koshak) и Koshak подписывают до mainnet-редеплоя. Никаких single-approval merge на proof-critical коде.

## План миграции

По дням детали в `/Users/koshak01/.claude/plans/nested-humming-harp.md`. Высокоуровневые фазы:

1. **Circuit + VK + обновление верификатора.** Изменения кода, unit-тесты, negative-тесты.
2. **Mainnet cleanup.** Withdraw существующих Day-13 test-депозитов под старым circuit, потом редеплой верификатора с новым VK.
3. **Релаер-крейт.** `crates/tidex6-relayer` с HTTP-сервисом, off-chain verify, replay protection.
4. **Client и CLI обновление.** `WithdrawBuilder::via_relayer`, `--relayer` флаг.
5. **Обновление frontend (`tidex6-web`).** Replace локального подписания на HTTPS POST в релаер.
6. **Deploy.** Поддомен `relayer.tidex6.com`, Unix-socket nginx proxy, systemd unit, фонд 0.5 SOL.
7. **Видео и документация.** Pitch, demo, Week-3, README, ROADMAP, CLAUDE.md — все обновлены под shipped релаер.
8. **Finalize.** `solana program set-upgrade-authority --final`, Colosseum submission.

## Связано

- **ADR-001** — commitment-схема. Не затронута этой ADR.
- **ADR-002** — Merkle tree storage. Не затронута.
- **ADR-003** — nullifier PDA. Не затронута.
- **ADR-005** — non-upgradeable верификатор. Редеплой этой ADR теперь последний перед `--final` lock. Утверждение ADR-010 о «последнем редеплое» перекрыто.
- **ADR-007** — killer features. `Shielded Memo` shipped в MVP; эта ADR поднимает релаер с v0.2-roadmap item в MVP, чтобы `unlinkability` присоединилось к selective disclosure как свойство MVP, а не обещание v0.2.
- **ADR-010** — транспорт memo. Релаер-сервис никак не взаимодействует с memo-payload'ами; deposit'ы несут memo, withdraw'ы — нет.
- `crates/tidex6-circuits/src/withdraw.rs` — circuit, получающий два новых public input.
- `crates/tidex6-circuits/src/bin/gen_withdraw_vk.rs` — регенератор VK, код не меняется, но производит новый VK.
- `programs/tidex6-verifier/src/lib.rs`, `programs/tidex6-verifier/src/pool.rs` — инструкция и handler, получающие `relayer` аккаунт, `relayer_fee` аргумент, второй transfer и `InvalidRelayerFee` ошибку.
- `programs/tidex6-verifier/src/withdraw_vk.rs` — регенерированный VK с `WITHDRAW_NR_PUBLIC_INPUTS = 5`.
- `crates/tidex6-client/src/withdraw.rs` — builder получает режимы `via_relayer` и `direct`.
- `crates/tidex6-cli/src/commands/withdraw.rs` — флаги `--relayer` и `--direct`.
- `crates/tidex6-relayer/` — новый крейт, HTTP-сервис.
- `docs/release/PR_CHECKLIST_PROOF_LOGIC.md` — discipline, которой эта ADR следует для circuit-изменения.
