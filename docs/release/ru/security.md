# Security Model

> **Назначение:** threat model, известные ограничения, классы уязвимостей от которых защищаемся, и инженерный процесс который ловит ошибки, которые делают люди при написании zero-knowledge кода.
>
> **Аудитория:** security researchers, аудиторы, grant reviewers, интеграторы оценивающие tidex6 для production.
>
> *tidex6.rs — I grant access, not permission. — Я даю доступ, не прошу разрешения.*

---

## Scope этого документа

Этот документ покрывает **MVP** security posture. Элементы помеченные `v0.2` или позже ссылаются на [ROADMAP.md](ROADMAP.md).

Он **не** покрывает:

- Безопасность integrator программ построенных поверх tidex6 (каждый интегратор отвечает за безопасность своей программы).
- Безопасность runtime environment (ОС, кошелёк, браузер, сеть).
- Физическую безопасность устройств где хранятся ключи.

Он **покрывает**:

- Криптографические примитивы которые мы используем и их известные ограничения.
- Unaudited code paths и как мы их изолируем.
- Trusted setup posture для MVP vs позже.
- Инженерный процесс который ловит ошибки при написании ZK кода.
- Классы уязвимостей которые били похожие системы и как мы от них защищаемся.

---

## 1. Известные криптографические ограничения

### 1.1 BN254 — примерно 100-bit security

BN254 pairing-friendly эллиптическая кривая изначально оценивалась в 128 бит security. Последующие достижения в Number Field Sieve для discrete logarithms на pairing curves с низкой embedding degree (линия улучшений Kim–Barbulescu опубликованная в 2015 и уточнявшаяся с тех пор) снизили эту оценку до приблизительно **100 бит** security.

**Почему мы всё ещё используем BN254:**
- Это единственная эллиптическая кривая с нативной поддержкой Solana syscalls (`alt_bn128`).
- Верификация Groth16 proof на BN254 стоит меньше 200 000 compute units через `groth16-solana` крейт.
- Альтернативы (BLS12-381, BLS12-377) имеют более высокую security, но нет Solana syscalls, что подняло бы стоимость верификации на порядки и сделало onchain верификацию непрактичной.
- BN254 остаётся стандартом для широкой Ethereum-ecosystem ZK экосистемы, что означает наш стек выигрывает от shared tooling и shared scrutiny.

**Что пользователям нужно понимать:**
- Для краткосрочной privacy (дни, недели, месяцы) ~100-bit security более чем достаточно.
- Для долгосрочной конфиденциальности (10+ лет) пользователи должны быть осведомлены что достижения в NFS могут дальше ослабить BN254. Депозиты сделанные сегодня могут или не могут быть computationally непрозрачны в 2040.
- Миграция на более сильную кривую (например BLS12-381) отслеживается как roadmap item и станет feasible если и когда Solana добавит соответствующие syscalls.

### 1.2 arkworks "academic prototype" disclaimer

`arkworks-rs` экосистема — которая предоставляет нашу Groth16 имплементацию, R1CS constraint synthesis, finite field arithmetic, и curve operations — несёт явный disclaimer от своих мейнтейнеров:

> *"This repository contains an academic proof-of-concept prototype. NOT ready for production use."*

Несмотря на этот disclaimer, `arkworks` — de facto стандарт Rust ZK стека. Production системы по всей экосистеме зависят от него. 15.5M+ cumulative downloads на `ark-ec` только отражают это.

**Наша позиция:**
- Мы pin'им точные minor версии где совместимость критична.
- Мы мониторим arkworks security advisories и применяем upstream fixes оперативно.
- Мы не модифицируем arkworks source; используем его as-is.
- Мы acknowledge disclaimer публично здесь вместо того чтобы делать вид что его не существует.

### 1.3 Custom unaudited ElGamal на BN254

Production-ready Rust крейт для ElGamal encryption на BN254 не существует. Все основные Rust ElGamal крейты таргетят Curve25519 или Ristretto, которые несовместимы с нашим Groth16 circuit field и нашими Solana syscalls. Мы пишем свой ElGamal с нуля используя arkworks примитивы.

**Риски:**
- Криптографический код написанный без независимого review inherently рискован. Возможные классы багов включают timing side channels, malleability, edge cases на identity element, и ошибки encoding.

**Mitigations:**
- ElGamal имплементация живёт в `tidex6-core::elgamal` и изолирована от consensus path. Privacy слой (Merkle tree, nullifiers, Groth16 верификация) использует стандартные well-understood примитивы. Баг в нашем ElGamal коде может leak'нуть deposit metadata не тому пользователю который opt'нулся в disclosure — но не может скомпрометировать privacy пользователей которые не opt'нулись, и не может позволить кражу.
- Код помечен `unaudited` в module documentation, в README, и в этом документе.
- Независимый криптографический audit — предусловие для mainnet deployment.
- См. [ADR-004](adr/ADR-004-elgamal-bn254.md) для полного обоснования и dual-curve дизайна (BN254 G1 для onchain ElGamal, Baby Jubjub для in-circuit операций).

### 1.4 Local Phase 2 trusted setup — DEVELOPMENT ONLY

Groth16 proving system требует trusted setup ceremony для генерации proving и verifying ключей для каждого конкретного circuit. Если противник узнаёт "toxic waste" секретные числа использованные во время ceremony, он может forge arbitrary proofs и слить pool.

**MVP posture:**
- Phase 1 (универсальная, circuit-independent половина) переиспользуется из существующей публичной ceremony. Никакой новой работы не требуется.
- Phase 2 (circuit-specific) запускается **локально разработчиком** как single-contributor ceremony. Это быстро, практично, и отгружает MVP — но это значит что toxic waste для MVP circuits физически присутствовал на одной машине, и security зависит от того что эта машина не компрометирована.

**MVP circuits помечены `DEVELOPMENT ONLY — not for real funds` в коде и документации.** Verifier развёрнутый на devnet для MVP демонстрации приемлем для devnet; он **не** приемлем для mainnet.

**Post-MVP (v0.2 target):**
- Публичная multi-contributor ceremony с 10–20 независимыми участниками.
- Random beacon финализация.
- Публичное объявление, GitHub координация, IPFS distribution промежуточных вкладов.
- Mainnet verifier использует ключи из этой публичной ceremony, не из local MVP ceremony.

См. [ADR-005](adr/ADR-005-non-upgradeable-verifier.md) для взаимодействия с non-upgradeable verifier решением (как только verifier развёрнут с конкретными ключами, эти ключи нельзя подменить — новая ceremony означает новую verifier программу).

---

## 2. Классы уязвимостей от которых защищаемся

### 2.1 Incomplete Fiat-Shamir transcript (CRITICAL)

Zero-knowledge proofs использующие Fiat-Shamir transform генерируют challenges через хеширование transcript публичных значений. Если любое значение на которое prover может влиять пропущено из transcript до генерации challenge, prover может манипулировать challenge чтобы forge proofs.

Это не теоретика. В 2025 году два отдельных Fiat-Shamir бага были найдены в Token-2022 Confidential Transfers программе на Solana — апрельский инцидент (пропущенные algebraic components в transcript) и "Phantom Challenge" инцидент в июне (prover-controlled sub-challenge в sigma OR proof не был absorbed в Fiat-Shamir transcript, позволяя arbitrary proof forgery). Второй баг был достаточно серьёзен чтобы отключить Confidential Transfers программу на основном Solana feature set на epoch 805 пока конкурентный audit был организован.

Мы берём это как прямой инженерный урок: **наша собственная proof logic не иммунна к тому же классу ошибок**. Наши equality proofs, наши ElGamal relation proofs, и любая будущая OR композиция которую мы введём все имеют ту же форму что и код который провалился.

**Наша защита:**
- **Rule 0:** *Anything the prover touches goes into the transcript.* Это первая линия нашего PR checklist.
- Специальный Fiat-Shamir discipline checklist на каждый PR который модифицирует proof logic, circuits, или transcript construction. См. [PR_CHECKLIST_PROOF_LOGIC.md](PR_CHECKLIST_PROOF_LOGIC.md).
- Two-reviewer policy на криптографические изменения. Автор плюс один независимый reviewer должны sign off на transcript construction перед merge.
- Regression тесты: honest proof верифицируется, tampered public input отклоняется, reused nullifier отклоняется.

### 2.2 Poseidon parameter mismatch (HIGH)

tidex6 хеширует данные offchain в клиенте (для вычисления commitments и nullifier hashes) и onchain в программе (для валидации Merkle roots). Если offchain Poseidon параметры отличаются от onchain параметров хотя бы на одну round constant, offchain-computed commitments не будут matchить onchain-computed commitments и весь pool будет нерабочим.

Стандартный путь как это проваливается: использование `ark-crypto-primitives::sponge::poseidon` offchain (который приходит с hardcoded параметрами которые могут не matchить circom / Solana conventions) пока программа использует `solana-poseidon` syscall (который circom-compatible). Хеши отличаются молча. Интеграторы обнаруживают mismatch только когда их первый proof проваливает верификацию, к этому моменту значительное время потеряно.

**Наша защита:**
- Offchain Poseidon предоставляется исключительно через `light-poseidon::Poseidon::<Fr>::new_circom(n)`. Конструктор `new_circom` блокирует параметры на circom-compatible значения которые matchат `solana-poseidon` byte-for-byte.
- Day-1 MVP timeline имеет обязательный equivalence test: хешировать тот же input offchain и onchain, сравнить byte-for-byte. Если результат не matchит, остановить всё и дебажить перед написанием любого другого кода.
- Версия `light-poseidon` запинена в `Cargo.toml` с узким constraint чтобы auto-updates не могли молча изменить параметры.

### 2.3 Ослабление BN254 со временем (MEDIUM, long-term)

Покрыто в секции 1.1. Основная mitigation — документация и образование пользователей: пользователи должны знать что BN254 предлагает примерно 100 бит security сегодня, и что гарантии долгосрочной конфиденциальности зависят от того что кривая остаётся computationally сложной.

Вторичная mitigation — roadmap item мигрировать на более сильную кривую когда Solana добавит необходимые syscalls. До тех пор BN254 — лучший доступный вариант для нативной Solana ZK верификации.

### 2.4 Компрометация trusted setup (HIGH, mainnet only)

Покрыто в секции 1.4. Для MVP trusted setup явно помечен DEVELOPMENT ONLY и verifier работает только на devnet. Для mainnet риск смягчён публичной multi-contributor ceremony запланированной на v0.2.

Вторичная mitigation: даже если mainnet ceremony контрибьюторы collectively компрометированы, атакующий который узнаёт toxic waste может forge proofs но не может retroactively раскрыть содержимое прошлых депозитов. Privacy сохранена; только soundness proof system сломан. Это ограничивает ущерб средствами которые в pool во время атаки.

### 2.5 Баги в ElGamal имплементации (HIGH, disclosure path only)

Покрыто в секции 1.3. Баги в нашем custom ElGamal коде — application-layer и не компрометируют privacy core. Они, однако, могут leak'нуть deposit metadata не тому пользователю который opt'нулся в disclosure. Mitigation — pre-mainnet audit и явная маркировка кода как unaudited.

### 2.6 Доступность и честность indexer'а (OPERATIONAL)

Merkle tree commitments хранится offchain в indexer'е. Withdrawers нуждаются в indexer'е чтобы построить Merkle proof перед тем как они смогут withdraw.

**Честность:** indexer не может врать undetectably о состоянии дерева. Любой Merkle proof который он производит должен верифицироваться против onchain корня, который программа поддерживает в ring buffer. Злонамеренный indexer может в худшем случае отказаться обслуживать proofs; он не может их forge.

**Доступность:** злонамеренный или offline indexer может заблокировать withdrawals отказываясь обслуживать proofs. Mitigation: indexer — это reference code (`tidex6-indexer`), полностью детерминистичный, и любой может запустить свой. Протокол публикует инструкции для перестройки дерева из onchain `DepositEvent` логов. Для production интеграторам следует запускать свой собственный indexer или использовать community-run multi-indexer fallback.

См. [ADR-002](adr/ADR-002-merkle-tree-storage.md) для полного обоснования.

### 2.7 Компрометация viewing key (LIMITED)

Если viewing key пользователя утёк, все прошлые депозиты зашифрованные под этим ключом становятся видимы тому кто держит утёкший ключ. Ciphertexts уже onchain; viewing key разблокирует их retroactively и способа "отозвать" его нет.

**Важно:** viewing keys **read-only**. Утёкший viewing key раскрывает историю атакующему но не позволяет атакующему тратить средства. Spending key — это отдельное значение, сгенерированное и удерживаемое независимо.

**Mitigations:**
- С viewing keys нужно обращаться с той же заботой что и с налоговой декларацией — делиться только с доверенными сторонами, хранить encrypted at rest, передавать через encrypted каналы.
- Пользователи которым нужно ротировать свою disclosure posture могут просто прекратить прикреплять auditor tag к будущим депозитам. Старый утёкший ключ раскрывает старые депозиты; новые депозиты защищены новым viewing key ещё не shared.
- Wallet-level управление viewing key — v0.2 roadmap item (интеграция с основными Solana кошельками для безопасного хранения и selective sharing).

### 2.8 Anonymity set в день один (OPERATIONAL)

Shielded pool настолько анонимен насколько количество депозитов он содержит. В день один MVP deployment любой один pool имеет ноль депозитов. Ранние пользователи будут withdraw из pool содержащего маленькое количество commitments, и anonymity которую они получают соответственно ограничена.

**Mitigations и честность:**
- Это inherent свойство per-program pools и признано в pitch и в flagship примере. См. [ADR-008](adr/ADR-008-pool-isolation.md).
- v0.3 shared anonymity pool архитектура адресует это через network effect: все интеграторы делают вклад депозитов в одно общее дерево, и anonymity растёт линейно с adoption.
- Для MVP интеграторам следует устанавливать реалистичные ожидания со своими пользователями: flagship `private-payroll` пример делает ясным что anonymity в маленьких pools слабый, и предлагает ждать адекватной глубины перед тем как полагаться на pool для чувствительных переводов.

---

## 3. Day-1 Validation Checklist

Перед написанием любого production кода, следующие четыре теста должны пройти. Это **kill gate** — если любой из этих проваливается, остановиться и дебажить перед продолжением. MVP timeline предполагает что эти проходят в первые два дня.

```bash
# 1. Poseidon compatibility test
#    Offchain (Rust, используя light-poseidon::new_circom) и
#    onchain (Solana syscall) хешируют тот же input. Байты должны matchить точно.

# 2. Groth16 pipeline smoke test
#    Написать trivial circuit ("I know x such that Poseidon(x) == y").
#    Сгенерировать proof с ark-groth16.
#    Верифицировать proof с groth16-solana внутри Anchor теста.
#    Если это проваливается, дебажить proof format / verifying key conversion / CPI plumbing
#    перед чем-либо ещё.

# 3. alt_bn128 syscall availability на target network
#    Развернуть минимальную программу которая вызывает alt_bn128 syscalls.
#    Верифицировать что она исполняется на devnet.
#    Измерить actual CU consumption и сравнить с expected (~200K для полного Groth16).

# 4. Anchor 1.0 CPI test
#    Написать две программы: caller и callee.
#    Верифицировать что CPI работает с proof data передаваемыми как instruction data.
#    Проверить account size limits для proof bytes.
```

**Если любой из тестов 1–4 проваливается, MVP заблокирован.** Это не предложение — остальная часть MVP зависит от этих четырёх примитивов работающих вместе. Дебаг их на день 2 в сотни раз дешевле чем обнаружение mismatch на день 20.

---

## 4. Post-MVP security roadmap

**v0.2:**
- Публичная Phase 2 trusted setup ceremony (10–20 независимых контрибьюторов).
- Внешний криптографический audit (при условии grant funding).
- Bug bounty программа.
- Wallet-adapter интеграция для безопасного хранения viewing-key.
- Полный иерархический key split (spending key → full viewing key → incoming-only viewing key → nullifier key).

**v0.3 и позже:**
- Shared anonymity pool (network-effect anonymity set growth).
- Browser WASM prover (не нужно доверять серверу с генерацией proof).
- Mobile prover для маленьких circuits.
- Миграция на более сильную кривую когда Solana syscalls поддержат это.

---

## 5. Честное summary ограничений

Чтобы сделать этот документ полезным как standalone чтение для аудиторов и grant reviewers, честное summary:

- Мы используем BN254 (~100-bit security) потому что это единственный вариант нативный для Solana.
- Мы зависим от arkworks, который несёт academic-prototype disclaimer.
- Наша ElGamal имплементация custom и unaudited, но изолирована от privacy-критического пути.
- Наш MVP trusted setup — single-contributor ceremony помеченная DEVELOPMENT ONLY.
- Наш day-one anonymity set маленький и мы говорим это явно.
- Мы защищаемся от Fiat-Shamir transcript багов специальным checklist'ом и two-reviewer policy, потому что этот класс багов бил похожие системы в недавнем прошлом.
- Мы не отгружаем на mainnet без публичной ceremony и криптографического audit.

Всё остальное — в ADRs и [PROJECT_BRIEF.md](PROJECT_BRIEF.md).

---

*tidex6.rs — I grant access, not permission.*
*Rust-native фреймворк приватности для Solana.*
