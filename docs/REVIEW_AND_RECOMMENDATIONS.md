# tidex6.rs — Critical Review & Technical Recommendations

> **Документ для:** Claude Code, человек-разработчик
> **Контекст:** Ревью PROJECT_BRIEF.md с позиции senior Rust/crypto engineer
> **Дата:** April 9, 2026
> **Статус:** Actionable — каждая секция содержит конкретные решения

---

## Содержание

1. [Technical Feasibility — таймлайн](#1-technical-feasibility)
2. [Architecture Soundness — дыры](#2-architecture-soundness)
3. [Tech Stack Choices — стек](#3-tech-stack-choices)
4. [Killer Feature Validity — selective disclosure](#4-killer-feature-validity)
5. [Market Positioning — позиционирование](#5-market-positioning)
6. [Regulatory Strategy — регуляторика](#6-regulatory-strategy)
7. [Open Questions — конкретные ответы](#7-open-questions)
8. [Missing Considerations — что упущено](#8-missing-considerations)
9. [Simplification Opportunities — что вырезать](#9-simplification-opportunities)
10. [Killer Feature #2 — что добавить](#10-killer-feature-2)
11. [Revised Timeline — новый план](#11-revised-timeline)
12. [Architecture Decision Records](#12-architecture-decision-records)
13. [Day-1 Validation Checklist](#13-day-1-validation-checklist)

---

## 1. Technical Feasibility

### Вердикт: таймлайн агрессивно оптимистичен. MVP возможен при жёстком скоупинге.

### 1.1 Главная проблема: ZK learning curve

Разработчик учит ZK с нуля. Brief предполагает, что за дни 1–3 будет поставлен PoC-пайплайн: R1CS-цепь на arkworks → trusted setup → конвертация VK → deploy verifier → CPI. Для человека без опыта с arkworks это **не 3 дня, это 7–10 дней**.

Почему:
- arkworks API — 15.5M+ downloads на `ark-ec`, но документации мало
- Ошибки компиляции криптические (trait bounds на 5 строк)
- Дебаг R1CS constraints — отдельный вид страдания: constraint не сходится, и единственный способ найти причину — бинарный поиск по gadgets
- `ark-groth16` 0.5.0 имеет breaking changes vs 0.4.x (trait restructuring, edition 2021)

### 1.2 Конкретные узкие места

**Poseidon compatibility (дни 1–3)**:
- `light-poseidon` использует параметры: t=2..13, R_F=8, R_P=[56,57,56,60,...] для BN254
- Solana Poseidon syscall **внутренне использует `light-poseidon`** — это хорошая новость
- НО: если использовать `ark-crypto-primitives::sponge::poseidon` вместо `light-poseidon`, параметры **будут другими**
- **Решение:** ВСЕГДА использовать `light-poseidon` off-chain через `Poseidon::<Fr>::new_circom(n)`. Никогда не использовать generic arkworks Poseidon
- Стоимость on-chain: ~61 CU (coefficient a) + ~542 CU (coefficient c) — крайне дёшево

**ElGamal на BN254 G1 (дни 18–21)**:
- **Нет production-ready crate.** Все существующие ElGamal реализации в Rust (`elastic_elgamal`, `rust-elgamal`) работают на Curve25519/Ristretto, не на BN254
- Ближайший референс: `babygiant-alt-bn128` — companion к `noir-elgamal`, ElGamal на Baby Jubjub с baby-step giant-step дискретный лог для u40, расшифровка <6 сек на M1
- **Придётся писать с нуля** используя `ark-bn254::G1Projective` для группы и `ark-bn254::Fr` для скаляров
- Это криптографический код, где ошибка = потеря средств. 4 дня на это + equality proof внутри Groth16 circuit — нереально для ZK-новичка

**Proc macros (дни 22–24)**:
- `#[privacy_program]` который генерирует PDA-структуры, Merkle tree accounts, CPI-вызовы — это 2–3 недели работы, не 3 дня
- Proc macros в Rust — это отдельный проект со своей парадигмой (syn, quote, TokenStream)
- **Решение:** ПОЛНОСТЬЮ вырезать из MVP. Заменить на builder pattern + helper модули

**Indexer (не в таймлайне)**:
- Без indexer'а withdrawer не может сгенерировать Merkle proof
- Нужна подписка на program logs, rebuild дерева off-chain
- Это ещё ~2–3 дня работы, которых нет в таймлайне

### 1.3 Реалистичная оценка

| Задача | Brief estimate | Реальная оценка | Разница |
|--------|---------------|-----------------|---------|
| PoC pipeline (circuit → verifier → CPI) | 3 дня | 7–10 дней | +4–7 |
| Core crates (commitment, nullifier, merkle) | 4 дня | 4 дня | 0 |
| Withdrawal circuit | 3 дня | 5 дней | +2 |
| Verifier program + basic mixer | 4 дня | 3 дня | -1 |
| Key hierarchy (FVK/IVK) | 3 дня | 2 дня | -1 |
| ElGamal + selective disclosure | 4 дня | 7–8 дней | +3–4 |
| Client SDK | 3 дня | 3 дня | 0 |
| Proc macros | 3 дня | **ВЫРЕЗАНО** | -3 |
| Banya example | 4 дня | 3 дня | -1 |
| Documentation | 2 дня | 2 дня | 0 |
| Demo + pitch | 2 дня | 2 дня | 0 |
| Indexer (ДОБАВЛЕНО) | 0 дней | 2–3 дня | +2–3 |
| **Итого** | **32 дня** | **40–47 дней** | **+8–15** |

### 1.4 Рекомендация

Чтобы уложиться в 32 дня:
1. Вырезать proc macros целиком
2. Вырезать AuditorWithExpiry и Multisig variants
3. Вырезать FVK/IVK разделение (только один viewing key уровень)
4. Вырезать все примеры кроме banya-club
5. Вырезать SP1 escape hatch
6. Добавить 3 дня буфера на непредвиденное
7. Если ElGamal не готов к дню 20 — сделать MVP без selective disclosure, добавить потом

---

## 2. Architecture Soundness

### Вердикт: архитектура в целом корректна, но есть 5 конкретных дыр

### 2.1 BUG: Несовместимость схем commitment

**Секция 4.2:**
```
commitment = Poseidon(secret, nullifier, amount)
```

**Секция 5.2:**
```
amount_commitment = Pedersen(amount, blinding)
auditor_ciphertext = ElGamal(auditor_pubkey, amount, ephemeral_randomness)
commitment = Poseidon(secret, nullifier, amount_commitment, auditor_ciphertext)
```

Эти две схемы **несовместимы**. Для фиксированных деноминаций Pedersen commitment избыточен — amount фиксирован и публично известен (0.1 / 1 / 10 SOL).

**Решение для MVP:**
```rust
// Простая схема (фиксированные деноминации, amount публичен):
commitment = Poseidon(secret, nullifier)
// amount проверяется программой по переведённым lamports

// Auditor ciphertext — отдельное поле, НЕ часть commitment:
// auditor_tag = ElGamal(auditor_pk, deposit_metadata)
// Хранится в event data, не влияет на Merkle tree
```

Это проще, безопаснее, и позволяет разделить privacy layer (Merkle tree + nullifiers) от disclosure layer (ElGamal ciphertexts).

### 2.2 BUG: Отсутствие relayer = сломанная unlinkability

В секции 4.2 withdrawal идёт напрямую от Bob. Но:
- Bob должен заплатить gas за withdrawal транзакцию
- Если Bob платит gas с нового адреса — откуда у него SOL?
- Если с существующего адреса — он деанонимизирован
- **Без relayer'а privacy модель не работает на практике**

Хорошая новость: на Solana relayer проще чем на Ethereum:
- Транзакции стоят ~$0.00025–$0.01 (vs $1–100+ на Ethereum)
- Solana нативно поддерживает `feePayer` — чистое разделение fee payer и signer
- **Kora** (Solana Foundation, December 2024) — стандартизированный fee relayer

**Решение для MVP:**
```
Minimum Viable Relayer:
1. HTTP endpoint: POST /relay
2. Принимает: serialized withdrawal transaction (proof + public inputs)
3. Устанавливает себя как feePayer
4. Отправляет транзакцию в Solana
5. Комиссия вычитается из withdrawal amount on-chain
6. Простой Rust HTTP сервер (~200 строк кода)
```

Это добавляет ~2 дня к таймлайну, но **без этого privacy не работает**.

### 2.3 BUG: Конкурентные Merkle tree updates

Секция 4.5 говорит: "Client computes new root locally, submits with deposit, program validates against old root." 

Проблема: два одновременных deposit'а вычисляют root на базе одного дерева. Второй будет отклонён.

**Решение для MVP:**
```
On-chain: хранить только последние N roots (ring buffer, N=30)
Deposit: программа сама добавляет leaf в on-chain счётчик позиций
  - leaf_index = atomic_increment(next_index)
  - Merkle tree полностью off-chain (indexer)
  - Программа хранит ТОЛЬКО roots и leaf count
Withdrawal: proof ссылается на любой из последних N roots
  - Это стандартный Tornado Cash паттерн
```

### 2.4 BUG: Nullifier storage не определён

Не описано, как хранятся использованные nullifier'ы.

**Решение для MVP:**
```
Один PDA per nullifier:
  seeds = [b"nullifier", nullifier_hash.as_ref()]
  data = пустой (rent-exempt minimum = 890 bytes → ~0.00089 SOL)
  
Проверка: try_create PDA. Если PDA уже существует → nullifier использован → reject.
Это стандартный Anchor паттерн через init_if_needed / проверку существования.

Стоимость: ~0.00089 SOL per withdrawal (создание PDA)
Для MVP это приемлемо. Для production — Bloom filter или compressed accounts.
```

### 2.5 ISSUE: BN254 security level

`ark-bn254` предоставляет только ~100-bit security (после Kim-Barbulescu 2015 NFS improvements). Это ниже NIST рекомендации в 128-bit. Но это стандарт для Ethereum-экосистемы ZK приложений (все используют BN254/alt_bn128).

**Решение:** Задокументировать в security.md. Не менять — BN254 единственная кривая с Solana syscall поддержкой.

---

## 3. Tech Stack Choices

### Вердикт: arkworks + groth16-solana — правильный выбор. Подтверждено исследованием.

### 3.1 Confirmed: arkworks 0.5 — правильно

- Mature, 15.5M+ downloads на `ark-ec`
- v0.5.0 coordinated release всех crates
- Активно поддерживается (Pratyush Mishra)
- **Единственный** зрелый Rust-native Groth16 стек

Альтернативы отпадают:
- **Halo2** (PLONKish): нет Solana verifier, другая proving система
- **Plonky3** (STARK/FRI): нет BN254 support, используется SP1 внутренне
- **Bellperson** (used by Namada MASP): targets BLS12-381, нет Solana syscalls

### 3.2 Confirmed: groth16-solana 0.2.0 — правильно

- Released June 2025, targets **arkworks 0.5.x** (`ark-bn254 ^0.5`, `ark-ec ^0.5`, `ark-ff ^0.5`)
- **<200,000 CU** per verification — вписывается в Solana compute budget (1.4M default, 1.4M max)
- Аудирован в рамках Light Protocol v3 security audit
- Совместим с circom-generated proofs через snarkjs `verifyingkey.json` конвертацию
- `sp1-solana` тоже зависит от него — canonical verifier

### 3.3 Confirmed: light-poseidon — правильно, но pin версию

- v0.3.0, 7M+ downloads, аудирован Veridise
- `solana-poseidon` v3.1.5 зависит от `light-poseidon ^0.2.0`
- **Используй `new_circom(n)`** — это гарантирует совместимость с on-chain syscall
- CU cost: ~61 + ~542 — крайне дёшево для Merkle tree операций

**WARNING:** `light-poseidon` v0.3.0 vs `solana-poseidon` зависимость на `^0.2.0` — убедись что v0.3 backward-compatible. Если нет — pin 0.2.x.

### 3.4 Confirmed: Anchor 1.0 — правильно, но осторожно

- v1.0.0 released, stable
- Переехал из `coral-xyz` в `solana-foundation`
- Breaking changes от 0.30: новый IDL формат, custom discriminators, TypeScript package migration
- `solana-program` заменён на sub-crates
- Requires Solana CLI 3.1.10 (Agave)

**Рекомендация:** Pin `anchor-lang = "=1.0.0"`, тестируй на devnet часто.

### 3.5 Reject: SP1 escape hatch — убрать из MVP

- SP1 Hypercube production-ready, ~280K CU on Solana (vs ~200K raw Groth16)
- Но: +80K CU overhead, +50 seconds proving time для Groth16 wrapping
- Для MVP — мёртвый вес в зависимостях
- **Решение:** убрать из Cargo.toml, упомянуть в roadmap как future option

### 3.6 Stack summary (final)

```toml
# ON-CHAIN (Anchor program)
anchor-lang = "=1.0.0"
groth16-solana = "0.2"
solana-poseidon = "3"    # uses light-poseidon internally
tidex6-core = { path = "../tidex6-core" }

# OFF-CHAIN (Client + Prover)  
ark-bn254 = "0.5"
ark-groth16 = "0.5"
ark-crypto-primitives = { version = "0.5", features = ["r1cs", "crh", "sponge"] }
ark-r1cs-std = "0.5"
ark-relations = "0.5"
ark-ff = "0.5"
ark-ec = "0.5"
ark-serialize = "0.5"
ark-ed-on-bn254 = "0.5"  # Baby Jubjub — для key derivation в circuits

light-poseidon = "0.3"   # MUST match on-chain, use new_circom()
anchor-client = "1.0"
solana-sdk = "3.0"
```

---

## 4. Killer Feature Validity

### Вердикт: идея валидна и уникальна для Solana. Но не "novel" в абсолютном смысле.

### 4.1 Кто уже делает selective disclosure

- **Railgun** (Ethereum): viewing keys, PPOI (Private Proofs of Innocence)
- **Iron Fish** (standalone L1): FVK/IVK ровно как описано
- **Token-2022 CT** (Solana, disabled): auditor ElGamal key per-mint
- **Privacy Pools / 0xbow** (Ethereum): association sets — compliance через inclusion proof

### 4.2 Реальная новизна tidex6

1. **Per-deposit granularity** — разные аудиторы для разных депозитов (Token-2022 делает per-mint)
2. **На Solana** — где ничего другого работающего нет
3. **Developer framework** — не end-user app

Это достаточно для hackathon pitch. Позиционируй как **инженерную комбинацию проверенных паттернов**, не как криптографический breakthrough.

### 4.3 BUG: AuditorWithExpiry не работает как задумано

```rust
pub enum DisclosurePolicy {
    AuditorWithExpiry(ElGamalPubkey, i64),  // ← ЭТО НЕ РАБОТАЕТ
}
```

Ciphertext уже записан на chain. Если аудитор скачал ciphertext до expiry — он расшифрует когда угодно. Expiry cryptographically unenforceable без time-lock encryption (identity-based encryption с trusted time server), что радикально усложняет систему.

**Решение:** Убрать `AuditorWithExpiry` и `Multisig` из MVP. Оставить:
```rust
pub enum DisclosurePolicy {
    None,                       // full privacy (default)
    Auditor(ElGamalPubkey),     // one auditor can see
}
```

### 4.4 Рекомендация по позиционированию killer feature

В pitch deck:
- "Per-deposit disclosure policies — choose different auditors for different transactions"
- "Inspired by Zcash Sapling viewing keys + Token-2022 auditor pattern"
- "First on Solana to combine full transaction privacy with granular compliance"

НЕ говори: "novel cryptographic breakthrough" или "never done before globally"

---

## 5. Market Positioning

### Вердикт: "framework for developers" — абсолютно правильный угол.

### 5.1 Landscape confirmation (из исследования)

Текущие Solana privacy проекты — **все end-user apps**, ни один не framework:

| Проект | Тип | TVL/Users | Compliance | Developer SDK |
|--------|-----|-----------|------------|---------------|
| **Privacy Cash** | Mixer app | $210M+ transfers, 1,192 DAU | ❌ Нет | ❌ |
| **Umbra** | Wallet (on Arcium MPC) | $154.9M ICO, 100 users/week | Частично | SDK April 2026 |
| **Cloak** | Privacy layer | Cohort 4 accelerator | ? | ? |
| **Encifher** | FHE tokens | On Jupiter | Частично | ❌ |
| **GhostWareOS** | Privacy suite | ? | ❌ | ❌ |
| **NullTrace** | SPL mixer | ? | ❌ | ❌ |
| **tidex6** | **Developer framework** | N/A | ✅ Day-1 | ✅ Core product |

**Никто не предлагает developer framework.** Это пустая ниша.

### 5.2 Ecosystem analysis цитата (kkoshiya)

> "The first thing that stands out in terms of PMF is the lack of a washer type service — basically Solana's equivalent of a Tornado Cash/Railgun."

### 5.3 Solana Foundation signals

- **Privacy Hack** (January 2026): $100K+ призов, целевой хакатон по privacy
- Solana official account spotlighted 12 privacy projects (December 2025)
- **Privacy — институциональный приоритет** для Solana Foundation

### 5.4 Рекомендация

Позиционирование: **"Anchor for privacy"**
- Anchor не строит dApps — он помогает другим строить
- tidex6 не строит privacy apps — он даёт инструменты

---

## 6. Regulatory Strategy

### Вердикт: "compliance by choice" — сильная позиция, но с важными оговорками.

### 6.1 Van Loon v. Treasury — что реально защищает

**Защищает:**
- Immutable smart contracts не являются "property" под IEEPA
- OFAC не может добавить immutable code в SDN list

**НЕ защищает:**
- Developer criminal liability (Pertsev осуждён на 64 месяца в Нидерландах)
- Mutable smart contracts (Treasury явно аргументировал что они sanctionable)
- DAO governance structures
- Human operators (relayer operators, frontend providers)
- Jurisdiction — решение действует только в Fifth Circuit

**Решение Fifth Circuit узкое:** Van Loon holds specifically for self-executing code that nobody can own, control, or exclude from use.

### 6.2 Roman Storm trial — прецедент для developer liability

- Trial August 2025: mixed verdict
- **Guilty:** conspiracy to operate unlicensed money transmitting business
- **Deadlocked jury:** money laundering, sanctions conspiracy
- DOJ "Ending Regulation by Prosecution" memo (April 2025) сузил подход, но не устранил liability

### 6.3 Concrete recommendations

1. **Сделай verifier program non-upgradeable** после deployment. Это критично:
   - Van Loon защищает только immutable contracts
   - Anchor programs upgradeable по умолчанию
   - `solana program set-upgrade-authority <PROGRAM_ID> --final` после deploy
   
2. **Не запускай relayer сам.** Опиши protocol для permissionless relayers.

3. **Формулировка:** "User-controlled transparency tools" вместо "no backdoors"
   - "No backdoor" звучит как отказ от сотрудничества
   - "User-controlled disclosure" звучит как empowerment

4. **Рассмотри association sets (Privacy Pools model)** — inclusion proofs без KYC:
   - 0xbow raised $3.5M seed (November 2025, Starbloom + Coinbase Ventures)
   - Ethereum Foundation integrated в Kohaku wallet
   - Концепция chain-agnostic, portable на Solana
   - 0xbow сами приглашают: "We invite L1 & L2 ecosystems to enable Privacy Pools"

5. **Лицензия MIT/Apache-2.0** — правильно. Не GPL (ограничит adoption).

### 6.4 What to say in pitch deck

```
"tidex6 ships with compliance from day one:
1. Viewing keys — users choose who sees their transactions
2. Association sets (roadmap) — prove funds are clean without KYC  
3. Non-upgradeable verifier — immutable code, Van Loon protected
4. No centralized operator — pure protocol, no money transmission"
```

---

## 7. Open Questions — Конкретные Ответы

### Q1: arkworks vs plonky2/halo2?

**Ответ: arkworks. Окончательно.**

- plonky2: STARK-based, нет BN254 verifier для Solana
- halo2: PLONKish, нет Solana verifier
- arkworks 0.5 + groth16-solana 0.2.0 = единственный production-ready pipeline
- Подтверждено: Light Protocol, sp1-solana, Elusiv все использовали arkworks/Groth16

### Q2: circom-compat или pure arkworks?

**Ответ: pure arkworks для final product.**

Обоснование:
- circom-compat добавляет слой абстракции и зависимость на circom-generated R1CS
- Для простых circuits (deposit/withdraw) arkworks напрямую будет проще дебажить
- НО: circom для быстрого прототипирования — валидный fallback

**Практический совет:**
```
День 1-3: напиши circuit на circom, скомпилируй через snarkjs, проверь что groth16-solana верифицирует
День 4+: перепиши на pure arkworks R1CS
Это валидирует pipeline до того как ты застрянешь на arkworks API
```

### Q3: Fixed denominations vs flexible amounts?

**Ответ: Fixed для MVP. 100%.**

- 3 деноминации: **0.1 SOL, 1 SOL, 10 SOL**
- Лучший anonymity set (все deposit'ы одинаковы)
- Проще circuit (amount не нужен в proof)
- Privacy Cash на Solana ($210M+ transfers) тоже использует fixed denominations — работает

### Q4: Trusted setup ceremony?

**Ответ: Phase 1 переиспользуй, Phase 2 — свой.**

- **Tornado Cash's specific ceremony НЕ подходит напрямую** — они использовали circom-generated circuit с другими constraints
- **Phase 1 (generic):** переиспользуй Perpetual Powers of Tau (PPoT) — поддерживает 2²⁸ constraints на BN254, используется Tornado Cash, Hermez, Semaphore, MACI
- **Phase 2 (circuit-specific):** нужен свой для tidex6 circuits

**Процесс:**
```bash
# 1. Скачай PPoT ptau файл (Hermez, 54 contributions + random beacon)
wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_XX.ptau

# 2. Для MVP: сгенерируй Phase 2 локально
snarkjs groth16 setup circuit.r1cs pot_final.ptau circuit_0000.zkey

# 3. Добавь свой contribution
snarkjs zkey contribute circuit_0000.zkey circuit_final.zkey --name="tidex6-dev"

# 4. Пометь как "DEVELOPMENT ONLY, NOT PRODUCTION-READY"
# 5. Для production: public ceremony с 10+ contributors
```

### Q5: SP1 (zkVM) vs pure arkworks?

**Ответ: pure arkworks для MVP. SP1 — post-hackathon.**

- SP1 verification на Solana: ~280K CU (vs ~200K Groth16 direct)
- SP1 proving: +50 seconds для Groth16 wrapping
- Добавляет сложность без value для hackathon demo
- **Убрать из Cargo.toml полностью**

### Q6: Shared vs per-program Merkle tree?

**Ответ: per-program для MVP.**

- Shared pool = координационная проблема (кто платит за аккаунты? кто обновляет дерево?)
- Per-program изолирован и прост
- Privacy Cash тоже per-pool — работает
- **Shared "master pool" — post-hackathon feature, если будет demand**

### Q7: SOL-only vs SPL tokens?

**Ответ: SOL-only достаточно.**

- Судьи оценивают архитектуру и потенциал, не token coverage
- Упомяни SPL support как "designed for, implementation ready in v0.2"
- Namada MASP паттерн (per-asset generator points) задокументируй как roadmap

### Q8: CLI vs library?

**Ответ: library + минимальный CLI.**

```
tidex6 keygen          # генерация spending key
tidex6 setup           # trusted setup (phase 2)
tidex6 export-vk       # экспорт viewing key
```

Больше ничего. 3 команды.

### Q9: Позиционирование — "Tornado Cash alternative" vs "privacy primitives"?

**Ответ: "Privacy primitives for Solana developers."**

- Не упоминай Tornado Cash в заголовке/pitch
- Упоминай в техническом описании: "inspired by proven patterns from Tornado Cash, Railgun, and Zcash"
- "Compliance-compatible" в каждом слайде

### Q10: Landing page vs README?

**Ответ: README для hackathon. Но сделай его красивым.**

- Хороший README с architecture diagrams + code snippets > посредственный landing page
- Добавь ASCII art header, badges, "Quick Start" за 5 минут
- После submission — простой landing на GitHub Pages

---

## 8. Missing Considerations

### 8.1 Relayer Network (CRITICAL)

**Без relayer'а privacy не работает.** Уже описано в 2.2.

Для MVP: простой HTTP relay server. Для production: permissionless relay protocol с:
- Staking mechanism (anti-spam)
- Fee market (relayers конкурируют по комиссии)
- Encrypted transaction submission (relayer не видит содержимое)
- Referencing: Railgun's Waku P2P broadcasters, Kora fee relayer

### 8.2 Indexer (CRITICAL)

Кто собирает события и строит off-chain Merkle tree?

**Решение для MVP:**
```rust
// Простой indexer: подписка на program logs через WebSocket
// Rebuild Merkle tree из DepositEvent'ов
// Хранение: в памяти или SQLite
// ~200-300 строк Rust кода

struct Indexer {
    rpc: RpcClient,
    tree: MerkleTree<PoseidonHasher>,
    commitments: Vec<Commitment>,
}

impl Indexer {
    async fn sync(&mut self) -> Result<()> {
        let events = self.rpc.get_program_events(PROGRAM_ID).await?;
        for event in events {
            self.tree.insert(event.commitment);
            self.commitments.push(event.commitment);
        }
        Ok(())
    }
    
    fn get_merkle_proof(&self, leaf_index: usize) -> MerklePath {
        self.tree.generate_proof(leaf_index)
    }
}
```

### 8.3 Fee Model

Кто платит за on-chain storage?

| Операция | Стоимость | Кто платит |
|----------|-----------|------------|
| Deposit (commitment в дерево) | ~0.001 SOL (rent-exempt PDA) | Depositor |
| Withdrawal (nullifier PDA) | ~0.00089 SOL | Вычитается из withdrawal |
| Merkle root update | Minimal (just account data) | Program authority |
| Relayer fee | ~0.001–0.01 SOL | Вычитается из withdrawal |

### 8.4 Front-running & MEV

- Deposit раскрывает commitment в mempool до включения в блок
- На Solana менее критично (leader-based scheduling, не auction-based)
- НО: Jito bundles существуют и MEV на Solana растёт
- **Mitigation:** commitment = hash of secret values → видеть commitment бесполезно без secret

### 8.5 Key Management UX

- Где пользователь хранит spending key?
- Wallet integration — целый проект
- **Для MVP:** key хранится в файле (~/.tidex6/keys.json), encrypted at rest
- **Для production:** Wallet adapter integration (Phantom, Solflare)

### 8.6 Upgrade Path

- Баг в circuit = новый trusted setup = новый verifier = новый pool
- Старый pool не мигрируется (nullifiers привязаны к конкретному circuit)
- **Mitigation:** версионирование pools. PoolV1, PoolV2 сосуществуют. Sweep mechanism для миграции средств из старого пула.

### 8.7 Anonymity Set Size

- Privacy Cash: 1,192 DAU — минимальный anonymity set для Solana privacy protocol
- Для MVP на devnet: anonymity set = 0 (только тестовые транзакции)
- **Pitch:** "Framework designed for shared anonymity sets across all integrating applications"
- Чем больше разработчиков интегрируют — тем больше anonymity set (если shared pool)

### 8.8 Viewing Key Revocation

- Если viewing key скомпрометирован — его нельзя "отозвать"
- Все прошлые транзакции с этим ключом навсегда видимы
- **Mitigation:** документируй это. Viewing key = read-only, не spending key. Компрометация viewing key не позволяет украсть средства.

---

## 9. Simplification Opportunities

### Что ВЫРЕЗАТЬ из MVP без потери core value proposition:

| # | Что вырезать | Экономия | Почему безопасно |
|---|-------------|----------|------------------|
| 1 | **Proc macros** (`#[privacy_program]` etc) | 5–7 дней | Заменить на builder pattern. `PrivatePool::new().init()` |
| 2 | **SP1 escape hatch** | 1–2 дня + dependency bloat | Post-hackathon. Даже не упоминай в Cargo.toml |
| 3 | **AuditorWithExpiry** | 2 дня | Cryptographically broken. Убрать |
| 4 | **Multisig disclosure** | 2 дня | Усложнение без value для demo |
| 5 | **FVK/IVK разделение** | 1 день | Один viewing key уровень. IVK — post-hackathon |
| 6 | **Примеры кроме banya** | 2–3 дня | salary/voting/donations — описания в README, не код |
| 7 | **QR code / ZIP-316 format** | 1 день | Hex-encoded key для MVP. Форматирование потом |
| 8 | **CLI beyond keygen/setup** | 1 день | 3 команды максимум |
| 9 | **On-chain Merkle tree storage** | 2 дня | Только roots on-chain, tree off-chain (indexer) |

**Итого сэкономлено: ~17–20 дней** — что покрывает дефицит из секции 1.

### Что ОСТАВИТЬ обязательно:

1. ✅ Deposit → withdrawal flow с Groth16 proof
2. ✅ Nullifier anti-double-spend
3. ✅ Merkle tree inclusion proof
4. ✅ ElGamal auditor encryption (per-deposit, optional)
5. ✅ Viewing key export/import (hex format)
6. ✅ Pre-deployed verifier program (CPI)
7. ✅ Client SDK (ProofBuilder, TransactionBuilder)
8. ✅ Banya example app
9. ✅ Minimal relayer
10. ✅ Indexer (in-memory)

---

## 10. Killer Feature #2

### Рекомендация: Shielded Memo (зашифрованное сообщение внутри deposit)

Каждый deposit может содержать зашифрованное memo (до ~200 bytes), расшифровываемое только spending key или viewing key.

**Почему это killer:**
- Никто на Solana не делает encrypted memo в privacy context
- Token-2022 CT не поддерживает memo в encrypted form
- **Убийственный аргумент для бизнес-юзкейсов:** бухгалтерия, invoicing, аудит
- Бухгалтер видит не только сумму, но и назначение платежа ("January rent", "Invoice #3847")

**Реализация (~1–2 дня):**
```rust
// Off-chain:
let shared_secret = ecdh(sender_sk, recipient_pk); // на Baby Jubjub
let memo_key = hkdf(shared_secret, b"tidex6-memo");
let encrypted_memo = aes_256_gcm_encrypt(memo_key, memo_bytes);

// В DepositEvent:
pub struct DepositEvent {
    pub commitment: [u8; 32],
    pub root: [u8; 32],
    pub timestamp: i64,
    pub auditor_tag: Option<[u8; 64]>,     // ElGamal ciphertext
    pub encrypted_memo: Option<Vec<u8>>,    // AES-GCM encrypted
    pub memo_ephemeral_pk: Option<[u8; 32]>, // для ECDH
}

// Viewing key holder:
let shared_secret = ecdh(viewing_key, memo_ephemeral_pk);
let memo_key = hkdf(shared_secret, b"tidex6-memo");
let memo = aes_256_gcm_decrypt(memo_key, encrypted_memo);
// → "Payment for January banya session"
```

**Не нужен в circuit** — memo не влияет на privacy proof. Это чисто application-layer feature.

### Альтернативный Killer Feature #2: Association Sets (Privacy Pools)

Если Shielded Memo — quick win, то Association Sets — стратегическое преимущество.

**Суть:** пользователь при withdrawal доказывает (через ZK proof) что его deposit принадлежит к "approved" набору — без раскрытия конкретного deposit'а.

**Почему это мощно:**
- 0xbow (Privacy Pools на Ethereum) raised $3.5M, backed by Ethereum Foundation
- 0xbow прямо приглашает L1/L2 к интеграции
- Никто на Solana не реализовал association sets
- Это **самый сильный ответ на "а как с compliance?"**

**Сложность:** medium. Добавляет ещё один circuit (inclusion proof в subset). Для MVP — post-hackathon, но **обязательно в roadmap и pitch deck.**

---

## 11. Revised Timeline

### MVP-focused 32-day plan

```
PHASE 1: VALIDATE (Days 1–10)
├── Day 1-2: Pipeline validation
│   ├── Write minimal circom circuit: "I know x: Poseidon(x) == y"
│   ├── Compile with snarkjs, generate proof
│   ├── Verify proof with groth16-solana in Anchor test
│   ├── CRITICAL TEST: light-poseidon off-chain == solana-poseidon on-chain
│   └── GATE: if this doesn't work by day 2, stop and debug
│
├── Day 3-5: Core primitives
│   ├── tidex6-core: Commitment, Nullifier types
│   ├── MerkleTree (off-chain, using light-poseidon)
│   ├── SpendingKey → ViewingKey derivation (simplified, one level)
│   ├── Unit tests for all primitives
│   └── Poseidon parameter compatibility tests (off-chain vs on-chain)
│
├── Day 6-8: Deposit circuit (arkworks)
│   ├── Rewrite circom PoC as arkworks R1CS
│   ├── DepositCircuit: prove knowledge of (secret, nullifier) for commitment
│   ├── Trusted setup Phase 2 with snarkjs
│   ├── VK conversion to groth16-solana format
│   └── GATE: end-to-end proof generation + verification
│
├── Day 9-10: Withdrawal circuit
│   ├── WithdrawCircuit: Merkle inclusion + nullifier derivation
│   ├── Public inputs: nullifier_hash, root, recipient
│   ├── Private inputs: secret, nullifier, merkle_path
│   └── Unit tests with mock Merkle trees

PHASE 2: BUILD (Days 11–20)
├── Day 11-13: On-chain programs
│   ├── tidex6-verifier: Anchor program, CPI-callable Groth16 verifier
│   ├── tidex6-pool: deposit + withdrawal instructions
│   ├── Nullifier PDA storage (one PDA per nullifier)
│   ├── Root history ring buffer (last 30 roots)
│   └── Deploy to devnet
│
├── Day 14-15: Integration test
│   ├── End-to-end: deposit → wait → withdraw on devnet
│   ├── Fixed denomination (1 SOL)
│   ├── Debug any CU budget issues
│   └── MILESTONE: working mixer on devnet
│
├── Day 16-17: Indexer
│   ├── WebSocket subscription to program events
│   ├── Off-chain Merkle tree rebuild
│   ├── Merkle proof generation
│   └── In-memory storage (SQLite optional)
│
├── Day 18-20: Selective disclosure
│   ├── ElGamal on BN254 G1 (custom implementation)
│   ├── Per-deposit auditor tag (DisclosurePolicy::None | Auditor)
│   ├── Auditor decryption flow
│   ├── Viewing key export (hex format)
│   └── MILESTONE: working opt-in disclosure

PHASE 3: POLISH (Days 21–28)
├── Day 21-23: Client SDK
│   ├── tidex6-client: ProofBuilder, TransactionBuilder, KeyManager
│   ├── Builder pattern API (no macros)
│   ├── Integration with indexer for Merkle proofs
│   └── Error handling, logging
│
├── Day 24-26: Banya example + relayer
│   ├── examples/banya-club: full flow with viewing keys
│   ├── Minimal HTTP relayer (POST /relay)
│   ├── CLI demo script (beautiful terminal output)
│   └── MILESTONE: complete demo flow
│
├── Day 27-28: Shielded Memo (killer feature #2)
│   ├── ECDH key exchange on Baby Jubjub
│   ├── AES-256-GCM memo encryption
│   ├── Integration into DepositEvent
│   └── Viewing key holder can read memos

PHASE 4: SHIP (Days 29–32)
├── Day 29-30: Documentation
│   ├── README (polished, with architecture diagrams)
│   ├── getting-started.md (5-minute quick start)
│   ├── architecture.md (data flow, key hierarchy)
│   ├── security.md (threat model, limitations, BN254 security level)
│   └── viewing-keys.md (tutorial)
│
├── Day 31: Demo & pitch
│   ├── 3-5 minute demo video
│   ├── 10-slide pitch deck
│   ├── GitHub cleanup (CI, badges, license)
│   └── Test full flow one more time
│
└── Day 32: SUBMIT
    ├── Colosseum Frontier submission
    ├── Target: Public Goods + Standout Team
    └── Accelerator application ($250K pre-seed)
```

### GATE Checkpoints (kill/continue decisions)

| Day | Gate | If FAIL |
|-----|------|---------|
| 2 | Groth16 proof verifies on Solana via CPI | Stop. Debug pipeline. Don't proceed. |
| 5 | Poseidon off-chain == on-chain (byte-for-byte) | Investigate light-poseidon version mismatch |
| 8 | arkworks circuit compiles and generates valid proof | Fallback to circom-based circuits |
| 14 | End-to-end deposit → withdraw on devnet | This IS the MVP. Everything else is polish. |
| 20 | ElGamal selective disclosure works | Ship without it. Viewing key = future feature. |

---

## 12. Architecture Decision Records

### ADR-001: Commitment scheme

**Decision:** `commitment = Poseidon(secret, nullifier)` для fixed denominations.

**Context:** Brief описывает два несовместимых варианта. Для fixed denominations amount публичен, не нужен в commitment.

**Consequences:** При переходе к flexible amounts потребуется новый circuit и новый trusted setup.

### ADR-002: Merkle tree — off-chain with on-chain roots

**Decision:** Полное дерево off-chain (indexer). On-chain только last 30 roots (ring buffer) + leaf counter.

**Context:** On-chain Merkle tree обновления дорого (CU), конкурентные updates проблематичны.

**Consequences:** Нужен indexer. Пользователь зависит от доступности indexer для withdrawal.

### ADR-003: Nullifier storage — one PDA per nullifier

**Decision:** `seeds = [b"nullifier", nullifier_hash]`, пустые данные, rent-exempt.

**Context:** Простейший anti-double-spend. O(1) lookup, O(n) storage.

**Consequences:** ~0.00089 SOL per withdrawal. Для production рассмотреть Bloom filter или compressed accounts.

### ADR-004: ElGamal on BN254 G1 — custom implementation

**Decision:** Написать additive homomorphic ElGamal используя `ark-bn254::G1Projective`.

**Context:** Нет production-ready crate. Ближайший референс: `babygiant-alt-bn128`.

**Consequences:** Криптографический код без аудита. Пометить как "unaudited, use at own risk" в security.md.

### ADR-005: Verifier program — non-upgradeable

**Decision:** После deployment: `solana program set-upgrade-authority <ID> --final`

**Context:** Van Loon v. Treasury защищает только immutable contracts. Регуляторная необходимость.

**Consequences:** Баг = новый deploy нового program ID. Миграция через versioned pools.

### ADR-006: No proc macros in MVP

**Decision:** Builder pattern + helper modules вместо `#[privacy_program]` proc macros.

**Context:** Proc macros = 2-3 недели разработки, не вписывается в таймлайн.

**Consequences:** Developer UX менее "magical", но работает. Macros — post-hackathon polish.

---

## 13. Day-1 Validation Checklist

Перед тем как писать любой production код, проверь эти вещи:

```bash
# 1. Poseidon compatibility test
# Off-chain (Rust):
use light_poseidon::{Poseidon, PoseidonBytesHasher, parameters::bn254_x5};
let mut hasher = Poseidon::<Fr>::new_circom(2).unwrap();
let input1 = Fr::from(42u64);
let input2 = Fr::from(69u64);
let hash = hasher.hash(&[input1, input2]).unwrap();
println!("Off-chain hash: {:?}", hash);

# On-chain (Anchor test):
# Use solana_poseidon::hash with same inputs
# Compare byte-for-byte
# IF MISMATCH → STOP. Debug before anything else.

# 2. Groth16 pipeline smoke test
# Write trivial circuit: "I know x such that Poseidon(x) == y"
# Generate proof with ark-groth16
# Verify with groth16-solana in Anchor program
# IF FAILS → check CU budget, VK format, proof serialization

# 3. alt_bn128 syscall availability
# Deploy simple program that calls sol_alt_bn128_group_op
# Verify it works on devnet
# Check CU consumption matches expected (~200K total for Groth16)

# 4. Anchor 1.0 CPI test
# Write two programs: caller + callee
# Verify CPI works with proof data as instruction data
# Check account size limits for proof bytes (256 bytes uncompressed)
```

**Если любой из тестов 1-4 не проходит — не продолжай. Чини pipeline.**

---

## Итоговая оценка

### Сильные стороны брифа:
- Глубокий конкурентный анализ (один из лучших)
- Правильный tech stack (подтверждено исследованием)
- Правильное позиционирование (framework, не app)
- Правильный timing (Token-2022 disabled, Arcium = MPC not ZK, Privacy Cash = no compliance)

### Критические риски (в порядке приоритета):
1. **ZK learning curve** — arkworks debugging съест на 50%+ больше времени
2. **Commitment schema inconsistency** — секции 4.2 и 5.2 описывают разные схемы
3. **Relayer gap** — без relayer'а privacy story развалится на demo day
4. **Indexer отсутствует** — не в таймлайне, но без него withdrawal невозможен
5. **ElGamal from scratch** — криптографический код без аудита

### Если всё вырезать по секции 9 + добавить relayer + indexer:

**MVP реалистичен за 32 дня.** Но с нулевым буфером.

---

**End of review. Этот документ + PROJECT_BRIEF.md = полный контекст для Claude Code.**
