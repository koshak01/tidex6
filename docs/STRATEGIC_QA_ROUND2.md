# tidex6.rs — Strategic Q&A Round 2

> **Контекст:** Ответы на 6 follow-up вопросов после принятия основного ревью
> **Входные документы:** PROJECT_BRIEF.md, REVIEW_AND_RECOMMENDATIONS.md, market research
> **Формат:** Прямой ответ → обоснование → actionable next step
> **Дата:** April 9, 2026

---

## Question 1 — Two Killer Features: Dilution or Strength?

### Прямой ответ: НЕ размывает. Усиливает. Но только при правильной упаковке.

### Обоснование

Проблема "двух killer features" возникает когда обе находятся на одном уровне зрелости и конкурируют за внимание. Здесь ситуация другая: Shielded Memo **работает в коде**, Association Sets **работает в стратегии**. Это два разных сигнала для двух разных аудиторий:

**Судьи-инженеры** смотрят на код. Им нужно: "вот работающая фича, которую я могу потрогать." Shielded Memo — это она. Encrypted memo расшифровывается viewing key'ом в live demo. Это конкретно, визуально, и доказывает техническую глубину.

**Судьи-стратеги** смотрят на vision. Им нужно: "куда это ведёт через 12 месяцев?" Association Sets — это ответ. "First Privacy Pools implementation on Solana" — это предложение, от которого грантовые комитеты не отказываются. 0xbow raised $3.5M на этом концепте. Ethereum Foundation интегрировал. Colosseum accelerator ищет именно такой масштаб vision.

Ключевое: **не ставь их на одну полку**. Shielded Memo — фича продукта. Association Sets — стратегический roadmap. В pitch deck это разные слайды, разные narrative layers.

### Framing для pitch deck (одно предложение)

> **"tidex6 ships with encrypted transaction memos for auditable privacy today, and will bring Privacy Pools–style compliance proofs to Solana — making it the first framework where users can prove their funds are clean without revealing their identity."**

Структура: [working feature] + [strategic direction] + [unique positioning].

Вариант покороче для elevator pitch:
> **"Private payments with encrypted memos now, compliant privacy proofs next — the full-stack privacy SDK for Solana."**

### Как это ложится в pitch deck

```
Slide 5: "What works today" (demo)
  → Shielded Memo: "Accountant sees payment + memo: 'Invoice #3847, January'"
  → Per-deposit auditor key: "Choose who sees what, per transaction"

Slide 8: "Roadmap" (vision)
  → v0.2: Association Sets (Privacy Pools on Solana)
  → "Prove your funds are clean — without KYC, without revealing your deposit"
  → Cite: 0xbow ($3.5M seed), Ethereum Foundation (Kohaku wallet)
  → One-liner: "The compliance layer that Privacy Cash and NullTrace don't have"
```

### Actionable next step

Напиши один параграф для README секции "Roadmap" про Association Sets. Ссылка на Privacy Pools paper (Buterin et al.), ссылка на 0xbow docs. Не нужен код — нужна **чёткая архитектурная заявка**: "We will implement association set proofs as an additional circuit that composites with the existing withdrawal proof, allowing users to prove membership in a curated deposit subset."

---

## Question 2 — Per-Program Pool vs Shared Pool (Anonymity Set Fragmentation)

### Прямой ответ: per-program для MVP — это ОК. Но нужна конкретная защита от вопроса судей.

### Обоснование

Ты прав: успех фреймворка парадоксально ослабляет privacy каждого отдельного пользователя. Если 10 разработчиков интегрируют tidex6 и каждый имеет свой pool с 50 deposit'ами — это 10 pools по 50, а не 1 pool на 500. Anonymity set = 50, а не 500.

Но shared pool в MVP — это **координационный кошмар**:

| Проблема shared pool | Сложность | Дни работы |
|----------------------|-----------|------------|
| Multi-program PDA ownership | Кто authority? Singleton program? | +3-4 |
| Cross-program root updates | Каждый deposit меняет root для всех | +2-3 |
| Fee accounting (кто платит rent) | On-chain fee split | +1-2 |
| Concurrent deposit sequencing | Гонки между разными programs | +2-3 |
| Multi-denomination в одном дереве | Разные листья для разных amounts | +1-2 |
| **Итого** | | **+9-14 дней** |

Это убивает MVP. Не делай.

### Как отвечать судьям

Вопрос: *"But anonymity set = 5 on day one is not real privacy?"*

**Ответ (заучи):**

> "You're absolutely right, and we designed for this. Per-program pools are the starting point — each integrator gets isolation and simplicity. But the architecture is built for a shared anonymity pool in v0.3, where all tidex6-integrated applications contribute to ONE Merkle tree. This is the Namada MASP model: one pool, many assets, one anonymity set. The more apps that integrate, the stronger privacy becomes for everyone. Day-one privacy comes from the pool size of each individual application — a busy DEX or payroll system can reach thousands of deposits within weeks. Cross-application shared pools are how we get to millions."

Ключевые фразы:
- **"Designed for"** — не "мы не подумали", а "сознательный выбор с конкретным планом"
- **"Namada MASP model"** — авторитетная ссылка, судьи знают Namada
- **"Network effect"** — именно это ищут accelerator judges

### Техническая заметка для roadmap

Shared pool реализуется как **singleton program** (`tidex6-shared-pool`) с:
```
- Один Merkle tree для всех participants
- Per-program deposit authority (CPI from integrator → shared pool)
- Unified nullifier set
- Fee: фиксированный % от deposit, идёт в pool maintenance fund
- Root updates: append-only (indexer handles tree), on-chain stores last N roots
```

Это ~2 недели работы post-hackathon. Нереалистично для MVP, но реалистично для v0.3.

### Actionable next step

Добавь в architecture.md секцию "Anonymity Set Growth Path":
```
Phase 1 (MVP): Per-program pools. Each integrator has isolated pool.
  Anonymity set = number of deposits in that specific pool.
  
Phase 2 (v0.2): Optional shared pool opt-in. Integrators can choose:
  - Isolated pool (default, backwards compatible)
  - Shared pool (stronger privacy, shared anonymity set)
  
Phase 3 (v0.3): Shared pool as default with per-program isolation as opt-out.
  Cross-application anonymity set. Namada MASP-inspired architecture.
```

---

## Question 3 — Fiat-Shamir Discipline: Concrete Checklist

### Прямой ответ: ваш список хороший, но неполный. Вот полный checklist с приоритизацией.

### Контекст: что пошло не так в Token-2022

**April 2025 (первый баг):** В ZK ElGamal Proof Program пропущены алгебраические компоненты в Fiat-Shamir hash. Пропатчено за 48 часов.

**June 2025 ("Phantom Challenge"):** В `PercentageWithCapProof` (sigma OR proof для fee validation) значение `c_max_proof` — challenge, сгенерированный prover'ом — **не было включено в Fiat-Shamir transcript**. Это позволяло prover'у подбирать challenge, что делало proof forge trivial. Результат: arbitrary token minting, balance theft. Program выключен на epoch 805.

Оба бага — один класс ошибки: **incomplete transcript**. Prover контролирует значение, которое должно быть зафиксировано в transcript, но не зафиксировано.

### Правило #1 (ловит 80% реальных багов)

> **"If the verifier uses a value, the transcript must bind it. If the prover computes a value that influences the proof, the transcript must absorb it BEFORE the challenge is derived."**

Или короче: **"Anything the prover touches goes into the transcript."**

### Полный Fiat-Shamir PR Checklist

```markdown
## Fiat-Shamir Transcript Review Checklist

При каждом PR, затрагивающем proof logic (circuits, transcript 
construction, proof generation, proof verification), проверь ВСЕ пункты.

### CRITICAL (блокирует merge)

- [ ] **RULE 0: Prover values → transcript.** 
      Каждое значение, вычисляемое prover'ом (commitments, intermediate 
      values, sub-challenges в OR proofs), ДОЛЖНО быть absorbed в 
      transcript ДО derivation challenge. Нарушение = proof forgery.
      
- [ ] **All public inputs absorbed.**
      Каждый public input (nullifier_hash, merkle_root, recipient, 
      amount/denomination) включён в transcript. Пропуск = proof reuse 
      across different statements.

- [ ] **All commitments absorbed (including intermediate).**
      В multi-round protocols или composed proofs: каждый commitment 
      на каждом round absorbed. Особое внимание к OR proofs и 
      sigma protocol compositions — именно здесь был Token-2022 баг.

- [ ] **All group elements used in proof absorbed.**
      G1/G2 points, ElGamal ciphertexts, Pedersen commitments — 
      всё что является частью proof statement.

- [ ] **Domain separator present.**
      Unique domain separator string в начале transcript. Предотвращает 
      cross-protocol proof replay. Format: "tidex6-v1-{circuit_name}".

- [ ] **No prover-controlled values used after challenge derivation 
      without re-absorption.**
      Если prover вычисляет response ПОСЛЕ challenge — response не 
      должен использоваться как input для ДРУГОГО challenge без 
      повторного absorption.

### HIGH (блокирует merge без обоснования)

- [ ] **Transcript order matches spec.**
      Порядок absorption matters. Изменение порядка = другой challenge = 
      другой proof. Задокументируй порядок в комментариях.

- [ ] **No transcript reuse across independent proofs.**
      Если генерируешь несколько proof'ов в одной транзакции — каждый 
      начинает с fresh transcript (или fork с unique suffix).

- [ ] **Field element encoding is canonical.**
      Fr elements absorbed в canonical form (Montgomery → standard, 
      или конкретный ark-serialize формат). Разная сериализация = 
      разный hash = verifier reject.

- [ ] **Curve point compression consistent.**
      Если absorb'ишь G1 points — всегда compressed или всегда 
      uncompressed. Mixing = different transcript.

### MEDIUM (require review comment)

- [ ] **Circuit constraint count stable.**
      Изменение constraint count может указывать на добавление/удаление 
      проверок. Diff + обоснование.

- [ ] **No redundant constraints removed.**
      "Оптимизация" удалением constraints может снять security properties.
      Каждое удаление = explicit review.

- [ ] **Witness generation matches circuit.**
      Witness values computed off-chain должны проходить through те же 
      operations что circuit expects. Mismatch = valid-looking proof 
      that proves wrong statement.

### META

- [ ] **Two reviewers signed off on transcript construction.**
      Author + один independent reviewer. Не merge с одним approval 
      на proof-critical code.

- [ ] **Test: honest proof verifies.**
      Trivial, но regression test.

- [ ] **Test: tampered public input rejects.**
      Измени один public input → proof должен быть rejected.

- [ ] **Test: reused nullifier rejects.**
      Double-spend test.
```

### Что ещё добавить в security.md

```markdown
## Known Vulnerability Classes

### 1. Incomplete Fiat-Shamir Transcript
Severity: CRITICAL
Reference: Token-2022 CT "Phantom Challenge" (June 2025)
Impact: Arbitrary proof forgery → unlimited minting/theft
Our mitigation: PR checklist, Rule 0 enforcement, two-reviewer policy

### 2. Poseidon Parameter Mismatch  
Severity: HIGH
Reference: arkworks-rs/ivls Issue #1
Impact: Off-chain/on-chain hash divergence → valid proofs rejected 
  or invalid proofs accepted
Our mitigation: Day-1 validation test, pinned light-poseidon version, 
  integration tests on every CI run

### 3. BN254 Security Level (~100 bits)
Severity: MEDIUM (long-term concern)
Reference: Kim-Barbulescu 2015 NFS improvements
Impact: Future advances in NFS could weaken BN254 below practical security
Our mitigation: Documented limitation. BN254 is standard for 
  Ethereum/Solana ZK ecosystem. Migration path: future switch to 
  BLS12-381 when Solana adds syscalls (tracked in roadmap).

### 4. Trusted Setup Compromise
Severity: HIGH (if Phase 2 compromised)
Reference: Bowe-Gabizon 2017 attack on Groth16 with subverted CRS
Impact: Prover can forge proofs without knowledge of witness
Our mitigation: MVP uses development-only ceremony (marked explicitly).
  Production will use public multi-contributor ceremony with ≥20 
  independent participants.

### 5. ElGamal Implementation (Custom, Unaudited)
Severity: HIGH
Impact: Incorrect encryption → privacy leak for auditor feature.
  Does NOT affect core privacy (deposit/withdrawal) which uses 
  standard Groth16.
Our mitigation: Isolated from core privacy logic. ElGamal is 
  application-layer (DisclosurePolicy), not consensus-layer.
  Marked "unaudited" in code and docs. Audit before mainnet.
```

### Actionable next step

1. Добавь checklist выше как `docs/PR_CHECKLIST_PROOF_LOGIC.md`
2. В `.github/PULL_REQUEST_TEMPLATE.md` добавь: "If this PR touches proof logic, circuits, or transcript construction: attach completed Fiat-Shamir checklist."
3. В security.md добавь Known Vulnerability Classes секцию

---

## Question 4 — Realistic Timeline: 32 Days for a ZK Newcomer

### Прямой ответ: 32 дня — впритык, но возможно. С двумя условиями.

### Условие 1: Day-1 validation MUST pass by day 2

Если к концу дня 2 нет работающего pipeline (circom circuit → snarkjs proof → groth16-solana verification → Anchor CPI), то 32 дня невозможны. Это kill-gate. Если pipeline не работает за 2 дня — переключись на circom-only path (без arkworks rewrite) и экономь 3-4 дня.

### Условие 2: ElGamal — fallback plan готов

ElGamal on BN254 from scratch — самая рискованная задача. Если к дню 18 нет working encryption/decryption — **ship без selective disclosure**. Это больно (теряешь killer feature #1), но working mixer > broken selective disclosure.

### Бюджет времени (после всех cuts)

```
PHASE 1: VALIDATE (Days 1-10)                          10 дней
  Pipeline validation + circom PoC               2 дня
  Core primitives (commitment, nullifier, keys)   3 дня
  Deposit circuit (arkworks)                      3 дня
  Withdrawal circuit                              2 дня

PHASE 2: BUILD (Days 11-20)                            10 дней
  On-chain programs (verifier + pool)             3 дня
  Integration test (e2e devnet)                   2 дня
  Indexer                                         2 дня
  ElGamal + selective disclosure                  3 дня

PHASE 3: POLISH (Days 21-28)                            8 дня
  Client SDK                                      2 дня
  Freelancer Payroll example + relayer            3 дня
  Shielded Memo                                   1.5 дня
  ADRs + security.md + roadmap                    1.5 дня

PHASE 4: SHIP (Days 29-32)                              4 дня
  Documentation (README, getting-started, etc)    2 дня
  Demo video + pitch deck                         1 день
  Submit + cleanup                                1 день

TOTAL:                                                 32 дня
BUFFER:                                                 0 дней
```

**Буфера нет.** Это проблема. Реальность ZK-разработки: ты БУДЕШЬ терять дни на:
- arkworks compilation errors (trait bounds не сходятся)
- Proof не верифицируется (off-by-one в constraint indexing)
- CU budget overflow на devnet
- Anchor 1.0 quirks (новый IDL формат)

### Где взять 3-5 дней буфера

Если нужен буфер — вот приоритизированный список того, что резать:

| Приоритет | Что вырезать | Экономия | Цена |
|-----------|-------------|----------|------|
| **Режь ПЕРВЫМ** | Shielded Memo | 1.5 дня | Теряешь demo wow-factor, но core privacy работает. Memo можно добавить за 1 день post-submission если время останется |
| **Режь ВТОРЫМ** | Client SDK polish | 1–2 дня | Вместо красивого builder API — raw function calls. Работает, но не sexy |
| **Режь ТРЕТЬИМ** | Документация (cookbook, tutorials) | 1 день | Оставь только README + architecture.md. Судьи читают README, не tutorials |
| **НЕ РЕЖЬ** | ElGamal selective disclosure | — | Без него ты "ещё один mixer". Privacy Cash уже mixer. Selective disclosure = единственный differentiator |
| **НЕ РЕЖЬ** | Indexer | — | Без indexer withdrawal physically impossible |
| **НЕ РЕЖЬ** | Relayer | — | Без relayer anonymity breaks on demo. Судья спросит "а откуда у recipient SOL на gas?" |

### Рекомендация

**Планируй 32 дня, но реши заранее:**

```
IF day 8: arkworks circuit не компилируется
THEN: оставайся на circom path (snarkjs prove → groth16-solana verify)
      экономишь 2-3 дня на arkworks debugging
      circuit менее "Rust-native" но работает

IF day 18: ElGamal не работает
THEN: ship без selective disclosure
      viewing key = post-hackathon
      фокусируйся на mixer quality + Shielded Memo

IF day 25: всё работает но docs не готовы
THEN: день 25-26 = README only (skip tutorials, cookbook)
      день 27 = demo video
      день 28 = submit early
```

**Circom fallback — это не поражение.** Tornado Cash, Semaphore, MACI — все используют circom circuits с snarkjs. groth16-solana совместим с circom-generated proofs. Если arkworks R1CS оказывается слишком сложным для 32-дневного sprint, circom circuit + Rust client SDK + Anchor program = полностью валидный submission. Ты всё ещё "Rust-native framework" — только circuit definition в circom, всё остальное в Rust.

### Финальный вердикт по таймлайну

32 дня для одного ZK-новичка — это **hero mode**. Возможно, но с нулевым запасом. Реалистичная оценка с буфером — **37 дней** (5 дней сверху). Чтобы уложиться в 32:

1. Используй circom как fallback для circuits (экономит 2-3 дня если arkworks не идёт)
2. Shielded Memo — первый кандидат на cut если время поджимает
3. ElGamal — последний cut, только если к дню 18 нет progress
4. Не трать время на красоту кода. Работающий ugly code > красивый незаконченный

---

## Question 5 — Flagship Example: Freelancer Payroll vs Banya

### Прямой ответ: Freelancer Payroll ЗНАЧИТЕЛЬНО сильнее. Меняй без колебаний.

### Обоснование

**Banya проблемы:**
- "Russian banya club" — культурно непрозрачно для международных судей
- "общак" и "Ашотыч" — zero resonance за пределами русскоязычной аудитории
- Требует объяснения контекста ("это как... ну... баня... и деньги...") — мёртвое время в 3-минутном demo
- Вызывает ассоциации с informal/grey economy — не то что хочешь рядом с "compliance by choice"

**Freelancer Payroll преимущества:**
- **Universally relatable.** Каждый судья либо фрилансер, либо нанимал фрилансера
- **Business-grade use case.** Accelerator judges ищут B2B потенциал — payroll это B2B
- **Natural compliance narrative.** "Tax time" — мгновенно понятно зачем viewing keys
- **Демонстрирует ВСЕ features:**

```
Feature                    | Freelancer Payroll demo
---------------------------|---------------------------------------
Private deposit            | Client pays Anna privately
Shielded Memo              | Memo: "Invoice #3847, January dev work"
Viewing key export         | Anna exports VK, gives to accountant
Auditor decryption         | Accountant scans chain, sees all income
Unlinkability              | Client A can't see Client B's payments
Fixed denominations        | Payments in 1 SOL / 10 SOL buckets
Per-deposit auditor        | Different auditor for business vs personal
```

### Blind spot: "accountant sees all = backdoor?"

Нет, если правильно framed. Ключевая разница:

```
Backdoor:     Government FORCES access. User has no choice.
Viewing key:  USER CHOOSES to share. Accountant sees only what Anna allows.
              Anna can have TWO viewing keys — one for accountant (business),
              one for personal (never shared). Or zero viewing keys (full privacy).
```

**В demo скажи буквально:**

> "Notice: Anna CHOSE to share this key. The protocol has no backdoor. If Anna never exports a viewing key, no one — not the accountant, not the government, not even the protocol developers — can see her transactions. This is compliance by choice, not compliance by force."

Это превращает потенциальную слабость в **самый сильный момент demo**.

### Demo script (2 terminal windows)

```
╔════════════════════════════════════╗  ╔══════════════════════════════════╗
║  TERMINAL 1: client.rs            ║  ║  TERMINAL 2: accountant.rs       ║
╠════════════════════════════════════╣  ╠══════════════════════════════════╣
║                                    ║  ║                                  ║
║  $ tidex6 deposit \                ║  ║  $ tidex6 scan \                 ║
║      --pool freelancer-payroll \   ║  ║      --viewing-key anna_vk.hex \ ║
║      --amount 10 \                 ║  ║      --pool freelancer-payroll   ║
║      --memo "Invoice #3847" \      ║  ║                                  ║
║      --auditor anna_auditor.pub    ║  ║  Scanning deposits...            ║
║                                    ║  ║                                  ║
║  ✓ Deposit confirmed               ║  ║  Found 3 deposits:               ║
║  ✓ Commitment: 0x8a3f...           ║  ║   #1: 10 SOL - "Invoice #3847"  ║
║  ✓ Memo encrypted for auditor      ║  ║   #2:  1 SOL - "Coffee meeting" ║
║  ✓ Tx: 5Uh7kP...                   ║  ║   #3: 10 SOL - "Feb retainer"  ║
║                                    ║  ║                                  ║
║  Observer sees: "deposit to pool"  ║  ║  Total income: 21 SOL            ║
║  Observer knows: NOTHING ELSE      ║  ║  Ready for tax filing ✓          ║
╚════════════════════════════════════╝  ╚══════════════════════════════════╝
```

### Рекомендация по naming

Назови example **не** `freelancer-payroll`, а `private-payroll`. Причины:
- "Private payroll" — более general (covers salary, contractor payments, consulting)
- Shorter
- Не ограничивает use case только freelancers

Внутри примера персонажи: **Anna** (recipient/freelancer) и **Kai** (accountant).

### Actionable next step

1. Переименуй `examples/banya-club/` → `examples/private-payroll/`
2. Создай два binary: `examples/private-payroll/src/client.rs` и `examples/private-payroll/src/accountant.rs`
3. Напиши demo script (для video recording) — 3 минуты, 6 шагов:
   - Step 1: Anna generates keys (`tidex6 keygen`)
   - Step 2: Client A pays Anna privately (deposit + memo)
   - Step 3: Client B pays Anna privately (different memo)
   - Step 4: Observer tries to link payments (FAILS — sees only commitments)
   - Step 5: Anna exports viewing key to accountant
   - Step 6: Accountant scans and sees full history with memos

---

## Question 6 — What Are We Still Missing?

### Прямой ответ: Proof generation time. Это слон в комнате которого никто не обсуждает.

### Проблема

Весь brief, весь review, все ADRs обсуждают **on-chain** verification (CU budget, Groth16 verifier, Merkle tree roots). Но **off-chain** proof generation — то, что пользователь ждёт на своём компьютере — нигде не бенчмаркнуто.

Грубые оценки для Groth16 proof generation на arkworks:

| Circuit complexity | Constraints | Proving time (M1 Mac) | Proving time (average laptop) |
|-------------------|-------------|----------------------|-------------------------------|
| Toy (Poseidon hash) | ~5K | <1 sec | 1-2 sec |
| Tornado Cash withdraw | ~30K | 3-5 sec | 8-15 sec |
| Deposit + auditor proof | ~50K | 5-10 sec | 15-30 sec |
| Full withdraw + Merkle(20) | ~100K | 10-20 sec | 30-60 sec |

Withdrawal circuit с Merkle depth 20 (1M capacity) + nullifier derivation + Poseidon hashing в circuit может оказаться **30-60 секунд на среднем ноутбуке**.

Для CLI demo это терпимо. Для production — это UX disaster.

### Почему это критично прямо сейчас

1. **Demo day.** Судья смотрит live demo. Ты запускаешь withdrawal. 45 секунд тишины. "Generating proof..." Судья теряет интерес. Или хуже — думает что программа зависла.

2. **Benchmark question.** Технический судья спросит: "What's the proving time?" Если ответ "мы не измеряли" — это red flag.

3. **Architecture impact.** Если proving time > 30 sec, это влияет на:
   - Merkle tree depth (уменьшить с 20 до 15? = 32K capacity вместо 1M)
   - Circuit complexity (можно ли упростить Poseidon rounds в circuit?)
   - Parallelization strategy (multi-threaded arkworks?)

### Что делать

**Day 8 action item (после первого рабочего circuit):**

```bash
# Бенчмарк proving time
$ time cargo run --release --example prove_withdrawal

# Если > 30 sec:
# Option A: уменьши Merkle depth с 20 до 16 (65K capacity, ~50% faster)
# Option B: enable rayon feature в arkworks (parallel witness generation)
# Option C: уменьши Poseidon rounds в circuit (если используешь generic, не circom-compat)

# Если > 60 sec:
# Option D: уменьши Merkle depth до 12 (4K capacity — enough for demo)
# Option E: pre-compute proving key at build time (saves ~2 sec startup)
```

**В demo video:** добавь прогресс-бар или таймер. "Generating zero-knowledge proof... (this takes ~15 seconds on a laptop)". Это превращает ожидание в **demonstration of computational work** а не в awkward pause.

**В pitch deck (slide):**

```
"Proving time: ~15 seconds on a modern laptop
Verification: <200K compute units (~$0.0001)
Privacy: complete (sender, receiver, amount hidden)
Compliance: optional (user-controlled viewing keys)"
```

### Ещё 3 minor blind spots

**6.1: Devnet SOL funding для demo**

Ты будешь демонстрировать на devnet. Devnet SOL faucet имеет rate limits. Если во время live demo faucet не работает — deposit невозможен.

**Mitigation:** Pre-fund demo wallets с достаточным количеством devnet SOL (100+ SOL). Сделай это за день до demo. Имей backup wallet.

**6.2: Anchor program size limit**

Solana programs имеют 10MB deploy size limit (v2 loader), но Groth16 verifying keys могут быть большими. VK для circuit с ~100K constraints — ~1-2 KB (Groth16 VK = constant size, это плюс), но program + CPI + account validation + VK storage в PDA — проверь что суммарно вписываешься.

**Mitigation:** VK храни в отдельном PDA account, не hardcode в program bytecode. Program loads VK at runtime через account data.

**6.3: Event data size limit**

`DepositEvent` с encrypted_memo (200 bytes) + auditor_tag (64 bytes) + commitment (32 bytes) + root (32 bytes) + memo_ephemeral_pk (32 bytes) + timestamp (8 bytes) = ~368 bytes.

Solana log data limit = 10KB per instruction. Это ОК. Но если используешь Anchor events (`emit!`), проверь что Anchor не добавляет overhead который пушит тебя к лимиту при большом количестве событий.

**Mitigation:** Тест: emit 10 events в одной транзакции, проверь CU и data limits.

### Actionable next steps

1. **Day 8:** бенчмарк proving time. Если > 30 sec — уменьши Merkle depth
2. **Day 14:** бенчмарк полный pipeline (prove + submit + verify). Запиши цифры
3. **Day 25:** pre-fund demo wallets на devnet (100+ SOL each)
4. **Day 27:** dry-run demo с таймером. Если proving > 20 sec — добавь progress indicator
5. Добавь `benches/` directory с criterion benchmarks для proving time

---

## Summary: Decision Matrix

| # | Вопрос | Решение | Confidence |
|---|--------|---------|------------|
| 1 | Two killer features | ДА, разные layers: Memo=code, ASets=roadmap | 95% |
| 2 | Per-program pool MVP | ДА, shared=v0.3. Готовь ответ для судей | 90% |
| 3 | Fiat-Shamir checklist | Добавь PR_CHECKLIST + security.md | 99% |
| 4 | 32 дня реалистично? | Впритык. Circom fallback = insurance. Memo = первый cut | 70% |
| 5 | Freelancer Payroll | ДА, значительно лучше banya. Rename → private-payroll | 98% |
| 6 | Blind spot | Proving time не бенчмаркнут. Day 8 action item | 95% |

---

**Этот документ + PROJECT_BRIEF.md + REVIEW_AND_RECOMMENDATIONS.md = полный контекст для Claude Code. Начинай с Day-1 Validation Checklist.**
