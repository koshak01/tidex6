# PR Checklist: Proof Logic Changes

> **Когда использовать:** любой pull request который затрагивает proof logic, circuit definitions, transcript construction, или криптографические примитивы.
>
> **Почему:** одного пропущенного значения в Fiat-Shamir transcript было достаточно чтобы forge arbitrary zero-knowledge proofs в production системах на Solana всего в 2025 году. Этот checklist существует чтобы поймать этот класс ошибок до того как он отгружается.
>
> **Enforcement:** каждый PR который matchит scope выше проходит через этот checklist. Автор заполняет его в описании PR. Один дополнительный reviewer signs off на transcript construction перед merge.

---

## Rule 0

> **Anything the prover touches goes into the transcript.**
>
> *Всё что prover трогает — идёт в transcript.*

Если verifier использует значение, transcript обязан его bind'ить. Если prover вычисляет значение влияющее на proof, transcript обязан его absorb'ить **до** того как challenge сгенерирован.

Это одно правило ловит большинство реальных Fiat-Shamir багов. Каждый item ниже — это конкретный инстанс Rule 0 применённый к конкретному failure mode.

---

## Section 1 — CRITICAL (блокирует merge)

Эти items блокируют merge безусловно. Если любой из них не может быть отмечен правдиво, PR не готов.

- [ ] **Rule 0 enforcement.** Каждое значение вычисленное prover'ом — включая commitments, intermediate values, и sub-challenges в OR proofs — absorbed в transcript **до** того как соответствующий challenge сгенерирован. Без исключений. Если есть какой-либо sub-challenge где-либо в протоколе который prover генерирует, он в transcript.

- [ ] **Все public inputs absorbed.** Каждый public input verifier'а (nullifier hash, Merkle root, recipient address, denomination, любые auditor public keys, любые domain flags) включён в transcript. Пропуск public input позволяет proof reuse между разными statements.

- [ ] **Все commitments absorbed, включая intermediate.** В multi-round протоколах или composed proofs, каждый commitment на каждом round absorbed в том порядке в котором он произведён. Особое внимание к sigma OR proofs и composed протоколам — это именно то где жил 2025 Phantom Challenge баг.

- [ ] **Все group elements использованные в proof absorbed.** G1 и G2 points, ElGamal ciphertexts, Pedersen commitments — всё что является частью утверждения которое доказывается. Unabsorbed group element — это attack surface.

- [ ] **Domain separator присутствует.** Transcript начинается с уникальной domain separator строки в формате `"tidex6-v1-{circuit_name}"`. Это предотвращает cross-protocol proof replay, где proof валидный для одного circuit принят другим с похожей формой transcript.

- [ ] **Никакое prover-controlled значение не используется после challenge derivation без re-absorption.** Если prover вычисляет response после того как challenge сгенерирован, этот response не должен становиться input для *другого* challenge без явного absorption в transcript сначала. Это subtle и исторически вызывало баги в протоколах которые композируют несколько challenges.

---

## Section 2 — HIGH (блокирует merge без явного обоснования)

Эти items блокируют merge если автор не предоставит письменное обоснование в описании PR объясняющее почему item не применяется или обрабатывается где-то ещё.

- [ ] **Transcript order соответствует спецификации.** Порядок в котором absorbed значения имеет значение — разные порядки производят разные challenges, которые производят разные proofs. Порядок задокументирован в code комментариях и matchит spec в соответствующем ADR или PROJECT_BRIEF.

- [ ] **Никакого transcript reuse между independent proofs.** Если PR генерирует несколько proofs в одной транзакции, каждый proof начинается с fresh transcript (или чётко задокументированного fork базового transcript с уникальным суффиксом).

- [ ] **Field element encoding каноничен.** Field elements (`Fr`) absorbed в canonical форме. Если код использует non-default serialization (Montgomery form, little-endian vs big-endian), выбор задокументирован в комментарии и консистентен между всеми transcript операциями в PR.

- [ ] **Curve point compression консистентен.** При absorbing G1 points в transcript, код использует либо compressed либо uncompressed encoding консистентно. Смешивание compressed и uncompressed производит разные transcripts для математически идентичных proofs и это немедленный verification failure.

- [ ] **Public inputs для Groth16 сериализуются консистентно offchain и onchain.** Offchain prover и onchain verifier должны сериализовать public inputs в byte-for-byte одинаковом формате. Один off-by-one или различие в serialization convention молча отклоняет каждый proof.

---

## Section 3 — MEDIUM (требует review comment)

Эти items требуют review comment от автора acknowledging что ситуация рассмотрена, даже если ничего не изменилось.

- [ ] **Circuit constraint count стабильный или изменение задокументировано.** Если constraint count изменился с последнего PR на circuit, автор отмечает delta и причину. Неожиданные падения в constraint count могут указывать что security-critical проверка была случайно удалена.

- [ ] **Никакие redundant constraints не были удалены как "оптимизация".** Удаление "unused" constraints из ZK circuit — это один из классических способов молча сломать soundness. Если любой constraint был удалён, описание PR объясняет почему это было безопасно.

- [ ] **Witness generation код matchит circuit definition.** Offchain код который вычисляет witness values должен применять те же операции что circuit ожидает. Divergence производит valid-looking proof который доказывает не то утверждение — и этот proof верифицируется успешно, приводя к silent vulnerability. Автор вручную трассировал witness generation путь против circuit constraints.

- [ ] **Новые proof types имеют хотя бы один negative тест.** Для любого нового proof type или любой модификации существующего proof type, есть хотя бы один тест который конструирует намеренно tampered input и верифицирует что proof отклонён.

---

## Section 4 — META (merge hygiene)

- [ ] **Два reviewers подписали transcript construction.** Автор плюс один независимый reviewer. Никаких single-approval merges на proof-critical коде.

- [ ] **Regression test: honest proof верифицируется.** Тест который конструирует valid proof и подтверждает что verifier его принимает. Тривиально, но защищает от случайного breakage.

- [ ] **Regression test: tampered public input отклоняется.** Тест который конструирует proof и затем меняет один public input байт, подтверждая что verifier его отклоняет. Это ловит silent changes в том что proof на самом деле доказывает.

- [ ] **Regression test: reused nullifier отклоняется.** Тест который пытается withdraw с уже использованным nullifier, подтверждая что double-spend проверка срабатывает.

- [ ] **Документация обновлена.** Если PR меняет transcript construction, соответствующий ADR обновлён. Если PR вводит новый circuit, новый ADR написан.

- [ ] **Никаких неиспользуемых криптографических импортов.** Мёртвый криптографический код — это red flag: он предполагает что что-то было частично удалено и что-то ещё осталось висеть. PR не имеет `use` statements или dependencies которые больше не ссылаются.

---

## Исторический контекст

Этот checklist существует потому что Fiat-Shamir ошибки били production zero-knowledge системы на Solana в пределах последнего года. В апреле 2025 года ZK ElGamal proof программа на Solana имела пропущенные algebraic components в своём Fiat-Shamir transcript. Баг был пропатчен в течение 48 часов. В июне 2025 года та же программа пострадала от второго, более серьёзного бага: "Phantom Challenge" — prover-generated sub-challenge в sigma OR proof для fee validation не был absorbed в Fiat-Shamir transcript, позволяя arbitrary proof forgery. Это включило unlimited token minting. Затронутая программа была отключена на Solana mainnet на epoch 805.

Оба инцидента — это один класс бага: **значение которое prover контролирует не было в transcript**. Rule 0 выше существует чтобы ловить этот класс багов. Остаток checklist — это Rule 0 развёрнутый в конкретные инстансы.

Мы документируем этот исторический контекст не чтобы критиковать кого-то — ошибки были сделаны компетентными инженерами в production системе которая была reviewed. Мы документируем это чтобы наши собственные будущие инженеры понимали что эта категория failure реальна, случалась недавно, и может случиться с нами если мы не deliberate.

---

*tidex6.rs — I grant access, not permission.*
*См. также: [security.md](security.md) секция 2.1 для описания класса уязвимости.*
