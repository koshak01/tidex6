# ADR-009: Proving time budget — Day-8 benchmark, 30 секунд acceptance

**Status:** Accepted
**Date:** 2026-04-09

## Context

Стоимость верификации Groth16 proof на Solana well-understood: меньше 200K compute units, детерминистично, предсказуемо. Стоимость *генерации* Groth16 proof off-chain редко бенчмаркается рано в проекте — и эта пропуска укусила больше одного ZK проекта в момент демо.

Для tidex6 withdrawal circuit включает:
- Merkle inclusion proof для глубины 20 (~20 hash операций внутри circuit)
- Nullifier derivation
- Poseidon hashing нескольких field elements
- Всё компилируется в R1CS constraints

Грубые оценки для arkworks Groth16 proving time:

| Сложность Circuit | Constraints | Mid-range laptop |
|---|---|---|
| Toy circuit (один Poseidon) | ~5K | 1–2 сек |
| Tornado-style withdraw | ~30K | 8–15 сек |
| Withdraw + auditor proof | ~50K | 15–30 сек |
| Полный withdraw, depth-20 Merkle, все features | ~100K | 30–60 сек |

30–60 секундное ожидание во время живого демо — это UX disaster. Судья смотрит на "Generating proof..." строку и либо теряет интерес, либо предполагает что программа зависла. Это нужно измерить рано и budget'ировать явно.

## Decision

**Day-8 MVP timeline — обязательный proving-time benchmark.** Как только первый end-to-end withdrawal circuit компилируется и производит valid proof, запустить:

```bash
time cargo run --release --example prove_withdrawal
```

Acceptance threshold: **proof generation ≤ 30 секунд** на target reference машине (M1 Mac или эквивалент).

Если threshold превышен:

| Измеренное время | Действие |
|---|---|
| 30–45 сек | Включить parallel features в arkworks (`rayon`). Re-benchmark. |
| 45–60 сек | Уменьшить Merkle depth с 20 до 16 (capacity падает до ~65K листьев, всё ещё fine для MVP). Re-benchmark. |
| > 60 сек | Уменьшить Merkle depth до 12 (~4K листьев, достаточно только для demo). Задокументировать уменьшение в security.md. План оптимизировать для v0.2. |

Demo video должно включать явный progress indicator во время proof generation (`[Generating zero-knowledge proof — ~15s on a laptop]`). Это конвертирует awkward pause в *демонстрацию computational work* и образовывает аудиторию о ZK proving стоимости.

Pitch deck включает benchmark слайд с измеренными числами:

```
Proof generation:  ~15 секунд (M1 laptop)
Verification:      <200K compute units (~$0.0001)
Privacy:           Complete — sender, receiver, amount hidden
Compliance:        Optional — user-controlled viewing keys
```

## Consequences

**Positive:**
- Проблема proving time поймана на день 8, не на день 30 (день подготовки демо).
- Конкретные числа в pitch deck — судьи доверяют измеренным benchmarks больше чем handwaved оценкам.
- Merkle depth становится явным, tunable параметром, а не скрытой константой. Будущие версии могут пересмотреть.
- Demo video устанавливает правильные ожидания — "это занимает 15 секунд потому что это настоящая криптография, не fake анимация".

**Negative:**
- Уменьшение Merkle depth уменьшает anonymity-set capacity. Это реальная privacy цена. Mitigation: задокументировать tradeoff явно в `security.md`, и трактовать depth 20 как v0.2 target если MVP должен отгружаться на depth 16 или ниже.
- Day-8 benchmark требует чтобы circuit работал end-to-end к этому моменту. Это тянет integration deadline вперёд и создаёт schedule pressure на ранней фазе.

**Neutral:**
- 30-секундный threshold arbitrary но defensible: это самая длинная пауза которую живое демо может поглотить не теряя зал.
- Proving time — это функция от hardware prover'а. Мы benchmark'аем на reference машине чтобы установить публичное число, но реальные пользователи на медленнее hardware увидят более длинные времена. Pitch deck и документация должны делать это явным.

## Related

- [ADR-002](ADR-002-merkle-tree-storage.md) — выбор Merkle depth
- [ADR-005](ADR-005-non-upgradeable-verifier.md) — баги пойманные на Day-8 — это баги которые не отгружаются в immutable verifier
- [PROJECT_BRIEF.md §11](../PROJECT_BRIEF.md) — security posture ссылается на этот benchmark
- [security.md](../security.md) — anonymity-set warnings привязанные к выбору Merkle depth
