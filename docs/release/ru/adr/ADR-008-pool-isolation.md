# ADR-008: Per-program pool в MVP, shared pool в v0.3

**Status:** Accepted
**Date:** 2026-04-09

## Context

Privacy фреймворк на Solana сталкивается с фундаментальным архитектурным выбором: как программы интеграторов разделяют (или не разделяют) underlying anonymity set?

Два варианта:

1. **Per-program pool.** Каждый интегратор разворачивает отдельный pool. Депозиты их пользователей сидят в их собственном Merkle tree, отдельно от каждого другого integrator's tree. Anonymity set per pool = количество депозитов в этом одном pool.
   - Pros: тривиально реализовать, нет cross-program координации, нет shared state, изолированные failure modes
   - Cons: anonymity set фрагментируется по приложениям. Новое приложение начинает с anonymity set ≈ 1.

2. **Shared anonymity pool.** Все интеграторы кладут депозиты в одно общее Merkle tree. Anonymity set = всего депозитов по всей экосистеме.
   - Pros: anonymity set масштабируется линейно с adoption — каждое новое приложение усиливает privacy для каждого существующего пользователя. Network effect
   - Cons: сложная multi-program координация — кто владеет PDA, как конкурентные depositы sequence'ятся, как fees учитываются между интеграторами, как протокол обрабатывает versioning если один интегратор хочет upgrade а другой нет. Несколько дней архитектурной design работы только.

MVP timeline не может поглотить shared-pool сложность. Но shipping per-program-only без признания anonymity-set фрагментации был бы стратегической ошибкой — судьи зададут вопрос, и "мы об этом не подумали" — неправильный ответ.

## Decision

**Per-program pool в MVP. Shared anonymity pool спроектирован как v0.3 архитектурный target.** Проблема фрагментации признана явно и конвертирована в roadmap item с конкретным framing: *network effect для privacy.*

v0.3 design notes (сохранены в ROADMAP.md):
- Один singleton `tidex6-shared-pool` program
- Per-integrator deposit authority (CPI из integrator → shared pool)
- Unified nullifier set
- Append-only roots, indexer линеаризует deposits
- Migration path: существующие per-program pools продолжают работать; новые интеграторы выбирают isolated или shared при deploy; со временем shared становится default

## Consequences

**Positive:**
- MVP отгружается вовремя. Per-program pool — это textbook implementation pattern без экзотической сложности.
- v0.3 framing подготовлен заранее: *"чем больше apps интегрируют tidex6, тем сильнее становится privacy для всех пользователей. Network effect meets privacy."* Это конвертирует слабость фрагментации в forward-looking силу в pitch.
- Pool каждого интегратора независим: баг в одном pool не может задеть другой, всплеск нагрузки в одном не может starve другой, versioning решение в одном не propagate'ится.
- У нас есть подготовленный ответ на неизбежный вопрос судьи *"но anonymity set = 5 в день один — это не настоящая privacy"* — см. judge Q&A секцию в demo prep notes.

**Negative:**
- Day-one anonymity в любом одном pool маленький. Новый pool с 5–50 депозитами слабо анонимен в абсолютных терминах. Flagship пример (private-payroll) намеренно показывает это честно: pool Лены — это то что есть, и демо говорит откровенно о том что это значит и что починит v0.3.
- Два интегратора на tidex6 не могут разделить anonymity set в MVP. Они сидят в disjoint trees. MVP workaround нет.
- v0.3 архитектура нетривиальна, и мы commit'имся к ней не реализовав её. Риск: когда мы садимся строить shared pool, какое-то ограничение которое не предвидели делает это сложнее ожидаемого. Mitigation: v0.3 design пройдёт через свой собственный ADR перед реализацией.

**Neutral:**
- Per-program pool — это та же модель которую используют несколько production privacy приложений. Она работает на практике, даже если имеет drawback фрагментации.
- Shared-pool дизайн намеренно модульный: он может разрабатываться в отдельном repo, тестироваться независимо, и поставляться как новая программа. Он не требует breaking changes для per-program pools.

## Related

- [ADR-002](ADR-002-merkle-tree-storage.md) — Merkle tree storage применяется и к per-program, и к shared моделям
- [ADR-005](ADR-005-non-upgradeable-verifier.md) — verifier shared между всеми pools независимо от модели
- [ROADMAP.md "Later — v0.3+"](../ROADMAP.md) — shared anonymity pool указан как v0.3 deliverable
- [PROJECT_BRIEF.md §11](../PROJECT_BRIEF.md) — anonymity-set day-one warning в security posture
