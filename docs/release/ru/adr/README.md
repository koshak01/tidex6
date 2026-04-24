# Architecture Decision Records

> Каждый файл в этой директории фиксирует одно архитектурное решение: вопрос который задаётся, выбранный ответ, и последствия этого выбора.
>
> ADRs пишутся **до** кода который их реализует, чтобы будущие контрибьюторы (и мы сами в будущем) могли прочитать почему код выглядит так, как выглядит, без раскопок в commit history.

## Индекс

| # | Заголовок | Статус |
|---|---|---|
| [ADR-001](ADR-001-commitment-scheme.md) | Commitment scheme: только `Poseidon(secret, nullifier)` | Accepted |
| [ADR-002](ADR-002-merkle-tree-storage.md) | Merkle tree offchain, root ring buffer onchain | Accepted |
| [ADR-003](ADR-003-nullifier-storage.md) | Хранение nullifier'ов: один PDA на каждый nullifier | Accepted |
| [ADR-004](ADR-004-elgamal-bn254.md) | ElGamal на BN254 — кастомная dual-curve реализация | Accepted |
| [ADR-005](ADR-005-non-upgradeable-verifier.md) | Verifier program non-upgradeable после deploy | Accepted |
| [ADR-006](ADR-006-no-proc-macros.md) | Никаких proc macros в MVP — builder pattern взамен | Accepted |
| [ADR-007](ADR-007-killer-features.md) | Killer features: Shielded Memo (MVP) + Association Sets (v0.2) | Accepted — Memo отгружен |
| [ADR-008](ADR-008-pool-isolation.md) | Per-program pool в MVP, shared pool в v0.3 | Accepted |
| [ADR-009](ADR-009-proving-time-budget.md) | Proving time budget: Day-8 benchmark, 30 секунд acceptance | Accepted |
| [ADR-010](ADR-010-memo-transport-via-spl-memo.md) | Транспорт memo через SPL Memo Program (без редеплоя верификатора) | Accepted |
| [ADR-011](ADR-011-relayer-architecture.md) | Архитектура релаера — fee внутри circuit + reference-сервис | Accepted |

## Формат

Каждый ADR следует одной структуре:

- **Status** — Accepted / Superseded / Deprecated
- **Date** — когда решение было принято
- **Context** — какой вопрос задаётся, почему сейчас, какие альтернативы существуют
- **Decision** — что было выбрано
- **Consequences** — positive, negative, neutral
- **Related** — cross-references на другие ADRs и документы

## Когда писать новый ADR

- Делается нетривиальный архитектурный выбор
- Решение будет сложно отменить позже
- Будущие контрибьюторы спросят "почему это сделано так?"
- Выбор который сейчас выглядит очевидным может выглядеть неправильным через полгода без контекста

## Когда НЕ писать ADR

- Implementation детали которые можно изменить без архитектурного impact
- Naming conventions и style решения (использовать style guide)
- Library version pins (использовать комментарии в Cargo.toml)
- Bug fixes (использовать commit messages)
