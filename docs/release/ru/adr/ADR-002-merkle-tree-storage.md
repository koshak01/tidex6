# ADR-002: Merkle tree offchain, root ring buffer onchain

**Status:** Accepted
**Date:** 2026-04-09

## Context

Shielded pool нуждается в Merkle tree из commitments. Withdrawer доказывает inclusion в дерево как часть своего ZK proof. Вопрос: где живёт дерево?

Три варианта:

1. **Полное дерево onchain.** Каждый узел хранится как account data. Обновления делаются в программе.
   - Pros: trustless, нет внешней зависимости
   - Cons: чрезвычайно дорого (CU и rent), конкурентные depositы race'ятся, глубина ограничена compute budget

2. **Полное дерево offchain, без onchain якоря.** Indexer — источник истины.
   - Pros: дёшево, быстрые обновления
   - Cons: требуется доверие (indexer может врать о состоянии дерева)

3. **Гибрид: дерево offchain, недавние корни onchain.** Indexer поддерживает полное дерево; программа хранит ring buffer недавних корней и counter для следующего leaf index. Withdrawals ссылаются на любой недавний корень.
   - Pros: дешёвый onchain footprint, trustless верификация (proofs проверяются против onchain корней), нет race conditions
   - Cons: требует indexer для вычисления Merkle proofs

## Decision

Гибрид: вариант 3.

- **Offchain (indexer):** полное Merkle tree глубины 20 (~1M листьев), перестраивается из `DepositEvent` логов любым indexer node.
- **Onchain (state программы):** ring buffer последних **30 корней** + counter `next_leaf_index`. Это весь onchain Merkle state.
- **Deposit flow:** программа видит новый commitment, инкрементит `next_leaf_index`, вычисляет новый корень через onchain Poseidon syscall (или принимает client-computed корень валидируемый через recomputation), пушит новый корень в ring buffer.
- **Withdraw flow:** proof ссылается на один из 30 корней в буфере. Программа проверяет proof против этого корня.

## Consequences

**Positive:**
- Onchain footprint константный: 30 × 32 bytes для корней + 8 bytes для counter ≈ 968 bytes всего. Тривиально.
- Нет race conditions на конкурентных depositах — программа линеаризатор (она владеет `next_leaf_index`).
- Withdrawals могут использовать любой из 30 последних корней, давая клиентам ~минуты на генерацию proof без беспокойства об изменении состояния дерева под ними.
- Withdrawal proofs по-прежнему trustless: даже если indexer врёт, proof обязан верифицироваться против onchain корня, который может прийти только из реального `DepositEvent`.

**Negative:**
- Indexer — критическая инфраструктура. Без indexer withdrawer не может построить Merkle proof и не может вывести. Mitigation: indexer — это reference code (`tidex6-indexer`), запускается где угодно, протокол публикует детерминистичные инструкции для перестройки дерева из onchain событий. Любой может запустить свой.
- Клиент должен ждать пока indexer догонит последний `DepositEvent` перед генерацией proof против последнего корня. На практике это sub-second.
- Окно из 30 корней означает что клиент чья генерация proof занимает дольше чем ~30 депозитов в pool увидит как его proof устаревает и потребует regenerate против более нового корня.

**Neutral:**
- Глубина дерева 20 → ~1M листьев capacity. Для MVP demo и хорошо в v0.2 это комфортно.
- `next_leaf_index` растёт монотонно; протокол не поддерживает удаление листьев (Merkle tree append-only).

## Related

- [ADR-001](ADR-001-commitment-scheme.md) — что хранится в каждом листе
- [ADR-003](ADR-003-nullifier-storage.md) — другая половина anti-double-spend
- [PROJECT_BRIEF.md §4.4](../PROJECT_BRIEF.md) — секция Merkle tree
