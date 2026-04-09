# ADR-003: Хранение nullifier'ов — один PDA на каждый nullifier

**Status:** Accepted
**Date:** 2026-04-09

## Context

Withdrawal должен раскрыть `nullifier_hash` чтобы программа могла предотвратить двойную трату того же депозита. Вопрос: как программа отслеживает какие nullifier'ы уже использованы?

Три варианта:

1. **Bloom filter** в одном аккаунте.
   - Pros: O(1) проверка, фиксированный размер аккаунта
   - Cons: false positives (реальный withdrawal может быть некорректно отклонён если его nullifier коллизирует с другим), filter деградирует по мере заполнения, сложно правильно размерить не зная финального количества withdrawals

2. **Vector of nullifiers** в одном растущем аккаунте.
   - Pros: нет false positives
   - Cons: O(n) проверка, аккаунт растёт неограниченно, упирается в Solana account size limits, делает программу bottleneck

3. **Один PDA на каждый использованный nullifier**, детерминистические seeds, пустые данные.
   - Pros: O(1) проверка (try-create-PDA), нет false positives, нет одного аккаунта растущего навсегда, parallelizable между withdrawals
   - Cons: per-withdrawal storage cost (~0.00089 SOL для rent-exempt PDA)

## Decision

Вариант 3: один PDA на каждый использованный nullifier.

```rust
seeds = [b"nullifier", nullifier_hash.as_ref()]
data  = [] // пусто (rent-exempt minimum, ~890 bytes)
```

- Withdrawal инструкция делает `try_create_pda` для nullifier.
- Если creation успешен → nullifier не использован → withdrawal продолжается.
- Если creation неудачен (аккаунт уже существует) → nullifier использован → withdrawal отклоняет с `NullifierAlreadyUsed`.

## Consequences

**Positive:**
- Стандартный Anchor / Solana паттерн. Сложно облажаться. Auditable.
- O(1) lookup. Нет глобального state для координации. Perfectly parallelizable между withdrawals.
- Нет false positives. Withdrawal не может быть некорректно отклонён из-за hash коллизии (Poseidon collision resistance).
- Каждый nullifier — отдельный аккаунт, поэтому программа не владеет растущей структурой данных требующей миграции по мере масштабирования протокола.

**Negative:**
- Storage cost ~0.00089 SOL на withdrawal. На MVP масштабе (сотни withdrawals на devnet) это пренебрежимо. На production масштабе (миллионы withdrawals на mainnet) это набегает в тысячи SOL заблокированного rent. Mitigation: это явный v0.3 design item — исследовать compressed-account паттерны для уменьшения per-nullifier rent.
- Накопленные nullifier PDAs растут неограниченно за время жизни протокола. Это фундаментально для anti-double-spend свойства и не может быть избегнуто в любой системе которая хочет разрешить historical withdrawals.

**Neutral:**
- Rent за nullifier PDAs оплачивает withdrawer (или relayer от имени withdrawer'а, удерживается из суммы withdrawal). Это та же модель, которую всегда использовали Tornado-style mixers.
- Для v0.3 пересмотрим nullifier storage и рассмотрим compressed accounts или другие техники для уменьшения per-nullifier cost. Изменение будет backward compatible: старые PDAs продолжат работать, новые используют новый механизм.

## Related

- [ADR-001](ADR-001-commitment-scheme.md) — как nullifier связан с commitment
- [ADR-002](ADR-002-merkle-tree-storage.md) — другая половина deposit-withdraw криптографии
- [PROJECT_BRIEF.md §4.5](../PROJECT_BRIEF.md) — секция nullifier storage
