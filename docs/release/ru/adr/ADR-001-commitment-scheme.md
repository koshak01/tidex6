# ADR-001: Commitment scheme — только `Poseidon(secret, nullifier)`

**Status:** Accepted
**Date:** 2026-04-09

## Context

Privacy-preserving shielded pool нуждается в commitment scheme который скрывает данные депозита, но при этом позволяет депозитору позже доказать ownership и потратить депозит. Commitment — это то, что хранится в Merkle tree, и это публичный якорь который связывает депозит с его withdrawal — не раскрывая эту связь внешним наблюдателям.

Два вопроса требуют ответов:

1. Что идёт внутрь commitment hash?
2. Где живут вспомогательные поля (auditor tag для selective disclosure, encrypted memo)?

MVP использует **фиксированные деноминации** (0.1 / 1 / 10 SOL) — см. ADR-007 косвенно. Это критично для ответа ниже: с фиксированными деноминациями amount публично известен программе (она видит переданные lamports) и не нуждается в доказательстве внутри ZK circuit.

## Decision

Commitment — это Poseidon hash от двух секретных значений и только от них:

```
commitment = Poseidon(secret, nullifier)
```

- `secret` — 32 случайных байта сгенерированных депозитором
- `nullifier` — 32 случайных байта сгенерированных депозитором

Auditor tag и encrypted memo, когда они присутствуют, хранятся как **отдельные поля** в `DepositEvent` struct, не внутри commitment:

```rust
pub struct DepositEvent {
    pub commitment: [u8; 32],          // Poseidon(secret, nullifier) — идёт в Merkle tree
    pub root: [u8; 32],
    pub leaf_index: u64,
    pub timestamp: i64,
    pub auditor_tag: Option<Vec<u8>>,  // ElGamal ciphertext, НЕ в commitment
    pub encrypted_memo: Option<Vec<u8>>,
    pub memo_ephemeral_pk: Option<[u8; 32]>,
}
```

## Consequences

**Positive:**
- ZK circuit минимален: доказать знание `(secret, nullifier)` такого что `Poseidon(secret, nullifier)` равно листу в Merkle tree, и что `Poseidon(nullifier)` равно публичному `nullifier_hash`. Мало constraints, низкий CU cost на верификацию, маленькая attack surface.
- Privacy слой (Merkle tree + nullifiers) полностью отвязан от disclosure слоя (auditor tag + memo). Баг в disclosure слое не может скомпрометировать privacy пользователей, которые не opt'нулись в disclosure.
- Auditor tag и memo могут эволюционировать независимо от circuit. Добавление нового memo encoding не требует нового trusted setup.

**Negative:**
- Эта commitment scheme **валидна только для фиксированных деноминаций**. Когда v0.3 введёт переменные деноминации, потребуется новый commitment который включает Pedersen amount commitment + range proof, вместе с новым circuit и новой trusted setup ceremony.
- Auditor tag не связан с commitment криптографически. Злонамеренный indexer или relayer может в принципе уронить tag из event log не влияя на валидность депозита. Mitigation: интеграторы верифицируют event log напрямую через RPC, не через third-party indexer которому не доверяют.

**Neutral:**
- Amount публично видим на уровне программы (программа видит переданные lamports), поэтому наблюдатели могут категоризировать депозиты по деноминации. Это то же свойство которое всегда имели fixed-denomination pools, и это то что вообще включает fixed-anonymity-set модель.

## Related

- [ADR-002](ADR-002-merkle-tree-storage.md) — где commitment хранится
- [ADR-003](ADR-003-nullifier-storage.md) — как nullifier проверяется при withdrawal
- [ADR-007](ADR-007-killer-features.md) — Shielded Memo как вспомогательное поле (MVP)
- [PROJECT_BRIEF.md §4.3](../PROJECT_BRIEF.md) — обзор архитектуры
