# ADR-006: Никаких proc macros в MVP — builder pattern взамен

**Status:** Accepted
**Date:** 2026-04-09

## Context

Изначальное видение проекта включало набор процедурных macros которые позволили бы интегратору добавить privacy в свою Anchor программу одной аннотацией:

```rust
#[privacy_program]
pub mod my_program {
    #[private_deposit]
    pub fn contribute(ctx: Context<Contribute>, amount: u64) -> Result<()> {
        // ...
    }
}
```

Macros должны были:
- Парсить `#[program]` модуль интегратора
- Детектить функции помеченные `#[private_deposit]` и `#[private_withdraw]`
- Auto-генерировать PDA структуры (PoolState, MerkleRoot history, NullifierPDA, Vault)
- Auto-генерировать CPI вызовы в `tidex6-verifier`
- Auto-генерировать IDL extensions чтобы client tooling знало о новых аккаунтах
- Обрабатывать edge cases на function signatures, account contexts, lifetimes

Это серьёзный мини-компилятор. Реалистичная оценка: **2–3 недели** full-time работы для одного разработчика с proc-macro опытом. Для разработчика нового в `syn` / `quote` / `proc-macro2`, дольше.

MVP timeline — 32 дня для одного разработчика. Две-три недели только на macros — это **архитектурный rewrite** плана работы.

## Decision

Полностью вырезать proc macros из MVP. Заменить на **builder pattern** API экспонированный `tidex6-client`:

```rust
use tidex6::PrivatePool;

let pool = PrivatePool::new(&ctx)
    .denomination(LAMPORTS_PER_SOL)
    .with_auditor(auditor_pubkey)
    .build()?;

pool.deposit(&signer, secret, nullifier)?;
pool.withdraw(proof, recipient)?;
```

Интегратор пишет ~5 строк Rust для подключения tidex6 в свою программу вместо ~2 строк macro аннотаций. Получившаяся программа verbose но понятна, debuggable, и IDE-friendly.

Macros спроектированы в архитектуре для v0.2 как **ergonomic sugar поверх проверенного builder API**, не как замена ему. Они будут реализованы после поставки MVP, поверх кода который уже работает.

## Consequences

**Positive:**
- Экономит ~10 дней в MVP timeline. Это самая большая единая временная экономия от review pass.
- Builder pattern код debuggable как обычный Rust. Нет скрытого сгенерированного кода. IDE автокомплит работает. Compile errors указывают на исходную строку интегратора, не на macro invocation.
- Тесты — это обычные unit tests против обычных функций, не test harnesses для macro expansion.
- Macros построенные позже сидят на стабильном протестированном API. Они становятся incremental enhancement, не architectural foundation.
- Легче понимать для нового контрибьютора который ревьюит SDK.

**Negative:**
- Pitch line "add privacy in 2 lines of code" становится "add privacy in 5 lines of code". Чуть менее magical, но всё ещё credible.
- Некоторая verbosity в коде интегратора которую macros бы спрятали — явные builder calls, явная account context wiring.
- Мы несём один лишний design item в v0.2: построить macros которые изначальный brief обещал.

**Neutral:**
- Builder pattern — well-understood Rust idiom. Каждый Rust разработчик может его прочитать без изучения нового синтаксиса.
- Macro работа не потеряна — когда она landed в v0.2, это будет cleaner implementation потому что сидит поверх API который уже отгружен и видел реальное integrator usage.

## Related

- [ADR-005](ADR-005-non-upgradeable-verifier.md) — verifier заблокирован, но SDK остаётся mutable
- [PROJECT_BRIEF.md §8](../PROJECT_BRIEF.md) — секция Developer Experience показывающая builder код
- [ROADMAP.md "Next — v0.2"](../ROADMAP.md) — ergonomic macros указаны как v0.2 deliverable
