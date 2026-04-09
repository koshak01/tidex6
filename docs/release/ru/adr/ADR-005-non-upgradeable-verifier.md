# ADR-005: Verifier program non-upgradeable после deploy

**Status:** Accepted
**Date:** 2026-04-09

## Context

Anchor программы upgradeable по умолчанию. Deployer держит upgrade authority key и может deploy новые версии программы под тем же program ID. Это удобно для разработки, но создаёт две проблемы для privacy протокола:

1. **Доверие:** пользователи должны доверять что upgrade authority никогда не задеплоит злонамеренную версию verifier (которая, например, принимает forged proofs и позволяет upgrade authority слить pool).

2. **Юридическая экспозиция:** в США ноябрьское 2024 года решение Fifth Circuit в *Van Loon v. Department of Treasury* установило что **immutable onchain code не может быть санкционирован как property под IEEPA** потому что он не может быть owned, controlled или excluded from use кем-либо. Критично, эта защита **не** применяется к mutable onchain коду — Treasury явно аргументировал что upgradeable programs остаются sanctionable, и суд этому не противоречил.

Для privacy протокола чьё value proposition включает сопротивление weaponization властями, immutability — не опция.

Solana предоставляет one-way операцию: `solana program set-upgrade-authority <PROGRAM_ID> --final` навсегда отзывает upgrade authority. После этого никто не может задеплоить новую версию программы под этим ID, никогда. Bytecode заморожен.

## Decision

`tidex6-verifier` блокируется через `solana program set-upgrade-authority --final` сразу после initial deployment. Verifier становится permanently immutable.

Это применяется к:
- Devnet deployment verifier (после MVP тестирования)
- Mainnet deployment verifier (когда MVP audit-ready)

Это **не** применяется к:
- Integrator программам (они принадлежат их разработчикам)
- Reference indexer / relayer (это offchain код, не onchain программы)
- SDK crates (это библиотеки, distributed через crates.io, версионируются нормально)

## Consequences

**Positive:**
- Криптографическая immutability: никто не может заменить verifier злонамеренной версией.
- Юридическая защита под прецедентом *Van Loon* (US Fifth Circuit jurisdiction). Verifier — это property которой никто не владеет и никто не может exclude from use.
- Сильное сообщение интеграторам: фундамент на котором они строят не может быть выдернут из-под них.
- Trust minimisation: пользователи не должны доверять deployer'у вести себя честно навсегда.

**Negative:**
- **Bug fixes требуют deploy новой verifier программы** под новым program ID. Старые integrator программы которые hardcode'ят старый verifier ID не получат автоматическую пользу от fix.
- Pool versioning становится v0.2 design item: PoolV1 (использует verifier-v1) и PoolV2 (использует verifier-v2) сосуществуют, и должен быть sweep механизм для пользователей мигрировать funds из V1 в V2.
- Все баги должны быть пойманы **до** deployment. Это поднимает планку для Day-1 Validation Checklist, Fiat-Shamir discipline, и trusted setup ceremony — см. ADR-009 и security model.
- Pre-mainnet audit становится обязательным и load-bearing. Нет опции "ship and patch".

**Neutral:**
- Программа интегратора остаётся upgradeable (или нет) на усмотрение интегратора. tidex6 mandates immutability только для shared verifier.
- Non-upgradeable verifier — это singleton на каждой сети. Все integrator программы CPI в один и тот же verifier.

## Related

- [ADR-006](ADR-006-no-proc-macros.md) — SDK mutable, verifier нет
- [ADR-009](ADR-009-proving-time-budget.md) — Day-8 validation gates которые защищают immutable verifier от shipping с багами
- [PROJECT_BRIEF.md §12](../PROJECT_BRIEF.md) — legal posture
- [security.md](../security.md) — security model и pre-deployment checklist
