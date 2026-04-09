# ADR-007: Killer features — Shielded Memo (MVP) + Association Sets (v0.2)

**Status:** Accepted
**Date:** 2026-04-09

## Context

MVP нуждается хотя бы в одной фиче помимо "ещё один shielded pool" которая даёт демо чёткий хук для аудитории. Два сильных кандидата всплыли во время review процесса:

1. **Shielded Memo** — зашифрованное memo до ~200 байт прикреплённое к каждому депозиту. Расшифровывается только владельцем соответствующего viewing key. Application-layer фича, нет влияния на ZK circuit. Оценка реализации: **1–2 дня**.

2. **Proof of Innocence (Association Sets)** — дополнительный ZK circuit который доказывает что депозит пользователя принадлежит курируемому подмножеству одобренных депозитов, не раскрывая какой именно депозит их. Compliance-by-choice без KYC. Оценка реализации: **5–7 дней** (новый circuit, новый trusted setup, offchain Association Set Provider сервис).

MVP timeline не вмещает оба. Выбор только одного создаёт tradeoff:

- **Только memo** → демо имеет работающую killer feature, но pitch теряет сильнейший ответ на *"как ты докажешь что твои средства чисты?"*
- **Только Association Sets** → сильный compliance story, но забирает весь MVP buffer и не оставляет места для polish.

## Decision

**Реализовать оба, но в разных слоях.**

- **Shielded Memo: отгружается в MVP коде.** Working, demonstrable фича в flagship примере. Появляется в `examples/private-payroll/` как зашифрованные memos которые Лена шлёт родителям и которые её бухгалтер позже расшифровывает. ECDH на Baby Jubjub + AES-256-GCM. ~1–2 дня работы.

- **Proof of Innocence: отгружается в roadmap и pitch deck, не в коде.** Спроектирован в архитектуре для v0.2, prominently позиционирован в `ROADMAP.md` и на отдельном pitch deck слайде. Pitch line: *"v0.2 ships the proof-of-innocence layer — users will be able to prove their funds are clean without revealing which deposit is theirs."*

MVP демо имеет одну работающую killer feature. Pitch deck имеет две — одну продемонстрированную в коде, одну продемонстрированную в плане.

## Consequences

**Positive:**
- Demo video имеет tangible "wow" момент (расшифровка memo на сцене).
- Pitch deck имеет и immediate value story (memo) и strategic vision story (proof of innocence).
- Memo и association sets обслуживают разные аудитории: memo говорит к *individual* use cases (freelancer + бухгалтер), association sets говорят к *институциональным* concerns (compliance, regulators).
- Memo — application-layer, поэтому не трогает circuit, trusted setup или verifier. Он не может создать регрессии в privacy core.

**Negative:**
- Pitch должен объяснить что proof of innocence — это "v0.2 designed but not implemented" — это softer claim чем "shipped today". Mitigation: назвать архитектуру, показать дизайн в pitch deck, commit'нуться к конкретному кварталу (Q3 2026).
- Две killer features увеличивают surface area которую мы должны объяснить в три минуты demo video. Solution: memo получает время демо, association sets получает один слайд и одно предложение.

**Neutral:**
- Split зеркалит архитектуру: memo живёт в `tidex6-core::memo`, association sets будут жить в `tidex6-circuits::association` когда landed. Оба — изолированные модули, ни один не блокирует другой.
- Решение может быть пересмотрено после MVP. Если Q3 2026 окажется иметь больше headroom чем ожидалось, association sets implementation двигается вверх. Если меньше, timeline держится.

## Related

- [ADR-001](ADR-001-commitment-scheme.md) — memo хранится как отдельное поле, не внутри commitment
- [ADR-004](ADR-004-elgamal-bn254.md) — memo использует ту же Baby Jubjub curve как in-circuit ECDH
- [PROJECT_BRIEF.md §5.2](../PROJECT_BRIEF.md) — описание Shielded Memo
- [PROJECT_BRIEF.md §5.3](../PROJECT_BRIEF.md) — описание Proof of Innocence v0.2
- [ROADMAP.md "Next — v0.2"](../ROADMAP.md) — Proof of Innocence как v0.2 deliverable
