# ADR-004: ElGamal на BN254 — кастомная dual-curve реализация

**Status:** Accepted
**Date:** 2026-04-09

## Context

Selective disclosure (auditor tag в `DepositEvent`) требует асимметричного шифрования: депозитор шифрует deposit metadata под публичным ключом аудитора, и только аудитор (со своим приватным ключом) может расшифровать сканируя chain events.

Естественный примитив — **ElGamal encryption** — additive homomorphic, well-studied, подходит к кривой которую мы уже используем для Groth16 (BN254).

Проблема: **production-ready Rust крейта для ElGamal на BN254 не существует.** Все основные Rust ElGamal имплементации таргетят Curve25519 / Ristretto, что несовместимо с нашими Solana syscalls и нашим Groth16 circuit field. Нам приходится писать свой.

Второе соображение: in-circuit операции (где ElGamal randomness или auditor-key derivation должны быть сделаны внутри Groth16 proof) prohibitively expensive на BN254 G1 напрямую, потому что BN254 group operations не нативны для BN254 scalar field. Стандартный fix — использовать **вторую кривую** чьё base field равно BN254's scalar field, поэтому её scalar multiplications становятся дешёвыми field operations внутри circuit. Эта кривая — **Baby Jubjub** (Twisted Edwards кривая), доступная как `ark-ed-on-bn254`.

## Decision

Dual-curve подход:

- **BN254 G1 (`ark-bn254::G1Projective`)** — используется для on-chain ElGamal ciphertext который аудитор расшифровывает off-chain. Стандартный additive ElGamal: кодировать сообщение `m` как `m·G`, шифровать как `(r·G, m·G + r·PK_auditor)`. Public key на G1.

- **Baby Jubjub (`ark-ed-on-bn254`)** — используется для in-circuit операций: ECDH key derivation для encrypted memo, in-circuit обработка auditor key, и любые будущие selective-disclosure операции которые должны быть доказаны внутри Groth16 circuit.

Обе кривые подключены через `tidex6-core::elgamal` с чистым API. Пользователь `tidex6-client` не видит выбор кривой — он просто вызывает `pool.deposit().with_auditor(auditor_pubkey)` и SDK делает всё остальное.

Имплементация написана с нуля используя arkworks примитивы (`ark-bn254::G1Projective`, `ark-bn254::Fr`, `ark-ed-on-bn254`).

## Consequences

**Positive:**
- Получаем дешёвый in-circuit ECDH и key derivation через Baby Jubjub.
- Получаем on-chain-verifiable ElGamal ciphertexts через BN254 G1.
- Две кривые говорят друг с другом через shared scalar field, что и есть то, что поддерживает дизайн BN254.
- ElGamal живёт в application layer, не в consensus path. Баг в нашей ElGamal имплементации может leak'нуть amounts не тому пользователю, который opt'нулся в disclosure — но не может скомпрометировать privacy пользователей которые не opt'нулись, и не может позволить кражу.

**Negative:**
- **ElGamal код не аудирован.** Мы пишем криптографический код с нуля без независимого review. Стандартные риски применимы: timing side channels, malleability, edge cases на identity element, ошибки encoding.
- Мы должны явно пометить это как unaudited в:
  - Документации модуля `tidex6-core::elgamal`
  - `README.md`
  - `security.md`
  - Pitch deck (под "честны о ограничениях")
- Mainnet deployment требует либо независимого криптографического audit либо переключения на vetted альтернативу когда таковая появится.
- Two-curve dependency увеличивает surface area кода которую должны понимать reviewers.

**Neutral:**
- Baby Jubjub — стандартная companion кривая к BN254. Любой, кто работал с Ethereum-ecosystem ZK приложениями, видел этот паттерн раньше. Это не экзотика.
- Пользователь SDK не осведомлён о dual-curve дизайне. Сложность contained внутри `tidex6-core::elgamal`.

## Related

- [ADR-001](ADR-001-commitment-scheme.md) — auditor tag хранится отдельно от commitment
- [ADR-007](ADR-007-killer-features.md) — Shielded Memo также использует Baby Jubjub для ECDH
- [PROJECT_BRIEF.md §5.1](../PROJECT_BRIEF.md) — описание selective disclosure
- [security.md](../security.md) — unaudited cryptography disclaimer
