# Runbook: финализация церемонии и деплой нового верификатора

Внутренний операторский документ (не публикуется). Публичная процедура —
`docs/release/CEREMONY.md`; здесь — точные команды и порядок действий оператора.
ADR-017 stages 1–2 реализованы и проверены end-to-end локально 2026-07-17.

## Предусловия

- [ ] Схема `WithdrawCircuit<20>` ЗАМОРОЖЕНА (ADR-017 §5) — с момента genesis
      ни одного изменения circuit/arkworks-версии. Любое изменение = re-run
      всей церемонии.
- [ ] `mpc.rs` прошёл `PR_CHECKLIST_PROOF_LOGIC` (двухревьюерная политика) —
      TRUST-CRITICAL, до того как VK начнёт охранять реальные деньги.
- [ ] Собрано достаточно вкладов (цель: 10–20+ независимых; см. Discord-план
      `_analysis/DISCORD_CEREMONY_ANNOUNCE.md`).
- [ ] nginx `/transcript/` работает (публичная цепочка скачивается), в
      `log.json` вклады совпадают с `ceremony_verify` выводом.

## Шаг 1 — объявить drand-раунд R (заранее!)

Выбрать БУДУЩИЙ раунд (например, +7 дней от анонса). drand mainnet
(League of Entropy, 30-секундные раунды, genesis 2020-08-10):

```bash
# текущий раунд:
curl -s https://api.drand.sh/public/latest | jq .round
# раунд через N секунд ≈ latest + N/30
```

Объявить R публично (страница церемонии + Discord + GitHub) ДО его наступления.
После объявления R приём вкладов продолжается до наступления раунда.

## Шаг 2 — закрыть приём вкладов

В момент наступления R (или непосредственно перед) Гиперион останавливает
приём: проще всего — supervisor stop ws-процесса не нужен, достаточно НЕ
принимать вклады после снятия snapshot. Порядок:

```bash
# на проде (html-юзер):
cd /home/html && cp .tidex6-ceremony/current.state ceremony-snapshot.state
```

Все вклады после snapshot в финал не входят (честно предупредить на странице).

## Шаг 3 — получить beacon и финализировать

```bash
curl -s https://api.drand.sh/public/<R> | jq -r '.round, .randomness'

# локально или на проде (где лежит ~/.tidex6-ceremony/):
cargo run --release -p tidex6-circuits --bin ceremony_finalize -- <R> <randomness_hex>
# → пишет final.state + final.json, замораживает current.state
# → verify_chain обязан сказать OK, иначе НЕ продолжать
```

## Шаг 4 — проверить и извлечь VK

```bash
cargo run --release -p tidex6-circuits --bin ceremony_verify -- \
    ~/.tidex6-ceremony/genesis.state ~/.tidex6-ceremony/final.state

cargo run --release -p tidex6-circuits --bin ceremony_extract_vk
# → self-test (prove+verify withdraw) + перезапись
#   programs/tidex6-verifier/src/withdraw_vk.rs (+rustfmt)
```

Коммит нового `withdraw_vk.rs` с пометкой «ceremony VK» (заголовок файла уже
multi-party — пишется extract-инструментом).

## Шаг 5 — опубликовать цепочку (stage 3)

- [ ] `final.state` + `final.json` + `genesis.state` + `log.json` → коммит в
      GitHub-репо (`ceremony/` рядом с `withdraw_genesis.state`).
- [ ] Ссылки на странице церемонии переключить с current → final.
- [ ] Пост в Discord: «ceremony finalized at drand round R — verify it».

## Шаг 6 — новый верификатор (stage 4)

По deploy-runbook (memory: reference_deploy_runbook) + ОБЯЗАТЕЛЬНО
`cargo audit` перед финализацией (memory: cargo_audit_before_final):

1. `anchor build` верификатора с церемониальным VK; новый Program ID
   (keypair сгенерировать заранее, Petr деплоит сам).
2. Деплой на mainnet, прогон deposit+withdraw на новом верификаторе
   (тест-кошелёк Petr).
3. OtterSec source-verify (`solana-verify build` через Docker Desktop).
4. Миграция пулов/конфигов: operator config.toml + tidex6-web + релеер +
   registry (`network.rs`) — новый verifier ID.
5. Прод-проверка полного two-layer flow.
6. `solana program set-upgrade-authority --final` — renounce. Точка невозврата.
7. Снять «DEVELOPMENT ONLY» маркировки: `README.md`, `security.md` §1.4,
   `ROADMAP.md`, страница церемонии («what we run today»).

## Откат / нештатное

- Финализация не прошла verify_chain → НЕ публиковать, разбираться (final.state
  не записывается при провале — инструмент сам не даст).
- Extract self-test упал → setup битый, церемония re-run (вероятность ~0 при
  прошедшем verify_chain; означало бы баг в mpc.rs).
- После renounce отката НЕТ — поэтому шаги 2–5 из деплой-чеклиста строго до
  шага 6.
