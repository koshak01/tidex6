# Final Demo Video — сценарий записи (RU)

**Длительность:** ~3:00 (формат Colosseum Project Submission)
**Формат:** screen recording (QuickTime → New Screen Recording → 4K)
**Без voiceover** — весь нарратив в YouTube description + chapters
**YouTube title:** `tidex6 — privacy framework for Solana | Live mainnet demo`
**Доступ:** **unlisted** (как и Week-1..4 — судьи получают ссылку через Colosseum form)

> Старые сценарии `DEMO_VIDEO_SCRIPT.md` и `DEMO_VOICEOVER_RU.md` от 10 апреля
> устарели (нет WASM, relayer, accountant в браузере, tip-jar). Не используем.
> Этот файл — единственная актуальная версия.

---

## Структура (7 модулей + intro + финал)

| Время | Сцена | Что показывает |
|---|---|---|
| 0:00–0:15 | Intro: landing | tidex6.com главная, slogan, footer (Solscan + Verified ✓) |
| 0:15–0:35 | Wallet + invite | Connect Phantom → Request Invite → одобрено |
| 0:35–1:10 | Shielded deposit | `/app/`, 0.1 SOL + memo + auditor pubkey → note |
| 1:10–1:45 | Withdraw via relayer | WASM proof в браузере, Activity log с relayer fee-payer |
| 1:45–2:00 | Relayer service | `relayer.tidex6.com/health` + `/stats` в новой вкладке |
| 2:00–2:25 | Accountant scan | `/accountant/`, paste viewing key, decrypted memos table |
| 2:25–2:45 | CPI integration | Solscan tip-jar + OtterSec verified + строки CPI в коде |
| 2:45–3:00 | Closing card | Slogan + URLs |

---

## Atom-блоки (вставить заранее)

```
═══════════ БЛОК 1: AUDITOR PUBLIC key (Сцена 3 — Deposit form) ═══════════
[взять из ~/.tidex6/identity.json → "auditor_public_key"]


═══════════ БЛОК 2: AUDITOR SECRET key (Сцена 6 — /accountant/) ═══════════
[взять из ~/.tidex6/identity.json → "auditor_secret_key"]


═══════════ БЛОК 3: memo текст (Сцена 3) ═══════════
Final demo May 2026


═══════════ БЛОК 4: recipient pubkey (Сцена 4 — Withdraw form) ═══════════
[твой второй кошелёк, например ED1HHGK6evjLyFCF9jWw8iXjAXfi2Xz4zaTHMcBNzaK9]
```

---

## Pre-flight checklist (за 30 минут до записи)

- [ ] Phantom Лены ≥ 0.3 SOL
- [ ] `curl https://relayer.tidex6.com/health` → `{"status":"ok"}`
- [ ] `tidex6.com/app/` грузится с актуальным WASM
- [ ] В Phantom приглашение **уже одобрено** (не первый раз)
- [ ] `~/.tidex6/identity.json` под рукой (для блоков 1 и 2)
- [ ] Все URLы открыть в отдельных tab'ах заранее:
  - `https://tidex6.com`
  - `https://tidex6.com/app/`
  - `https://tidex6.com/accountant/`
  - `https://relayer.tidex6.com/health`
  - `https://relayer.tidex6.com/stats`
  - `https://solscan.io/account/2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C`
  - `https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`
  - `https://verify.osec.io/status/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`
- [ ] Закрыть все лишние вкладки/уведомления, скрыть Dock
- [ ] Тёмная тема в Chrome
- [ ] Окно браузера 1920×1080 центровано (или 4K full)
- [ ] iTerm с открытым `programs/tidex6-tip-jar/src/lib.rs` в редакторе

---

## Сцена 0 — Intro / Landing (0:00–0:15)

1. Открыта `tidex6.com` главная
2. Скролл сверху до видимости hero-блока (slogan «I grant access, not permission»)
3. Чуть скролл до footer, **подержать на строке** «Program: 2qEm…cU9C · Security.txt ✓ · Verified ✓»

Цель: первые 15 секунд — «вот сайт, вот mainnet, вот verified».

---

## Сцена 1 — Wallet + Invite (0:15–0:35)

1. Click `Launch App` или `Acc` в хедере → переход на `/app/`
2. Состояние «Wallet not connected» → click **Connect Wallet**
3. Phantom popup → approve
4. Wallet pubkey появляется в правом верхнем углу
5. **Подержать на Activity log** строке `Invite approved. Welcome!` 2 сек

(Если invite **не одобрен** — flow «Request Invite» → Telegram bot approval. Но для демо лучше иметь уже approved кошелёк.)

---

## Сцена 2 — Shielded Deposit (0:35–1:10)

1. На `/app/`, в Deposit форме:
   - Denomination: `0.1 SOL`
   - Memo: вставить **БЛОК 3** (`Final demo May 2026`)
   - Auditor public key: вставить **БЛОК 1**
2. Click **Deposit**
3. Phantom popup → approve transaction
4. **Подержать на Activity log** 4-5 сек, видны строки:
   - `Encrypting memo + generating note...`
   - `Deposit confirmed! Tx: <signature>`
5. Note выпадает в зелёный блок «Your Deposit Note»
6. Click **Copy** на кнопке справа от note — show toast / copy confirmation

---

## Сцена 3 — Withdraw via Relayer (1:10–1:45)

1. Note **уже скопирован** в clipboard из предыдущей сцены — paste в Withdraw textarea (правая колонка)
2. Recipient: вставить **БЛОК 4** (другой кошелёк)
3. Click **Withdraw via relayer**
4. **Подержать на Activity log** 8-10 сек, видны самые важные строки:
   - `Withdraw — generating zero-knowledge proof IN BROWSER...`
   - `Proof generated in ~1700 ms`
   - `Submitting via relayer.tidex6.com (we pay the fee) ...`
   - `Withdraw confirmed! Tx: <signature>`
   - `Fee-payer in this tx: relayer.tidex6.com (your wallet did not sign)`
   - `Message from sender: Final demo May 2026`
5. Сверху появляется зелёная плашка «Withdrawn successfully via relayer.tidex6.com! Message from sender: …»

---

## Сцена 4 — Relayer service (1:45–2:00)

1. Switch на вкладку `relayer.tidex6.com/health` — JSON `{"status":"ok"}`, **подержать 3 сек**
2. Switch на `relayer.tidex6.com/stats` — JSON `{balance_sol, processed_24h, current_rps}`, **подержать 4 сек**

Цель: показать что relayer — **открытый сервис**, любой может проверить.

---

## Сцена 5 — Accountant scan (2:00–2:25)

1. Click `Acc` в хедере → переход на `/accountant/`
2. Поле `secret key` (password input) → paste **БЛОК 2**
3. Denomination: `0.1 SOL`
4. Click **Scan**
5. Loader → таблица с decrypted memos
6. **Подержать на таблице 8 сек** — особенно подсветить строку `Final demo May 2026` (тот же memo из Сцены 2)

---

## Сцена 6 — CPI integration (tip-jar) (2:25–2:45)

1. Switch на вкладку `solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x` — **подержать на Verified Build бейдже 3 сек**
2. Switch на `verify.osec.io/status/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x` — **подержать на `Verified ✓` 3 сек**
3. Switch на iTerm/RustRover с открытым `programs/tidex6-tip-jar/src/lib.rs`
4. Скролл до строк CPI:

   ```rust
   tidex6_verifier::cpi::deposit(
       CpiContext::new(verifier_program, ctx.accounts.into_deposit_ctx()),
       commitment,
       memo_payload,
   )?;
   ```

5. **Подержать на этих строках 5 сек**

---

## Сцена 7 — Closing card (2:45–3:00)

Чёрный экран → белыми буквами:

```
       I grant access, not permission.

       tidex6.com  ·  Solana mainnet
       github.com/koshak01/tidex6
```

Висит **3 сек минимум**.

---

## YouTube description (EN, готов к copy-paste)

```
tidex6 — a Rust-native privacy framework for Solana.

Built solo for the Solana Foundation Colosseum Frontier hackathon
(April 6 – May 11, 2026). The full stack is live on Solana mainnet
right now and you are watching real transactions.

What you see in this video, in order:

00:00  The landing page. Verifier program 2qEm...cU9C is deployed
       on mainnet, OtterSec-verified, with security.txt embedded.

00:15  Wallet connection. Phantom integrated through Solana wallet
       adapter. Invite-gated for the demo period — every approval
       passes through a Telegram bot the developer controls.

00:35  Shielded deposit. The user picks a fixed denomination
       (0.1 / 0.5 / 1 / 10 SOL), writes a memo, and pastes their
       auditor's public key. The result is an opaque hex note —
       there's nothing for a chain-watcher to read.

01:10  Withdraw via relayer. The Groth16 proof is generated
       IN THE BROWSER (about 1.7 seconds on M-series CPUs).
       The user's secret never leaves the tab — you can verify
       this yourself: the WebAssembly module's import set
       contains zero network APIs (fetch, WebSocket,
       XMLHttpRequest). Confinement is provable, not asserted.
       The transaction is then signed by relayer.tidex6.com,
       not by the user's wallet — your address never appears
       as the fee-payer.

01:45  The relayer is a public service with open endpoints.
       /health returns liveness, /stats returns balance and
       throughput. Anyone can run their own instance — the
       reference one is open-source under MIT/Apache-2.0.

02:00  The accountant page. The fund (or its auditor) pastes
       the matching secret key, picks a denomination, hits Scan,
       and gets back the full table of memos addressed to them
       — decrypted client-side, with on-chain transaction
       signatures. Privacy by default, transparency by choice.

02:25  CPI integration. tidex6 ships as a primitive, not an app.
       The reference example — tip-jar at 5Woh...9b9x — is a
       third-party Anchor program that uses the verifier via
       Cross-Program Invocation. About eighty lines of Rust to
       make any Solana program accept private payments.

02:45  Closing. I grant access, not permission.


═══════════════════════════════════════════════════════════════
LINKS
═══════════════════════════════════════════════════════════════

Verifier program (the one that checks proofs and holds the SOL):
  https://solscan.io/account/2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C
  https://verify.osec.io/status/2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C

Tip-jar reference (CPI integration example):
  https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x
  https://verify.osec.io/status/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x

Source code (MIT / Apache-2.0):
  https://github.com/koshak01/tidex6

Live application:
  https://tidex6.com/

Reference relayer:
  https://relayer.tidex6.com/health
  https://relayer.tidex6.com/stats


═══════════════════════════════════════════════════════════════
USE CASES
═══════════════════════════════════════════════════════════════

The same primitive serves three families of users out of the box:

1. Private personal payments. A user sending money to family
   in a different jurisdiction without exposing the link
   between sender and recipient on the public chain.

2. Creator economy. Tip jars, subscription protocols, NFT
   royalty splitters — anyone who accepts crypto can become
   tidex6-aware in about thirty lines of Rust through CPI.

3. Transparent funds with private donors. A donation fund
   publishes one address forever instead of rotating wallets.
   Donors send shielded deposits. The fund hands one auditor
   key to its accountant — the auditor sees every contribution
   with date, amount, and memo, the public sees nothing. Privacy
   by default, transparency by choice — both at the same time.


═══════════════════════════════════════════════════════════════
ARCHITECTURE
═══════════════════════════════════════════════════════════════

Curve:           BN254 (alt_bn128 syscalls on Solana)
Proof system:    Groth16 via groth16-solana
Hash:            Poseidon, circom-compatible (light-poseidon
                 + solana-poseidon syscall, byte-identical)
Tree:            Append-only Merkle, depth 20 (~1M leaves),
                 last 30 roots cached on-chain
Nullifier:       One PDA per used nullifier (anti double-spend)
Memo:            AES-256-GCM envelope, padded to 286 bytes,
                 ECDH wrap-K to recipient + optional auditor

Verifier program is non-upgradeable after the final lock —
no backdoor, no key escrow, no recovery service.


═══════════════════════════════════════════════════════════════

I grant access, not permission.
```

---

## Чеклист после записи

- [ ] Длина 2:55–3:05
- [ ] Активность плотная — нет dead air ≥ 3 секунд
- [ ] Все Activity log важные строки читаемы (zoom через iMovie)
- [ ] Финальный экран висит ≥ 3 секунды
- [ ] Описание YouTube — обновить с реальными tx-сигнатурами Сцены 2 + Сцены 3
- [ ] Установить chapters (timestamps) в YouTube Studio — точно как в description
- [ ] Загрузка **unlisted** (как и Week-1..4) — судьи получают ссылку через Colosseum form
- [ ] Добавить запись в `video/PROGRESS_VIDEOS.md` (отдельная секция Final Demo)
- [ ] URL финального видео — в Colosseum submission form
