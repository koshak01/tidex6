# Week-4 Progress Video — сценарий записи (RU)

**Длительность:** ~1:50–2:00 (плотный монтаж, без `sleep` блоков как в Week-1)
**Формат:** screen recording (Mac → QuickTime «New Screen Recording» 4K)
**без voiceover** — весь нарратив в YouTube description.
**YouTube title:** `Week 4 — The secret never leaves the tab: WASM proving + accountant + CPI`
**Доступ:** unlisted (как Week-1/2/3) до момента когда пойдёт в Colosseum submission.

---

## Что показываем (4 сцены, не больше)

| # | Сцена | Время | Главное послание |
|---|---|---|---|
| 1 | WASM proving в браузере + DevTools imports | 0:00–0:25 | «secret never leaves the tab» — доказуемо |
| 2 | Browser deposit + withdraw via relayer | 0:25–0:55 | ~1.7s proof, Activity log с relayer fee-payer |
| 3 | Accountant scan в браузере | 0:55–1:30 | Замкнули trilogy «Лена → родители → Kai» в одной вкладке |
| 4 | tip-jar CPI на mainnet + OtterSec verified | 1:30–1:55 | «любой dev встраивает tidex6 за 80 строк Rust» |

Финал 1:55–2:00 — slogan card.

**Что в Week-4 НЕ показываем** (специально оставлено для финального Demo):
- Отдельную сцену про relayer (`/health`, `/stats`) — будет в 3-мин Demo
- Live-tx через tip-jar (CLI или TS-скрипт) — будет в 3-мин Demo

---

## Перед записью

- [ ] Залить Phantom Лены ≥ 0.3 SOL (на одну прогонку с запасом)
- [ ] Проверить `relayer.tidex6.com` жив: `curl https://relayer.tidex6.com/health`
- [ ] Проверить `tidex6.com/app/` грузится с актуальным WASM (открыть DevTools
      → Network → WASM-файл `200`, integrity check pass)
- [ ] Сгенерить keypair для accountant-сцены: `tidex6 keygen --output /tmp/kai.json`
- [ ] Закрыть все лишние вкладки/уведомления, скрыть Dock
- [ ] Тёмная тема в Chrome (footer лучше выглядит на чёрном)
- [ ] Окно браузера 1920×1080 центровано, либо 4K full

---

## Сцена 1 — WASM proof in the browser (0:00–0:30)

### Кадры

1. **0:00** — Открыта `tidex6.com/app/`, кошелёк подключён, форма Deposit
   готова. Activity log: «Ready. Wallet connected.»
2. **0:08** — DevTools уже открыт справа (Cmd+Option+I), Console.
   Печатаешь команду:

   ```js
   const m = await WebAssembly.compileStreaming(fetch('/static/wasm/tidex6_prover_wasm_bg.wasm'));
   WebAssembly.Module.imports(m).filter(i => /fetch|WebSocket|XMLHttpRequest/.test(i.name))
   ```

   Enter. Output: `[]` (пустой массив).
3. **0:18** — Подсветить курсором результат на 2-3 секунды.

### Voiceover (RU)

> До этой недели доказательство генерировалось на сервере — ваш секрет
> и nullifier улетали туда вместе с note. Это было удобно, но это
> было компромиссом.
>
> С четвёртой недели криптография полностью в браузере. Вот формальное
> доказательство: я спрашиваю у самого WebAssembly-модуля список его
> импортов и фильтрую по `fetch`, `WebSocket`, `XMLHttpRequest`.
> Результат — пустой массив. У этого модуля физически нет способа
> отправить ваши данные куда-либо.

---

## Сцена 2 — Withdraw полностью в браузере (0:30–0:55)

### Кадры

1. **0:30** — Сделать deposit (или иметь готовую заранее ноту в буфере).
   Текст memo: `Week 4 demo`.
2. **0:35** — Скопировать note в Withdraw textarea. Recipient = другой
   твой кошелёк (например `ED1H…zaK9`).
3. **0:40** — Click «Withdraw via relayer». Activity log заполняется в
   реальном времени. Самые важные строки крупно (zoom через iMovie):

   ```
   Withdraw — generating zero-knowledge proof IN BROWSER...
   Proof generated in 1715 ms
   Submitting via relayer.tidex6.com (we pay the fee) ...
   Withdraw confirmed! Tx: <signature>
   Fee-payer in this tx: relayer.tidex6.com (your wallet did not sign)
   Message from sender: Week 4 demo
   ```

4. **0:50** — Курсор подсвечивает строку «Proof generated in 1715 ms».

### Voiceover (RU)

> Я делаю withdraw. Доказательство строится прямо во вкладке —
> примерно полторы секунды на M-серии MacBook. Транзакцию подписывает
> наш relayer, ваш кошелёк не появляется в качестве fee-payer.
> Получатель видит расшифрованное сообщение «Week 4 demo» — оно
> расшифровалось здесь же, в браузере, ключом, выведенным из ноты.

---

## Сцена 3 — Accountant scan в браузере (0:55–1:30)

### Кадры

1. **0:55** — Click `Acc` в хедере → переход на `/accountant/`.
   Заголовок «Accountant».
2. **1:00** — Поле «secret key» (password input) — вставляешь
   `auditor_secret_key` из `~/.tidex6/identity.json` (заранее открыть в
   соседнем окне или иметь в буфере). Выбор denomination = 0.1 SOL.
3. **1:08** — Click «Scan». Появляется loader, потом — таблица:

   | Date | Memo | Tx |
   |---|---|---|
   | 2026-04-26 | rent 2026 | `2sVVdjxAbr…fde7Pn` |
   | 2026-05-XX | Week 4 demo | `<новый tx из сцены 2>` |
   | … | … | … |

4. **1:20** — Курсор подсвечивает строку «Week 4 demo» — это **тот же**
   memo который только что вставила Лена в сцене 2.
5. **1:25** — Не закрывая страницу, открыть DevTools → Network. Показать
   что secret key ушёл **один** раз в WS-сообщении и больше нет
   повторных отправок.

### Voiceover (RU)

> Это страница для бухгалтера. Раньше она работала только в CLI —
> Kai запускал отдельный бинарь. Теперь сканнер живёт прямо на сайте.
>
> Я вставляю свой viewing-key. Нажимаю Scan. Получаю список всех
> платежей, которые когда-либо были адресованы мне через приватный
> пул — с расшифрованными memo, датами и подписями транзакций. Среди
> них — тот самый «Week 4 demo» из предыдущей сцены.
>
> Ключ ушёл по WebSocket один раз. Бэкенд использует его в RAM для
> сканирования и забывает после ответа. Сама дешифровка возможна
> только потому, что я её разрешил.

---

## Сцена 4 — tip-jar CPI на mainnet + OtterSec (1:30–1:55)

### Кадры

1. **1:30** — Solscan: `https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`
   на mainnet. В разделе «Verified Build» зелёная галочка.
2. **1:38** — Переключаемся на `https://verify.osec.io/status/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`
   (или вкладку OtterSec). Status: `Verified ✓` + repo + commit hash.
3. **1:43** — Открываем `programs/tidex6-tip-jar/src/lib.rs` в редакторе
   на крупном шрифте, скроллим до строк CPI:

   ```rust
   tidex6_verifier::cpi::deposit(
       CpiContext::new(verifier_program, ctx.accounts.into_deposit_ctx()),
       commitment,
       memo_payload,
   )?;
   ```

4. **1:50** — Всё, длительность файла `lib.rs` ~ ~80 строк. Подсветить
   общее число строк визуально.

### Voiceover (RU)

> tidex6 — это не отдельное приложение. Это примитив, который
> подключается через CPI. Вот пример: программа tip-jar, развёрнутая
> на mainnet и проверенная OtterSec. Внутри — одна инструкция, которая
> делает CPI в наш верификатор. Восемьдесят строк Rust-кода — и любая
> Solana-программа умеет принимать приватные платежи.

---

## Финал (1:55–2:00)

### Кадры

- Чёрный экран → белыми буквами:
  ```
  I grant access, not permission.
  ```
- Внизу мелким шрифтом:
  ```
  tidex6.com  ·  Solana mainnet  ·  github.com/koshak01/tidex6
  ```

### Voiceover (RU)

> Четвёртая неделя. Доказательство — в браузере. Бухгалтер — в браузере.
> Интеграция — тридцать строк Rust. Это tidex6.

---

## Описание для YouTube (EN, после записи)

```
Week 4. The privacy stack closes.

Three things ship at once:

1. The proof is now generated in the browser. The secret never
   leaves the tab. You can verify this yourself: ask the WASM
   module for its imports, filter for fetch/WebSocket/XMLHttpRequest
   — the result is an empty array. The module has no network access
   by construction.

2. The accountant lives in the browser. Earlier weeks shipped a
   CLI scanner; now there's a page on tidex6.com/accountant/ where
   the holder of a viewing key pastes it in, hits Scan, and sees
   the full list of memos addressed to them — decrypted client-side,
   with on-chain transaction signatures.

3. tidex6 ships as a primitive, not an app. The reference
   integration — a program called tip-jar — is deployed on Solana
   mainnet and verified by OtterSec. About eighty lines of Rust
   to make any Solana program accept private payments via CPI.

This is everything we wanted to show before the Colosseum
submission. The final 3-minute demo follows.

I grant access, not permission.

Mainnet program (verifier):
  https://solscan.io/account/2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C

Mainnet program (tip-jar reference):
  https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x

OtterSec verifications:
  https://verify.osec.io/status/2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C
  https://verify.osec.io/status/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x

Source: github.com/koshak01/tidex6
```

---

## Чеклист после записи

- [ ] Длина 1:50–2:00 (если 2:30 — сократить вторую сцену)
- [ ] Активность плотная — нет dead air ≥ 3 секунд
- [ ] DevTools console читаемая (увеличить шрифт ⌘+ заранее)
- [ ] Activity log читаемый (zoom важных строк через iMovie)
- [ ] Voiceover — спокойный, без скороговорки, паузы как в скрипте
- [ ] Финальный экран висит ≥ 2 секунды
- [ ] Описание YouTube — обновить с реальной withdraw-tx из сцены 2
- [ ] Добавить запись в `video/PROGRESS_VIDEOS.md` (Week-4 секция)
