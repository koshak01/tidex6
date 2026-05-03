# tidex6 Weekly Progress Videos

Хронология прогресс-видео для Colosseum Frontier 2026. Каждое видео фиксирует
конкретный шаг продукта. Цель индекса — чтобы Week-N видео не дублировало то,
что уже показано в предыдущих, и чтобы внешний зритель (судьи / спонсоры)
видел чистую линейную историю.

---

## Week-1 — CLI three-actor private payroll

- **Дата записи:** ~10 апреля 2026
- **Длительность:** 1:32
- **Сеть:** Solana mainnet (`api.mainnet-beta.solana.com`)
- **YouTube:** TBD

### Public description (EN)

> The first end-to-end run of tidex6 — three terminals, three actors, one
> private payroll. Before the website, before the relayer, before any UI —
> just three Rust binaries on a laptop, talking to live Solana mainnet
> through the CLI. This is the smallest demonstration of the whole product:
>
> - **Lena (sender)** runs `tidex6 deposit --amount 0.5 --memo 'october medicine'`
>   and gets a note file back. The deposit is on chain; her wallet's link to
>   the recipient is gone.
> - **The parents (receiver)** run `tidex6 withdraw --note parents.note --to
>   their-wallet`. The CLI rebuilds the Merkle tree from on-chain history,
>   generates a Groth16 zero-knowledge proof in their terminal, and submits
>   it. The funds arrive. No one watching the chain learns where they came
>   from.
> - **Kai (the accountant)** runs `tidex6 accountant scan --auditor-key
>   their-key`. He gets a JSONL file with every memo Lena ever addressed to
>   him, plus a tax-ready Markdown report.
>
> Three roles, three terminals, three different sets of capabilities — built
> on the same shielded pool. No web app, no fancy UI, just the primitive
> working at the protocol level. Everything you see in the later videos is
> built on top of this.
>
> *I grant access, not permission.*

### Что фактически показано (технический разбор)

1. **tmux split 3 pane** — Лена (слева), родители (правый верх), Kai (правый низ)
2. **Лена → deposit:** `cargo run --release --bin sender -- deposit --amount 0.5 --memo 'october medicine' --recipient-label parents --note-out /tmp/parents.note`
   - вывод: cluster mainnet, payer, denomination 0.5 SOL, commitment hex, signature, leaf index, explorer URL
   - note записывается в `/tmp/parents.note`
   - scan entry дописывается в `~/.tidex6/payroll_scan.jsonl`
3. **Родители → withdraw:** `receiver withdraw --note /tmp/parents.note --to <pubkey>`
   - видно три строки прогресса: «rebuilding Merkle tree from on-chain history» → «generating zero-knowledge withdraw proof» → «submitting to verifier program»
4. **Kai → accountant scan:** Markdown-отчёт с тремя transfers (все 2026-04-10, 0.5 SOL, recipient `parents`, memo `october medicine`), Monthly totals, By recipient, Grand total `1.500 SOL across 3 transfers`

### Чего в этом видео НЕТ

- Нет website / browser UI — всё чисто в терминале
- Нет relayer — fee-payer везде сам участник, его pubkey виден on-chain
- Нет browser WASM — proof генерится локальным CLI
- Нет CPI integration (tip-jar)
- Нет accountant с настоящим отдельным viewing key (виден тот же payer pubkey)

### Tempo issue (lessons learned)

- Реальной активности только **первые ~15 секунд** из 1:32
- Остальные ~1:17 — пустые ожидания (`while ! -s parents.note; do sleep 1`,
  `sleep 45` перед запуском accountant). Зрителю смотреть нечего.
- **Для Week-4:** убрать `sleep` блоки, либо вырезать в монтаже, либо
  ускорять в 2–3× при простое. Активность должна быть плотной.

---

## Week-2 — Public website + browser deposit + Shielded Memo (early)

- **Дата записи:** ~середина апреля 2026 (до ADR-012 деплоя 2026-04-15)
- **Длительность:** 1:17
- **Сеть:** Solana mainnet
- **YouTube:** TBD (unlisted, "доступ по ссылке")

### Public description (EN, текущая версия на YouTube)

> Up to this point a deposit was just money — you could send SOL privately,
> but you couldn't tell the recipient why. No "rent for March", no "happy
> birthday", no invoice reference. Just a number.
>
> This update adds **Shielded Memo**: a short encrypted message (up to 256
> bytes) attached to every deposit. The sender writes the memo, the recipient
> reads it after they redeem the note. The message rides on the same Solana
> transaction as the deposit, so there's no separate channel to manage and no
> risk of losing it.
>
> The encryption is end-to-end. The on-chain bytes are AES-256-GCM ciphertext
> addressed to the recipient (and optionally to a designated auditor —
> covered in a later video). To everyone else watching the chain, it's just
> opaque bytes.
>
> Result: every deposit can now carry context — and that context stays
> private to the people who are supposed to read it.

### Что фактически показано (технический разбор)

1. **Запуск публичного сайта tidex6.com/app/**
   - Хедер: Home / How it Works / Use Cases / Developers / Roadmap + Launch
     App / Acc / Connect Wallet
   - Состояние без подключённого кошелька — показ "Request Access" блока
   - Footer: "I grant access, not permission" + Program 2qEmhLEn...nBcU9C +
     Security.txt ✓ + Verified ✓
2. **Request Invite flow** — приглашение через Telegram bot approval
3. **IDE/terminal вставка** — RustRover с workspace `Cargo.toml`, в терминале
   `solana balance` 2.83 SOL — для зрителя контекст что это рабочий dev-сетап
4. **Connect Phantom** — wallet подключён, `Cs9F9sdyc…8Y8n6`, кнопка "Connect
   Wallet" сменилась на адрес
5. **Deposit form (browser):**
   - кнопки 0.1 / 0.5 / 1 / 10 SOL
   - Memo (required) + подпись «Encrypted for the auditor. Recipient will
     also see this text in their note.»
   - Auditor public key (64 hex) поле
6. **Заполненный deposit:** 0.1 SOL, memo `Rent April 2026`, auditor pubkey
   `061ec073d77cf0c7326c0c7974b426ac9e71e8529c6506af5678…`
7. **Identity demo через terminal** (`cat ~/.tidex6/identity.json`) — видно
   откуда зритель берёт `auditor_public_key` для вставки в форму
8. **Note выпала:** `tidex6-note-v2:0.1:00f2f1…:247ef5…:UmVudCBBcHJpbCAyMDI2`
9. **Withdraw подготовлен:** note скопирован в textarea, recipient =
   `ED1HHGK6evjLyFCF9jWw8iXjAXfi2Xz4zaTHMcBNzaK9` (другой кошелёк)

### Знаешь сам — мемо в видео НЕ зашифровано

Последний сегмент note `UmVudCBBcHJpbCAyMDI2` = base64-decode → **"Rent
April 2026"** дословно. На момент записи envelope-шифрование (ADR-012,
deployed 2026-04-15) ещё не работало в проде, memo шло в base64 plaintext.

Это означает рассогласование между описанием и реальностью видео:

| Описание YouTube утверждает | Видео фактически показывает |
|---|---|
| AES-256-GCM ciphertext | base64 plaintext memo в note |
| Encrypted envelope, opaque bytes | Любой может прочитать note → memo |

**Рекомендация для текущего описания:** оставить как есть — описание говорит
о **фиче** Shielded Memo как продуктовой идее, а не о точной byte-структуре
note. Зритель не делает base64-decode. Если хочется честности — добавь в
описание одну фразу: *"Final envelope encryption (AES-256-GCM) shipped in
v2.5.11, demonstrated in a later video."* — но не критично.

### Чего в этом видео НЕТ

- Нет relayer — fee-payer всё ещё подключённый Phantom (Лена видна on-chain)
- Нет browser WASM — proof генерится на сервере, secret уходит туда же
- Нет CPI integration (tip-jar)
- Нет финального envelope encryption — memo plaintext в base64
- Нет accountant flow — auditor key вводится, но нет демонстрации scan

---

## Week-3 — Opaque notes + envelope encryption + relayer-paid withdraws

- **Дата записи:** конец апреля 2026 (после ADR-011 deploy 2026-04-24)
- **Длительность:** 1:58
- **Сеть:** Solana mainnet
- **YouTube:** TBD (unlisted)

### Public description (EN, новая)

См. блок "Предлагаемое описание" ниже.

### Что фактически показано (технический разбор)

1. **Deposit form, обновлённый UI:**
   - Memo стало `(optional)` (было `(required)` в Week-2)
   - Подпись поля: «Encrypted on-chain under a key derived from the note
     itself. The recipient decrypts it automatically when redeeming the
     note.» — это и есть ADR-012 envelope (AES-256-GCM)
   - Auditor public key тоже `(optional, 64 hex)` — был обязателен в Week-2
2. **Note изменился структурно:**
   - Было: `tidex6-note-v2:0.1:c1:c2:UmVudCBBcHJpbCAyMDI2` (Rent April в base64)
   - Стало: `02001a197653cd242533e151bee64ac0e28c6bc6d16b54f437c2f3b892d4a75881…` —
     чистый hex, **без структуры**, никаких разделителей, никаких подсказок
     для chain-watcher'а
3. **Withdraw form справа:**
   - Подпись: «The withdraw transaction is submitted by **relayer.tidex6.com**
     — our wallet pays the on-chain fee so you stay unlinked.»
   - Кнопка переименована: **«Withdraw via relayer»**
4. **Activity Log в момент withdraw:**
   - `Withdraw — generating zero-knowledge proof...`
   - `Submitting via relayer.tidex6.com (we pay the fee) ...`
   - `Parsing note...`
   - `Rebuilding Merkle tree + generating ZK proof...`
   - `Withdraw confirmed! Tx: 2sVVdjxAbrCwnhk79aBTz…fde7Pn`
   - `Fee-payer in this tx: relayer.tidex6.com (your wallet did not sign)`
   - `Message from sender: rent 2026` — recipient увидел расшифрованный memo
5. **Top-of-form панель:**
   - "Withdrawn successfully via relayer.tidex6.com! Message from sender:
     'rent 2026'"
6. **Terminal balance check** (другой кошелёк-получатель `ED1H…zaK9`):
   - До withdraw: `0.462935881 SOL`
   - После withdraw: `0.561761601 SOL` (получил ~0.1 SOL минус on-chain rent)
7. **Solscan URLs** в текстовом редакторе как доказательство:
   - deposit tx `4L9YyejCHEtr8zmYhWffEPvZpu4sij5usLfB3oKzPGfPByk8bfv8sYUHARdHQx3FjsBGNicdSNmcp6ef5xiRUqAX`
   - withdraw tx `2sVVdjxAbrCwnhk79aBTzUNjYBjqSThvJEzQdXN16YqaTAwCSuQLEicbuRdEPhUb323aMEnvfeMTFGWtw2fde7Pn`

### Чего в этом видео НЕТ

- **Нет browser-side WASM proving (ADR-013).** Proof всё ещё генерится на
  сервере — secret уходит вместе с note по WebSocket, бэкенд держит ключи в
  RAM. Это и будет Week-4.
- **Нет CPI integration (tip-jar).** Никакой третьей программы, всё внутри
  одного `tidex6-verifier`.
- **Нет security_txt в программах** — embedding ещё не сделан.
- **Нет OtterSec verification** — программы deployed но не verified.

---

## Week-4 — Browser WASM proving + accountant + CPI

- **Дата записи:** 2026-05-03
- **Сабмит:** 2026-05-03 (Colosseum Weekly Update form, в окне последних 3 дней недели)
- **Длительность:** 1:20 (формат Colosseum Weekly Video Update — лимит 1 минута, мы чуть переехали)
- **YouTube:** загружен 2026-05-03, доступ "по ссылке" (URL подставить из YouTube Studio)

### Сценарий записи

`video/WEEK-4_PROGRESS_SCRIPT_RU.md` — 4 сцены:

1. WASM imports check (`WebAssembly.Module.imports(...).filter(/fetch|WS|XHR/) → []`)
2. Browser deposit + withdraw via relayer (Activity log с fee-payer = relayer)
3. Accountant scan на `/accountant/` (Week-4 demo memo появляется в таблице)
4. tip-jar CPI mainnet + OtterSec verified

### Description (EN, копировался в YouTube)

См. секцию «Описание для YouTube» в `WEEK-4_PROGRESS_SCRIPT_RU.md`.

### Title

`Week 4 — The secret never leaves the tab: WASM proving + accountant + CPI`
