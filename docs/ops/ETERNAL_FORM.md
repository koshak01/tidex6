# Colosseum Eternal — тексты для формы

Спринт запущен 05.08.2026 23:58. Подача открывается **26.08.2026**, закрывается
в последнюю неделю спринта. То есть на работу три недели, четвёртая — на
оформление, видео и вычитку.

Проект: `tidex6` · категория **Payments & Remittance** · https://colosseum.com

---

## STEP 1 — PROJECT INFO

### PROJECT NAME (public)

```
tidex6
```

Строчными. На карточке они сами капитализируют в `TIDEX6`; у нас везде —
в крейтах, на сайте, в GitHub — строчное.

### BRIEF DESCRIPTION (public, 498/500)

```
A Rust-native privacy layer for Solana payments — a library you drop into your own program, not another app. Two layers: Token-2022 confidential transfers hide the amount, a Groth16 proof breaks the sender-recipient link. The part nobody else has: an auditor slot. The sender chooses who may read a payment — an accountant, a regulator — and that reader can never spend or freeze it. Audit without seizure. Live on Solana mainnet, 7 crates published, and in the official MCP Registry for AI agents.
```

### PROJECT WEBSITE (public)

```
https://tidex6.com
```

### WHAT ARE YOU BUILDING, AND WHO IS IT FOR? (только для судей, 989/1000)

```
We are building the privacy layer other Solana projects plug into, not another payments app.

Today a Solana payment is fully public: amount, sender, recipient. Fine for trading, wrong for almost everything else — payroll, cross-border support to family, invoices, donations. The usual answer is "use a mixer", which hides everything and makes you look guilty. Ours is different: the sender chooses who may see.

A payment carries an encrypted memo addressed to a reader the sender picks — an accountant, an auditor, a regulator. That reader sees date, amount and purpose, and can never spend or freeze. Audit without seizure.

Who it is for: developers first. Seven crates on crates.io, a 158-line CPI example, two MCP servers so AI agents can pay without holding keys. A Solana program becomes privacy-capable in about thirty lines.

End users are reached through them: remittance senders, remote teams paying salaries, funds publishing one permanent address instead of rotating wallets.
```

### WHY DID YOU DECIDE TO BUILD THIS, AND WHY BUILD IT NOW? (945/1000)

```
Because a public ledger is the wrong default for paying people.

Every salary, every transfer to family, every invoice on Solana is readable by anyone forever. The industry's answer has been mixers — hide everything, and look guilty doing it. That framing is why privacy tools get treated as contraband instead of infrastructure.

The useful primitive is the opposite: hidden by default, disclosable by choice. The sender decides who may read a payment, and that reader can never touch the money.

Why now: two things landed in 2026. Solana re-enabled Token-2022 confidential transfers, so the amount hides natively instead of through our own heavy circuit. And agents became real buyers of infrastructure — an agent paying on your behalf needs privacy and an audit trail at once, which is exactly our shape.

We also learned that most privacy projects here die within a year of their hackathon. We would rather be the boring one still shipping.
```

### WHAT TECHNOLOGIES ARE YOU USING OR INTEGRATING WITH?

```
Rust, Solana, Anchor. Groth16 over BN254 verified on-chain via native alt_bn128 syscalls; arkworks for proving; Poseidon (light-poseidon, circom-compatible) for commitments. Token-2022 Confidential Transfers for hidden amounts. ML-KEM-768 (post-quantum) + ChaCha20-Poly1305 for the encrypted memo envelope, with an X25519 view-tag for fast scanning. WebAssembly (wasm-pack) for the in-browser prover, Web Workers to keep the tab responsive. Model Context Protocol (rmcp) for agent access, with OAuth 2.0 + dynamic client registration on the hosted server. Helius RPC. OtterSec for program verification, solana-verifiable-build for reproducible builds. Developer tooling: Claude Code, GitHub Actions.
```

### Is your project a mobile-focused dApp?

Нет, галку не ставить. Мы библиотека и веб-приложение.

---

## STEP 2 — MEDIA AND CODE

### Repository

```
https://github.com/koshak01/tidex6
```

Публичный, CI зелёный, 7 крейтов опубликованы на crates.io.

### Логотип

Лежит в репозитории, каталог `brand/` — есть SVG и PNG-квадраты под аватарки.
Для directory лучше квадратный PNG с собственным фоном (тот, что делали под
Solscan и favicon).

### Demo / video

**Единственное, чего нет в актуальном виде.** Существующее видео снято к
Frontier в мае — там ещё SOL, видимые суммы и передача ноты из рук в руки.
Показывать его сейчас нельзя: продукт другой.

Переснять на третьей неделе спринта. Что показывать:

- отправка приватного платежа USDC на mainnet;
- получатель находит платёж сам, сканируя цепь своим ключом;
- аудитор открывает сумму и memo — и не может ни потратить, ни заморозить;
- то же самое делает ИИ-агент через MCP, спрашивая подтверждение.

### Прочие ссылки, если попросят

```
https://tidex6.com/business/     — как проект зарабатывает
https://ceremony.tidex6.com/     — публичная церемония
https://crates.io/crates/tidex6-client
https://registry.modelcontextprotocol.io  (io.github.koshak01/tidex6-mcp-local)
https://verify.osec.io/status/CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd
```

---

### PLEASE SHARE ANY IMPORTANT CONTEXT ABOUT YOUR REPO (495/500)

```
The repository holds the protocol: crates (core, circuits, client, indexer, MCP servers), on-chain programs (verifier, wUSDC/wUSDT pools, reader registry), and a CPI example showing a third-party program paying privately in ~30 lines.

Two production surfaces live in separate repositories, both ours: tidex6-web (site and browser app) and tidex6-relayer (fee payer, and the browser's read path to the chain).

aleo/ is an exploratory spike on another chain, kept separate rather than folded in.
```

### LIVE PRODUCT LINK

```
https://tidex6.com
```

### ACCESS INSTRUCTIONS

```
No login needed. Connect any Solana wallet (Phantom, Solflare, Backpack, Ledger).

Mainnet payments are capped while the trusted setup is unfinished; devnet is open. To try without spending: /receive/ and /accountant/ read the chain with a key derived from a wallet signature — no transaction is signed.
```

### Чекбоксы

- **Make demo video public in the project directory** — ставить. Скрывать
  нечего, а публичное видео работает на нас после оценки.
- **Feature my project in the Colosseum directory after evaluation** — ставить.
  Это бесплатная витрина ровно для тех, кто ищет библиотеку.

---

## STEP 3 — TEAM

### WHERE IS YOUR TEAM PRIMARILY BASED?

```
Montenegro
```

### DID ANYONE NOT LISTED ON THE TEAM DO MEANINGFUL WORK? (536/600)

```
Development is done by one person working with AI coding assistants (Claude Code) throughout — architecture, implementation and review. No other humans contributed code.

Two external parties deserve mention: OtterSec verified the on-chain programs, and Sentio's automated analysis surfaced an unchecked-arithmetic issue we fixed (SW005).

The trusted-setup ceremony is by design contributed to by outsiders — currently 4 independent wallets, targeting 20+. Their contributions are cryptographic, not code, and the transcript is public.
```

Про ИИ сказано прямо. Скрывать нечего: так сейчас работает половина индустрии,
а поймают на умолчании — будет хуже, чем если сказать самим.

### X PROFILE

```
@koshak0006
```

### IS THERE ANYTHING ELSE JUDGES SHOULD KNOW? (499/500)

**Вот сюда идёт связь с прошлой заявкой** — отдельного поля для неё в форме
нет, галка на старте была только обещанием.

```
Submitted to Colosseum Frontier in May 2026; brought to Eternal because it materially changed — 330 commits since, +63k lines.

Then: SOL, amount public, note handed to the recipient out of band. Now: USDC/USDT with the amount hidden by Token-2022 confidential transfers, and nothing handed over — the recipient scans the chain himself.

Also new: revenue in code, agent access via MCP, an on-chain reader registry, regulated pools, a public ceremony.

Full changelog: WHAT_CHANGED_SINCE_FRONTIER.md
```

### ARE YOU APPLYING FOR THE COLOSSEUM ACCELERATOR?

Выбрано **Yes** (05.08). Это уже не про приз, а про инвестиции и долю.

---

## ACCELERATOR ADD-ON

### EQUITY PERCENTAGE

```
100
```

Единственный основатель, компания не инкорпорирована — так и есть.

### ARE YOU WORKING ON THIS FULL-TIME?

Твой ответ. Вариантов три: `Yes` / `Not yet` / `No`. Врать нет смысла —
на интервью спросят, чем ещё занят. Если параллельно идут другие продукты,
честнее `Not yet`: они это слышат постоянно и ценят прямоту выше позы.

### WHAT'S THE MOST IMPRESSIVE THING YOU'VE BUILT OUTSIDE OF THIS PROJECT? (485/500)

```
A complete trading system in Rust against Polymarket, built solo: market data ingestion, CLOB order paths, Postgres state, deployed and running in production against real markets.

Before crypto: I ran the systems behind a multi-brand fashion retailer at roughly EUR 1M monthly turnover — storefront and operations both, payment flows included. And a practice that delivered 400+ projects over a decade.

Different domains, same discipline: systems that lose money when they are wrong.
```

### YOU COULD BE WORKING ON ANYTHING RIGHT NOW — WHY CHOOSE THIS? (991/1000)

```
Because I have spent twenty years moving other people's money through systems, and the blockchain version is worse at the one thing that matters: it tells everyone.

Every salary paid on Solana is public forever. Every transfer to family, every invoice, every donation. The industry's answer was mixers — hide everything, look guilty doing it — and that is why privacy tools get treated as contraband rather than plumbing.

The right primitive is the opposite, and nobody was building it: hidden by default, disclosable by choice. The sender picks who may read a payment, and that reader can never touch the money. Audit without seizure.

I also looked at what happened to everyone who tried before me. Of 28 privacy and payments winners from past Colosseum hackathons, almost all are dead within a year — repositories gone, domains expired, last commit the week the prize was announced. That is a reason to be the one still shipping, with real mainnet transactions rather than a demo video.
```

Последний абзац — наш козырь. Мы единственные, кто пришёл, изучив кладбище
предшественников, и говорит об этом вслух.

### TELL US ABOUT A TIME YOU WENT TO EXTREME LENGTHS (496/500)

```
In July I rebuilt this product from the ground up in five weeks — 98 commits in a month, alone.

The old version moved SOL with visible amounts and handed the recipient a note out of band. I replaced the cryptography (post-quantum envelopes), the asset layer (Token-2022 confidential transfers) and the delivery model — the recipient now scans the chain himself — while keeping mainnet live throughout.

Nobody asked for it. The old version was good enough to demo. It was not good enough to use.
```

Если есть история из жизни ярче — бери свою, проверяемый факт про июль просто
всегда под рукой.

### ARE YOU A TECHNICAL FOUNDER?

`Yes` — без вариантов.

### TECHNICAL BACKGROUND (600/600, впритык)

```
Twenty years of production systems: Oracle PL/SQL for institutional data, high-load web, e-commerce at roughly EUR 1M monthly turnover. Recent work is in Rust.

On this product I wrote all of it. The Groth16 circuits and the in-circuit Poseidon gadget, the on-chain programs (verifier, pools, reader registry), the post-quantum ML-KEM envelope with its X25519 view-tag, the WASM browser prover, the Rust SDK, both MCP servers, the relayer, the web app. I run the servers it deploys to.

There is no other engineer. The work is done with AI assistants, and the architecture and the decisions are mine.
```

Перечисление компонентов не для красоты: человек, который не писал схемы, не
назовёт in-circuit Poseidon-гаджет и X25519 view-tag. Это техническая подпись.

Про ИИ — та же формулировка, что в поле «кто ещё делал работу», чтобы не было
расхождения между ответами.

### ARE YOU LOOKING FOR A COFOUNDER?

Решение Петра. `Yes` снимает главное возражение к соло-фаундеру и даёт
Colosseum повод свести с людьми; `No` честнее, если партнёр не нужен — но
тогда на интервью будет вопрос «что с проектом, если тебя не станет».

### PLEASE SHARE A TEAM TELEGRAM CONTACT

Твой контакт, я его не подставляю.

---

## ABOUT YOU (личный профиль)

Дедлайн профиля: **2 сентября, 23:58 GMT+2**.

Часть полей — только твои, я их не выдумываю: возраст, пол, учился ли сейчас,
образование, где работал раньше. Что подсказать могу:

### WHAT IS YOUR ROLE / TITLE ON THIS PROJECT?

```
Founder & sole engineer
```

### TWITTER/X PROFILE

```
@koshak0006
```

Поле пустое, хотя LinkedIn и GitHub подтянулись — заполнить.

### WHERE HAVE YOU WORKED OR BUILT BEFORE? (980/1000)

Собрано Никой из резюме — факты, не сочинение. Вставлять дословно.

```
Twenty-plus years shipping production systems, most of them moving money.

I started in Oracle PL/SQL, building institutional systems where data integrity was the product: asset registries, bulk processing, reporting at scale. Correctness under load was the job, not a feature.

Then high-load web, and industrial e-commerce: multi-brand fashion retail at roughly EUR 1M monthly turnover, where I owned the storefront and the operations behind it, payment flows included.

Founder of foothold.me (Montenegro); before it, a practice that delivered 400+ projects over a decade.

Recent work is Rust-first. tidex6 is a Solana privacy framework — Groth16 shielded pool, on-chain verifier, unlinkable-withdraw relayer, WASM prover, Token-2022 Confidential Transfers — audited by OtterSec, live on mainnet. Alongside it, a complete trading system in Rust against Polymarket: market data, CLOB order paths, Postgres state, production deploy.

I run my own servers and ship to production.
```

Первая строка отвечает ровно на вопрос жюри в категории Payments: двадцать лет
человек двигает деньги. Дальше дуга без разрывов — институциональные системы,
где неверная запись дороже отсутствующей; магазин с миллионным оборотом и
живыми платёжными потоками; теперь приватные платежи. Не «увлёкся блокчейном»,
а пришёл к нему из денег.

### WHAT'S YOUR EDUCATIONAL BACKGROUND? (437/500)

```
Moscow State University of Instrument Engineering and Informatics (MGUPI), 2003 — Computers, complexes, systems and networks. Moscow Economic Institute, 2002 — Programming.

The formal grounding in systems and networks is what made the low-level work feel like familiar ground rather than a leap. The rest came from twenty years of production: nothing teaches correctness under load like being responsible for it at three in the morning.
```

### IPv4 — в резюме этого нет

Ника намеренно не добавила: факт по смыслу подходит (рынок, где приватность
сделки имеет цену), но в CV его нет и проверить она не могла. В поле осталось
20 символов — если добавлять, придётся чем-то жертвовать. Решай сам.

### OTHER RELEVANT LINKS

```
https://tidex6.com
https://crates.io/crates/tidex6-client
https://registry.modelcontextprotocol.io
```

---

## Цифры, которые могут понадобиться в любом поле

- 330 коммитов с 11 мая, +63 478 / −16 865 строк, три репозитория
- 9 новых ADR (014–021), 10 новых крейтов и программ
- mainnet: 105 конвертов, 46 платежей, все получены, 18 раскрыто аудитору
- 7 крейтов на crates.io, версия 2.18.0
- церемония: 4 контрибьютора из 20+ нужных
- три независимых пути пройдены end-to-end за один день: CLI, браузер с
  Phantom, сторонний ИИ-агент

---

## ACCELERATOR — инвесторские вопросы

### HOW DO YOU KNOW PEOPLE ACTUALLY NEED THIS? (946/1000)

```
Honestly: from demand signals, not customer interviews. I will not pretend otherwise.

The signals: a ZeroClaw bounty this summer asked, almost word for word, for "stealth addresses, hidden amounts, compliance viewing keys" — our exact feature set, written by someone else. Superteam funded a grant on the same premise. Our crates get pulled by people we do not know, and the repository was cloned by 84 unique sources in two weeks with zero promotion.

The structural argument is stronger than any survey. Every company paying salaries on-chain leaks its payroll to competitors. Every freelancer invoicing in stablecoin publishes their rates. Every fund exposes its donors. That is why most businesses still will not touch on-chain payroll.

The existing answer is mixers, which solve the wrong half: they hide from everyone, including your own accountant, and make you look guilty. Nobody was building the version where you disclose on purpose.
```

Первая строка — намеренно. У нас нет интервью с клиентами, и притворяться, что
есть, — верный способ провалиться на первом уточняющем вопросе.

### HOW FAR ALONG ARE YOU? DO YOU HAVE USERS? (921/1000)

```
Live on Solana mainnet since April, rebuilt from the ground up in July.

What works end to end today: private USDC and USDT payments with hidden amounts, stealth delivery (the recipient scans the chain himself — nothing is handed over), an auditor slot, a relayer so the recipient's wallet never appears as fee payer, an in-browser prover, a Rust SDK, and two MCP servers so AI agents can pay. Verifier immutable and OtterSec-verified.

Numbers: 105 envelopes on chain, 46 payments, all collected. 7 crates on crates.io. In the official MCP Registry.

Users, honestly: none yet. Those 46 payments are our own tests with real money. What we have is early pull — unknown people downloading the crates, 84 unique clones in two weeks — and one blocker we fix first: the trusted setup has 4 contributors of 20+ needed, so the verifying key is still a development key. Until that closes, inviting real users would be dishonest.
```

**Здесь мы говорим «пользователей нет».** Это проверяется за час, и надутая
метрика убьёт доверие ко всему остальному. Зато объяснение, почему мы их пока
не зовём, — само по себе сильный аргумент: мы не тащим людей на недоделанный
trusted setup.

### WHO ELSE IS BUILDING, AND WHAT ARE THEY GETTING WRONG? (895/1000)

```
Arcium, Umbra, Elusiv, Light Protocol on Solana; Railgun and Privacy Pools on Ethereum; DarkDrop is closest in shape.

What they get wrong, in one sentence: they optimise for anonymity, and anonymity is not what stops businesses from using on-chain payments — accountability is.

A mixer hides you from everyone, including the people you must prove things to: your accountant at tax time, a regulator asking a question, a client disputing an invoice. So the tool becomes unusable for exactly the payments that matter, and its users acquire a stigma. Vitalik's own Privacy Pools work admits this — it bolts proofs of innocence on afterwards.

We invert it: the sender picks a reader, seals the payment for them, and that reader can read but never spend or freeze.

They also get survival wrong. Of 28 privacy and payments winners from past Colosseum hackathons, almost all are dead within a year.
```

⚠️ Наше правило «не упоминать конкурентов» действует для публичных документов
(`docs/release/`). Здесь спрашивают прямо — уклоняться нельзя, это читается как
незнание рынка.

### HOW DO YOU MAKE MONEY? (487/500)

```
A 1% fee per payment with a 0.1 floor, paid by the sender on top — the recipient receives exactly what was sent. It is in the code and running on mainnet today, not a plan.

The unusual part: our revenue is private too. The fee is collected as a stealth note to the operator's key, indistinguishable on chain from any other payment. We sell privacy and apply it to ourselves.

No token, no subscription. If nobody pays anybody, we earn nothing — the correct incentive for a payment rail.
```

### HOW LONG HAVE YOU BEEN WORKING ON THIS? FULL TIME? (387/500)

```
Since April 2026 — first commit April 9th. One person.

Not full-time in the sense of exclusivity: I run other products and my own infrastructure business. But this is where the work goes — 330 commits since May across three repositories, 98 of them in July alone, which is when the product was rebuilt from SOL with visible amounts into what it is now.

Funding would make it exclusive.
```

### WHERE IS EACH MEMBER BASED? IN-PERSON? (408/500)

```
One person, based in Herceg Novi, Montenegro. No team to co-locate, so the in-person question does not apply today.

Funding would change this: the first hires would be a second engineer and someone owning integrations — getting other Solana projects to adopt the library is a different job from building it, and it is the part I am worst at.

Whether that team is remote or local would depend on the people.
```

### Переключатели

- **HAVE YOU FORMED A LEGAL ENTITY?** — твой ответ. Для tidex6 сущности нет;
  если считать foothold.me — решай сам, но тогда это надо будет объяснить.
- **HAVE YOU TAKEN ANY INVESTMENT?** — `No`.
- **ARE YOU CURRENTLY FUNDRAISING?** — твой ответ. Раз подаёшь в акселератор,
  логично `Yes`; `No` означает «денег не ищу», и тогда непонятно, зачем заявка.
- **DO YOU HAVE A LIVE TOKEN?** — `No`. **И это наш плюс**, а не пробел:
  у нас в roadmap записано «no token and no plan for one» — privacy-рельс,
  которому нужен собственный актив, имеет вторую причину существовать, и она
  конкурирует с первой.

### FUNDRAISING DETAILS (469/500)

```
First raise. No prior round, no SAFE, no term sheet, no token — nothing has been sold and the cap table is one person.

Raising pre-seed to fund the two things effort alone cannot buy: an independent security audit of the circuits and on-chain programs, and a second engineer so the project stops being limited by one person's throughput.

We applied for a small ecosystem grant in July and were turned down. Everything shipped since was self-funded and shipped anyway.
```

Суммы намеренно нет. Eternal сам называет размер ($250k pre-seed), и наше
число в этом поле может только разойтись с их рамкой. «Чистая таблица
владения, ничего не продано» — для инвестора важнее суммы.

**Про грант Superteam: отказ, а не pending.** Заявка от 25.07 на 5000 USDG
отклонена. Писать «pending» в заявке инвесторам нельзя — это проверяемая
неправда. Решили сказать об отказе прямо: вопрос «пробовали гранты?» на
созвоне прозвучит всё равно, и лучше, чтобы ответ уже стоял в анкете.

**Решение принято 06.08.2026: пишем про отказ.** Альтернативный вариант
(молчать о гранте) отклонён — вопрос «пробовали ли гранты» прозвучит на
созвоне всё равно, и лучше, чтобы ответ уже стоял в анкете.
