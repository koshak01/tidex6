# Handoff → Аид · Aleo / Leo — тот же privacy-контур, что tidex6, на языке ≈Rust

**Дата:** 2026-08-04  
**От:** Ника (find + ТЗ)  
**Кому:** **Аид** (owner · ZK / product)  
**Зачем:** Аид «не находит» задачу — вот явный бриф. **Ника код Leo не пишет** (lane Аида).

---

## 1. Что имелось в виду

| | |
|--|--|
| **«Тот же контур»** | Privacy stack **tidex6** (Solana): shielded link + hidden amount + selective disclosure + (опц.) stealth/relayer |
| **«Язык похожий на Rust»** | **Leo** (Aleo) — ZK DSL, синтаксис близок к Rust · https://leo-lang.org · docs https://developer.aleo.org |
| **Грант** | Aleo Developer Grants · до **$100k** · OSS on Aleo · https://aleo.org/grants · apply https://form.asana.com/?k=sCm0WT9M-V_fHl8AA48czQ&d=1199198487809755 |

**Не** Colosseum product dual-submit.  
**Не** Token-2022 FoT lab (отдельный handoff `HANDOFF_TOKEN2022_FOT_LAB_AID.md`).  
**Это:** port **идеи/архитектуры privacy** на **Aleo/Leo** под grant + PoW.

---

## 2. Карта контура tidex6 → Aleo/Leo

| Слой tidex6 (Solana/Rust) | Смысл | Leo / Aleo аналог (направление) |
|---------------------------|--------|----------------------------------|
| Groth16 shielded pool | скрыть **link** sender↔receiver | private records / transition proofs; note-style state |
| Token-2022 CT / wUSDC | скрыть **amount** | private amounts in records (native private by default) |
| Viewing key / selective disclose | auditor path | selective disclosure / view key patterns on Aleo |
| Relayer unlinkable withdraw | tx payer ≠ user | public submitter vs private user (design carefully) |
| Stealth / ML-KEM memo | find notes without handoff | encrypted memo / scan pattern (scope MVP carefully) |
| Browser WASM prover | client-side prove | snarkVM client / web stack as second phase |
| CPI tip-jar example | 30-line integrate privacy | simple Leo program + host integration example |

**MVP для grant (реалистично):**

1. **Leo program:** private transfer / note deposit–withdraw (minimal).  
2. **Wrong vs right** docs: where privacy breaks if public fields leak (mirror FoT lab spirit).  
3. **Tests** + README (build, prove, execute on testnet/local).  
4. **One-pager** for Asana form: problem · solution · milestones · budget · OSS.  
5. Optional: map from tidex6 ADR (link-only) — what ports, what is Solana-specific.

**Не в MVP v1:** full relayer product, mainnet funds, copy Solana program 1:1.

---

## 3. Grant facts (live 2026-08-04)

| | |
|--|--|
| Page | https://aleo.org/grants |
| Funding | up to **$100K**, milestone-based |
| License | **open-source required** |
| Who | teams + solo |
| Scope tags | Payment · Identity · Gaming · DeFi |
| Form | https://form.asana.com/?k=sCm0WT9M-V_fHl8AA48czQ&d=1199198487809755 |
| Leo | https://leo-lang.org · docs https://developer.aleo.org/guides/introduction/getting_started |

---

## 4. Роли

| Кто | Роль |
|-----|------|
| **Аид** | owner: Leo scaffold, grant text, repo, milestones |
| **Ника** | research/links + этот brief; **не** Leo implementation |
| **Пётр** | direction / apply OK |

---

## 5. Ссылки на «контур» у себя

- tidex6 README: `/Users/koshak01/work/rust/tidex6/README.md`  
- Privacy layers: Groth16 pool + Token-2022 CT + relayer + stealth  
- Product: https://tidex6.com  

Pitch angle for Aleo: *«We already shipped dual-layer privacy on Solana (tidex6). Port the architecture to Aleo native ZK privacy with Leo for compliant private payments / payroll.»*

---

## 6. Next (Аид)

1. Confirm take ownership.  
2. Leo hello-world + private transfer MVP ETA.  
3. Draft grant milestones ($ ask).  
4. Ping Nike if need security/wrong-vs-right checklist (like FoT).  
