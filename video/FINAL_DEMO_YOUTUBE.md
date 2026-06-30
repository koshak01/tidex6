# Final Demo — YouTube заголовок и описание

> Лимит YouTube description: **5000 символов**.
> Текущее description ниже укладывается в **~4500 символов**.

---

## Title (≤100 символов)

```
tidex6 — privacy framework for Solana | Live mainnet demo
```

---

## Description (copy-paste в YouTube)

> Перед публикацией: подставить реальные tx-сигнатуры из записи
> в блок `LIVE TRANSACTIONS FROM THIS RECORDING`.

```text
tidex6 — a Rust-native privacy framework for Solana.

Built solo for the Solana Foundation Colosseum Frontier hackathon (April 6 – May 11, 2026). The full stack is live on Solana mainnet right now and you are watching real transactions.

What you see in this video, in order:

00:00  The landing page. Verifier program 2qEm...cU9C is deployed on mainnet, OtterSec-verified, with security.txt embedded.

00:15  Wallet connection. Phantom integrated through Solana wallet adapter. Invite-gated for the demo period — every approval passes through a Telegram bot the developer controls.

00:35  Shielded deposit. The user picks a fixed denomination (0.1 / 0.5 / 1 / 10 SOL), writes a memo, and pastes their auditor's public key. The result is an opaque hex note — there's nothing for a chain-watcher to read.

01:10  Withdraw via relayer. The Groth16 proof is generated IN THE BROWSER (~1.7 seconds on M-series CPUs). The user's secret never leaves the tab — you can verify this yourself: the WebAssembly module's import set contains zero network APIs (fetch, WebSocket, XMLHttpRequest). Confinement is provable, not asserted. The transaction is then signed by relayer.tidex6.com, not by the user's wallet — your address never appears as the fee-payer.

01:45  The relayer is a public service with open endpoints. /health returns liveness, /stats returns balance and throughput. Anyone can run their own instance — the reference one is open-source under MIT/Apache-2.0.

02:00  The accountant page. The fund (or its auditor) pastes the matching secret key, picks a denomination, hits Scan, and gets back the full table of memos addressed to them — decrypted client-side, with on-chain transaction signatures. Privacy by default, transparency by choice.

02:25  CPI integration. tidex6 ships as a primitive, not an app. The reference example — tip-jar at 5Woh...9b9x — is a third-party Anchor program that uses the verifier via Cross-Program Invocation. About 80 lines of Rust to make any Solana program accept private payments.

02:45  Closing. I grant access, not permission.

═══ LIVE TRANSACTIONS FROM THIS RECORDING ═══

Deposit (Scene 2):
https://solscan.io/tx/2dWRkpRdLtc6kRv97cBUBH2YJALibC1oABpzmm9met7ZDAzvvSWNqERdRXDkyK5mttbL7hR32GTs78KQuzY6RVBc

Withdraw via relayer (Scene 3):
https://solscan.io/tx/23SbZPazgb9ZHykGW4N2QXYsQRX3V5As5Y6ThrEaN6Q6EB35A8gD5iYWcAaeSA6h6Hpa773pBSJtU4eh7F4edavR

═══ LINKS ═══

Verifier program (checks proofs, holds SOL):
https://solscan.io/account/2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C
https://verify.osec.io/status/2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C

Tip-jar reference (CPI example):
https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x
https://verify.osec.io/status/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x

Source: https://github.com/koshak01/tidex6
Live app: https://tidex6.com/
Relayer: https://relayer.tidex6.com/health · https://relayer.tidex6.com/stats

═══ USE CASES ═══

1. Private personal payments. A user sending money to family in a different jurisdiction without exposing the link between sender and recipient on the public chain.

2. Creator economy. Tip jars, subscription protocols, NFT royalty splitters — anyone who accepts crypto can become tidex6-aware in ~30 lines of Rust through CPI.

3. Transparent funds with private donors. A donation fund publishes one address forever instead of rotating wallets. Donors send shielded deposits. The fund hands one auditor key to its accountant — the auditor sees every contribution with date, amount, and memo, the public sees nothing. Privacy by default, transparency by choice — both at the same time.

═══ ARCHITECTURE ═══

Curve: BN254 (alt_bn128 syscalls)
Proof system: Groth16 via groth16-solana
Hash: Poseidon, circom-compatible (light-poseidon + solana-poseidon syscall, byte-identical)
Tree: append-only Merkle, depth 20 (~1M leaves), last 30 roots cached on-chain
Nullifier: one PDA per used nullifier (anti double-spend)
Memo: AES-256-GCM envelope, padded to 286 bytes, ECDH wrap-K to recipient + optional auditor
Browser prover: WebAssembly, ~1.7 s per proof, secret never leaves the tab (provable via WASM imports inspection)
Relayer: reference HTTPS service, fee-payer = relayer (your wallet never appears on chain as payer)

Verifier program is non-upgradeable after the final lock — no backdoor, no key escrow, no recovery service.

═══ DISCLOSURE ═══

DEVELOPMENT ONLY. Pre-audit, single-contributor Phase-2 trusted setup, hackathon-grade trust assumptions. The mainnet deployment is for end-to-end demonstration, not for securing real funds. Full threat model in docs/release/security.md.

I grant access, not permission.
```

---

## Tags (≤500 символов суммарно, разделители — запятые)

```
solana, privacy, zero knowledge, zk, groth16, rust, anchor, webassembly, shielded pool, bn254, colosseum frontier, hackathon, cryptography, web3, defi
```

---

## Чеклист публикации в YouTube Studio

1. **Title** — copy-paste из блока выше
2. **Description** — copy-paste **только содержимое внутри ```text...``` блока**, без обрамления
3. **Подставить tx-сигнатуры:**
   - найди deposit tx (Сцена 2) и withdraw tx (Сцена 3) — в Activity Log на сайте или на Solscan по своему кошельку
   - замени `<DEPOSIT_TX_FROM_RECORDING>` и `<WITHDRAW_TX_FROM_RECORDING>` в description на реальные сигнатуры
4. **Tags** — в Details → Show More → Tags
5. **Visibility:** Unlisted (как Week-1..4)
6. **Audience:** "No, it's not made for kids" (важно для submission)
7. **Chapters:** YouTube подхватит автоматически из timestamps `00:00`, `00:15`, ... в description (если первая строка с timestamp начинается с `00:00` — что у нас и есть)
8. После публикации — **открой ссылку в incognito**, проверь что unlisted-видео реально открывается

---

## Текущая длина description

```bash
# Проверить длину можно так:
wc -c <(sed -n '/^```text$/,/^```$/p' FINAL_DEMO_YOUTUBE.md | sed '1d;$d')
```

Должно быть ~4400-4500 символов — комфортно в лимит 5000.
