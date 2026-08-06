# What changed since Colosseum Frontier

**Frontier deadline: 11 May 2026. This document covers 11 May – 5 August 2026.**

Numbers first, because the claim "materially changed" should be checkable:

| | tidex6 | tidex6-web | tidex6-relayer | total |
|---|---|---|---|---|
| commits | 119 | 174 | 37 | **330** |
| lines | +42 529 / −6 146 | +19 305 / −10 433 | +1 644 / −286 | **+63 478 / −16 865** |
| files touched | 242 | | | |

Nine new ADRs (014–021). Ten new crates and programs. Four programs deployed
to mainnet. Almost all of it landed in a five-week burst: 8 commits in June,
**98 in July**, 13 in August.

---

## 1. The product itself changed

At Frontier this moved **SOL**, with the amount visible on chain, and the
deposit note handed from sender to recipient out of band.

Today it moves **USDC and USDT with the amount hidden**, and nothing is handed
over at all.

| Frontier | Now |
|---|---|
| SOL only | **USDC and USDT**, two pools live on mainnet |
| amount public | **amount hidden** — Token-2022 Confidential Transfers |
| note passed to recipient | **stealth** — the recipient scans the chain with their own key |
| ElGamal | **ML-KEM-768**, post-quantum envelope |
| no revenue model | **1% fee with a 0.1 floor, in the code and running** |
| no agent access | **two MCP servers**, OAuth, published agent skill |

Two assets rather than one matters more than it looks: it proves the scheme is
not welded to a single mint, and that adding an asset is a deployment, not a
redesign.

## 2. Speed: the scan stopped being linear in practice

**X25519 view-tag** (8–9 July, `tidex6-core::viewtag`, ADR-014 + roadmap A4).

Each envelope slot carries an ephemeral X25519 key and a **one-byte tag**. A
reader recomputes the tag with a single scalar multiplication and skips
everything that is not addressed to them — instead of running an ML-KEM
decapsulation per envelope.

Measured in the browser on 5 August: **102 envelopes, 17 of them ours,
decrypted in 0.02 s**. Without the tag every one of those 102 would have cost a
full decapsulation.

**Heavy work moved off the UI thread** (3 August): both the Groth16 prover and
the ceremony contribution run in Web Workers, with the WASM lazy-loaded. The tab
no longer freezes while a proof is built.

## 3. Security: holes found and closed

Not hardening in the abstract — specific defects, each with a commit:

- **Payment replay / front-run / wrong-sender** in the user-pays verification
  path (10 July). Then hardened again the same day: empty commitment rejected,
  TOCTOU-safe replay lock, strict memo match.
- **`RUSTSEC-2026-0144`** — anchor-lang 1.0.0 accepted any executable program
  as `Program<System>`, opening a vault-drain via transfer CPI. Bumped to
  1.1.2 and the verifier redeployed (30 June). No deposits existed yet; nothing
  was lost.
- **Unchecked lamport arithmetic** in confidential-amounts withdraw — reported
  as Sentio SW005, fixed 24 July.
- **Operator SOL preflight** (5 August). A deposit is a chain of transactions
  paid by two parties: the sender's USDC leaves first, then the operator pays
  for `deposit` and every `append_memo`. When the operator ran out of SOL
  mid-chain, the note landed in the tree with a half-written envelope —
  unreachable by both sides. The cost of finding this was one real dollar. The
  chain is now priced up front and refuses to start when it cannot finish.
- **Dependabot** kept current (serde_with 3.18 → 3.21, 20 July).

## 4. Reliability under a real RPC

Failures that only appear against a live network, each fixed where it happened:

- retry on `BlockhashNotFound` across all wrap CT operations, not just account
  creation (Helius node lag, 15 July);
- wait for freshly created ATAs to become visible before using them (8 July);
- a failed fee-note no longer kills an otherwise good deposit (17 July);
- compute-budget limit and priority fee on withdraw (1 July);
- reclaim window default raised from 10 minutes to **12 hours** (19 July) —
  ten minutes is not a window a human can act inside;
- config parsed **before** the first transaction is signed, not after (19 July).

## 5. Revenue, and it is private too

**ADR-016.** The fee is 1% with a 0.1 floor, configurable (`fee_bps`,
`fee_floor_micro`), and the payer sees it before signing.

The part that is unusual: **the fee is collected as its own stealth note**
(15 July). Operator income does not arrive in a visible account — it is
deposited to the operator's reader key exactly like any other payment, so an
observer cannot separate "protocol revenue" from user traffic.

We sell privacy and apply it to ourselves. On chain, next to each of the two
payments made on 5 August, the fee note appears four seconds later and is
indistinguishable from a payment.

The floor is not greed: rent for the memo account holding the envelope, plus
fees for `deposit` and every `append_memo`, cost the same whatever the amount.
That also means the 0.1 denominations are a devnet tool, and the tool
descriptions now say so.

## 6. Agents can use it without holding keys

**ADR-018 / ADR-021**, roughly 25 commits in late July.

- **Hosted MCP** at `mcp.tidex6.com` — OAuth with dynamic client registration,
  30-day tokens, prepare-only tools. The agent produces a link; the human signs
  in their own wallet. The agent never holds a key.
- **Local MCP** (`tidex6-mcp-local`) — same protocol, key on the operator's own
  machine, for people who want no hosted party at all.
- **Identity from a wallet signature** rather than a key file (ADR-018), with
  the signed message spelling out what a stolen signature would cost.
- **Published agent skill** at `/skill.md`.
- Fixed denominations and an in-code cap, so an injected instruction cannot ask
  for an arbitrary amount — the schema itself refuses to express it.
- Tools that **refuse to overstate**: "a line that could not be read is not a
  zero", "never report an unlanded payment as paid".

Verified on 5 August with a third-party agent (ZeroClaw 0.8.3): it read the
tool descriptions, understood it was mainnet with a local key, warned the
operator in its own words, waited for approval, and — when approval did not
come — reported plainly that nothing had happened on chain rather than claiming
success.

## 7. A wallet address is the whole address book

**ADR-019, on-chain reader registry** (25 July), deployed at
`D1dCoBuiRehhT24XTF8Dmhm9cFERpmfANLB1bb3aGxLJ` on both mainnet and devnet.

A wallet publishes its ML-KEM public key once. After that, a sender needs
**only the ordinary wallet address** — no key exchange, no file, no code
handed over. The registry stores public halves only and never touches money.

Deliberately: **no usernames.** A name has lookalikes; an address does not.

## 8. Trusted setup became a public ceremony

**ADR-017** (17–19 July): `ceremony_finalize` and `ceremony_extract_vk`, a
public chain-verification tool, `CEREMONY.md`, and a self-contained bootstrap
so production never needs snarkjs.

The contribution runs **in the contributor's own tab** — fresh entropy mixed
and destroyed locally, only the new parameters leave. Costs nothing, signs no
transaction, takes about a minute.

Anti-sybil: empty and brand-new wallets are rejected; a wallet must have
on-chain history at least 30 days old (3 August).

**This is the honest weak spot: 4 contributors so far, target 20+.** Until the
ceremony finishes, the verifying key is a development key, and the site says so
plainly rather than hiding it.

## 9. Regulated pools

**ADR-007 v2** (17 July): pool-level auditors. A regulator or exchange holds a
viewing key for an entire pool — sees every transaction with amount and memo,
**and can neither spend nor freeze**. Audit without seizure, which is the whole
argument of this project stated as a feature.

## 10. The web surface was rebuilt

174 commits. Highlights rather than a list:

- **Sign in with a wallet** (ADR-020) — signature instead of a password, and
  the ceremony contribution folded into the same signature by a checkbox.
- `/app` retired in favour of `/send`, `/receive`, `/accountant`, `/register`,
  `/pay`, `/verify`, `/business`.
- **A page that says how the project makes money** (`/business`) — including
  what is *not* true yet, which most projects omit.
- Analytics on the ceremony funnel (GA4 + X Pixel + Conversion API).
- **A blocking overlay on withdrawal** (5 August) — the page cannot be clicked
  during a ~25-second operation, and shows which stage is running.
- Copy corrected twice on 5 August: first to stop reading as a guide to evading
  controls, then to stop claiming more than the chain delivers. The site now
  says *"the chain never learns who paid whom"* instead of *"nobody can see"* —
  because a deposit and a withdrawal are both public, and what is hidden is the
  link between them.

## 11. The relayer became the browser's back door to the chain

37 commits, and a change of role. It started as "the thing that pays the
withdrawal fee so the recipient's wallet never appears as payer" — that still
holds — but the browser now needs a way to talk to the chain without shipping
an RPC key to every tab, and the relayer became that way:

- `POST /rpc/`, `GET /rpc-ws/`, and devnet twins — JSON-RPC and websocket
  proxies to Helius, with an **allowlist of methods** rather than an open pipe
  (`getAccountInfo` for the registry, `getBalance`, token balances,
  `getSignaturesForAddress` for the ceremony age gate — each added deliberately,
  one commit at a time);
- `GET /merkle-path`, `GET /memo-accounts` — the public data a browser prover
  needs, served without any key;
- `POST /build-deposit`, `POST /build-refund` — instruction recipes the wallet
  signs. **The relayer builds, the human signs, the relayer never holds a key.**
- `POST /client-error/` — browser errors reach the Telegram error topic, with
  secret material scrubbed on the way (defence in depth: the browser already
  scrubs, the relayer scrubs again);
- byte-exact canonical input check and DoS hardening on the withdraw path;
- timeouts sized to what actually happens: 90 s for `/withdraw/`, because it
  waits for confirmation, not for a request.

This is what let the fifth server binary be deleted (`tidex6_solana`, 1 July):
Solana work moved off the server entirely — into the browser for proving and
scanning, and into the relayer for public reads.

## 12. Anyone can check the browser code is the published code

`/verify` (9 July): the WASM prover is built from a **pinned toolchain with a
deterministic script**, and the page shows the hash of the artefact your tab is
running next to the hash anyone can reproduce from source. Not "trust us with
your secret" — "confirm it yourself, then trust the arithmetic".

This matters because the secret of a payment is generated in the tab and never
leaves it. A promise like that is worth exactly as much as the ability to
verify the code making it.

## 13. Supply chain, tightened before it bit us

8 July: **msgpack self-hosted** instead of loaded from a CDN, plus a strict
Content-Security-Policy. A third-party script on a payment page is a third
party who can rewrite the payment.

On 5 August this stopped being theoretical: the operator's machine was hit by
malware delivered through an npm dependency of an unrelated project. tidex6 was
untouched — but the lesson is the same one this commit was already about, and
it is now a rule rather than a preference.

## 14. Wallets, plural

9 July: **Wallet Standard** support — Phantom, Solflare, Backpack, Ledger —
instead of talking to `window.solana` and hoping. A privacy tool that works
with exactly one wallet is a privacy tool for the people who already have that
wallet.

## 15. The sender can take the money back

`reclaim` / `refund`, in the code (1 July) and in the UI (2 July). If a payment
is never collected, the depositor gets it back after the window — 12 hours by
default since 19 July, up from an unusable 10 minutes.

The withdrawal page warns before the deadline and, since 5 August, tells the
truth about the race: after the window a withdrawal still works, the sender
merely *may* reclaim first.

## 16. One server binary fewer

1 July: the fifth binary (`tidex6_solana`) was **deleted**. Scanning and merkle
paths moved into the browser, public reads into the relayer, proving into a Web
Worker. Less server, less trust required, fewer places a key could have lived.

## 17. Engineering hygiene

- Reproducible builds: the verifier via `solana-verifiable-build` (Docker), the
  browser prover with a pinned toolchain and a deterministic script — anyone can
  confirm the code in their tab is the published source.
- Published to crates.io with a README on every crate.
- The public repo builds for someone who is not us.
- CI gate on `cargo fmt`; found and fixed the gap that excluded crates were
  never checked by it.

---

## Beyond the code

Work that does not show up in a commit count but took the same weeks:

**Submissions and funding.** ZeroClaw Earn bounty — full package submitted
~30 July (write-up, Discord showcase, demo video, agent skill, two config
profiles), judging closes 21 August. Superteam Balkan grant application filed
25 July.

**Competitive research.** A corpus in `_analysis/` covering the privacy
landscape — deep dives into DarkDrop, Kohaku (Ethereum Foundation's privacy
toolkit), the Frontier rivals, and a survey of 28 previous Colosseum
privacy/payments winners. That last one is uncomfortable reading: most are
dead within a year — repositories 404, DNS expired, pushes that stopped the
week the hackathon ended. It is also why "still shipping in August" is a claim
worth making.

Two findings from that research changed the product rather than a slide deck:
the view-tag came out of studying how others scan, and the pool-level auditor
design (ADR-007 v2) came out of reading what regulated venues actually need.

**A second chain, explored honestly.** August: a Leo 4.4 spike on **Aleo** —
a private transfer with an auditor slip, the same "privacy with consent" shape
expressed in a different privacy platform's language. Kept deliberately
separate from tidex6 rather than folded in: a spike is a spike until it earns
its place.

**Growth machinery.** Ceremony funnel instrumented end to end (GA4 Measurement
Protocol server-side, X Pixel plus Conversion API), ad creatives prepared, and
an X Ads account approved with billing attached. The outcome is a negative
result worth recording: the one campaign that ran bought 523,690 impressions
and 527 clicks for $22.64 and produced **zero** ceremony contributions, while
both campaigns that named the ceremony directly were blocked by the platform
as financial promotion. Paid feed does not reach people willing to sign a
contribution — direct outreach is the only channel left.

---

## Live numbers, 5 August 2026

```
mainnet pools        2 (wUSDC, wUSDT), both with hidden amounts
envelopes on chain   105
payments             46, all received
disclosed to auditor 18
programs deployed    verifier v2 (immutable), wUSDC pool, wUSDT pool, registry
ceremony             4 contributors of 20+ needed
```

Three independent paths were exercised end to end on mainnet the same day —
local CLI, browser with Phantom, and a third-party AI agent — each completing
send → audit → receive with real money.

---

*I grant access, not permission.*
