# tidex6 — Demo Video Script

**Target length:** under 3 minutes (Colosseum hard limit: 3:00)
**Format:** screen recording, live terminals — **NOT a slide deck, NOT a code walkthrough**
**Audio:** voiceover in English, recorded separately and laid over the screencast
**Upload:** YouTube unlisted (the demo video field is not marked PUBLIC, so unlisted is fine)

---

## What Colosseum asks for

> *"Should show the live product, not a slide deck, not a code walkthrough."*

Read that twice. The judges have seen thousands of hackathon
videos. They want proof your thing **runs**, not a pitch. So the
demo video is almost all terminal. No figma mockups, no
architecture diagrams, no camera on your face. Just three
terminals doing real things on real devnet.

---

## Pre-flight checklist (do all of this before you hit record)

- [ ] Devnet wallet has at least **1 SOL** at `~/.config/solana/id.json`. Check with `solana balance`.
- [ ] Run `cargo build --release --bin tidex6 --bin sender --bin receiver --bin accountant` once cold so the actual demo runs don't include a 3-minute cargo build.
- [ ] Pre-generate a recipient keypair for the parents: `solana-keygen new --no-bip39-passphrase --silent --outfile /tmp/parents.json && solana-keygen pubkey /tmp/parents.json` → remember the pubkey.
- [ ] Delete any stale files from earlier takes: `rm -f /tmp/parents.note /tmp/lena-demo-scan.jsonl /tmp/lena-demo-report.md`.
- [ ] Close Slack, Telegram, every notification source. A notification popping up mid-record ruins a take.
- [ ] Set terminal font to **16pt minimum** — video compression eats small text.
- [ ] Use a dark colour scheme in the terminal. Contrast reads better in video codecs than light themes.
- [ ] Open OBS, create a scene with one big terminal window filling the whole 1920×1080 frame. Add a logo overlay in the top-right corner using `brand/logo-dark.png`.

---

## 🎬 SCRIPT — 2 minutes 50 seconds

### 🎯 0:00 – 0:10  —  **Hook** (10 s)

**On screen:**
Logo `brand/logo-dark.png` fills the frame, full size, centred on
black. Slogan `I grant access, not permission.` fades in below.

**Voiceover:**

> tidex6. A Rust-native privacy framework for Solana, running
> live on devnet right now. Here is one minute of proof.

**Notes:**
- Slow fade in of logo, 0.5 seconds.
- Hold 2 seconds on the slogan, silent.
- Then cut hard to the terminal. No transition effects.

---

### 🎯 0:10 – 0:20  —  **Setup shot** (10 s)

**On screen:**
One big terminal. You type one command — slowly, visibly:

```bash
solana balance && solana config get | head -2
```

Terminal shows a real number (e.g. `11.4 SOL`) and the devnet
RPC URL.

**Voiceover:**

> Real devnet. Real wallet. Real balance. No mocks.

**Notes:**
- This is the **grounding shot**. It tells the judge "everything
  you see after this is live on-chain."
- Do **not** type anything else. Resist the urge to set up 15
  terminals. One terminal, one command, one cut.

---

### 🎯 0:20 – 1:15  —  **Act 1: Lena sends** (55 s)

**On screen:**
Same terminal. You run the sender binary with a real memo:

```bash
cd examples/private-payroll
cargo run --release --bin sender -- \
    deposit --amount 0.5 --memo "october medicine" \
    --recipient-label parents --note-out /tmp/parents.note
```

Wait for output — commitment, signature, leaf index, explorer
URL, "Note written to /tmp/parents.note".

Then `cat /tmp/parents.note` to show the note text format on
screen:

```
tidex6-note-v1:0.5:<secret_hex>:<nullifier_hex>
```

**Voiceover:**

> Meet Lena. She's in Amsterdam, sending money home to her
> parents. She runs `tidex6 sender deposit`, 0.5 SOL, memo
> "october medicine." The tidex6 SDK generates a fresh deposit
> note, sends a zero-knowledge commitment to the shielded pool,
> and writes the note to a file. That file is everything the
> parents need to redeem the money. The pool publishes only a
> hash — no sender, no receiver, no amount visible on-chain.

**Notes:**
- This is the **longest section** because it is the most
  visually dense. The voiceover has to match the actual
  runtime — roughly 40 seconds for the sender command on a warm
  cargo build.
- When the sender finishes, **click the explorer URL** in the
  terminal and cut to a quick browser shot of Solscan showing
  the transaction. Hold on Solscan for 3 seconds with the
  voiceover saying *"This transaction is on-chain, right now."*
- Then cut back to the terminal.

---

### 🎯 1:15 – 1:55  —  **Act 2: Parents redeem** (40 s)

**On screen:**
Same terminal. You run the receiver binary, passing the note
file and a parents pubkey:

```bash
cargo run --release --bin receiver -- \
    withdraw --note /tmp/parents.note \
    --to $(solana-keygen pubkey /tmp/parents.json)
```

Output streams: "rebuilding Merkle tree from on-chain history",
"generating zero-knowledge withdraw proof", "submitting to
verifier program", then the signature and "Recipient … received
the funds. Done."

**Voiceover:**

> The parents get the note file. They run
> `tidex6 receiver withdraw`. The SDK reads the pool's on-chain
> log history, rebuilds the Merkle tree offline, finds the leaf,
> generates a Groth16 proof with `WithdrawCircuit<20>`, and sends
> it to the verifier program. The verifier runs the proof through
> Solana's native alt_bn128 syscalls, pays out 0.5 SOL, and writes
> a nullifier PDA so the note can never be spent twice. No
> linkage between Lena's deposit and the parents' withdrawal.

**Notes:**
- Proof generation takes about 15 seconds. The voiceover pace
  should match that — don't rush, let the judge watch the terminal
  lines stream.
- When the final "Recipient ... received" line appears, cut to
  Solscan again (fresh tab) showing the withdraw tx. Hold 3
  seconds. *"Here is the payout transaction. The recipient
  balance increased by exactly 0.5 SOL, and the proof is in the
  program logs."*

---

### 🎯 1:55 – 2:35  —  **Act 3: Kai audits** (40 s)

**On screen:**
Same terminal. You run the accountant binary:

```bash
cargo run --release --bin accountant -- \
    scan --scan-file ~/.tidex6/payroll_scan.jsonl \
         --output /tmp/lena-report.md
```

Output prints the summary:

```
  Lena's transfers summary:
    2026-10-05 | parents | 0.5 SOL | october medicine | 5kQ64DkVSE7y…
  Grand total: 0.500 SOL
Tax report ready.
```

Then cut to an editor with `/tmp/lena-report.md` open, scrolled
to show the Markdown tables.

**Voiceover:**

> At tax time, Lena gives her accountant Kai a scan file she
> kept locally — one JSON line per transfer. Kai runs
> `tidex6 accountant scan`, and gets back a Markdown tax report
> grouped by month and recipient, with every memo and
> transaction signature intact. Kai sees exactly what Lena chose
> to show him. Nothing more, nothing less. Selective disclosure
> is not a backdoor — it is a capability that Lena holds and
> shares at her discretion.

**Notes:**
- This is the **narrative climax**. It is what differentiates
  tidex6 from every other privacy pool: *privacy by default,
  transparency by choice.*
- Markdown report in the text editor should look clean. Use a
  dark theme with good syntax highlighting for Markdown.

---

### 🎯 2:35 – 2:50  —  **Wrap** (15 s)

**On screen:**
Cut back to the tidex6 logo. Slogan `I grant access, not permission.`
under it. Below the slogan, three lines of white text fade in
one after the other:

```
github.com/koshak01/tidex6
Live on Solana devnet.
No backdoor. No key escrow. By choice.
```

**Voiceover:**

> This is tidex6. Rust-native. BN254. Groth16. Live on Solana
> devnet today. Repository link in the description. I grant
> access, not permission.

**Notes:**
- Silence for 2 seconds after the last word. Just logo on
  screen, no movement. Then fade to black.
- **Do not** add an outro jingle. Silence is louder here than
  music.

---

## Alternate 3-minute variant (if you have slack)

If the full demo runs closer to 2:30 and you have 30 seconds to
spare, insert a short negative-test section between Act 3 and
the wrap:

> *"One more thing. Let's try to break it. What happens if someone
> front-runs the withdrawal by replacing the recipient account?"*

Show a one-line command that re-submits the withdraw with a
different recipient, get the `Groth16VerificationFailed` error,
cut to the terminal:

```
Error: custom program error: 0x1773
AnchorError: Groth16VerificationFailed
```

Voiceover:

> *"The proof is bound to the recipient. Change the recipient,
> the proof is invalid, the transaction reverts. Front-running
> protection is part of the cryptography, not policy."*

Then wrap as above.

This is optional. Skip it if you're tight on time — the three
main acts are enough for Colosseum judging.

---

## 📋 Repetition checklist

Before hitting "record final":

### Content
- [ ] Total runtime **≤ 3:00**. Ideal is 2:40–2:50.
- [ ] Three clear acts: Lena deposits, parents withdraw, Kai audits.
- [ ] Two Solscan cuts: one after the deposit, one after the withdraw. These are the "it's real" shots.
- [ ] The slogan appears twice: once in the hook, once in the wrap.
- [ ] GitHub URL on screen in the final frame.

### Form
- [ ] Terminal commands typed at a reasonable pace — not so slow it drags, not so fast the viewer can't read.
- [ ] All output fits in the viewport without scrolling cut off.
- [ ] No typos in commands. Re-do the take if there's a typo.
- [ ] Voiceover is separate from the screen-record audio. Don't rely on live narration during the take — it always sounds worse.

### Technical
- [ ] 1920×1080 resolution (1080p).
- [ ] 30 FPS is enough; 60 FPS is overkill for terminal content.
- [ ] H.264 codec, .mp4 container, ~10 Mbps target bitrate.
- [ ] Audio: 48 kHz, 192 kbps stereo.
- [ ] No compression artifacts on the text — check by pausing at random frames.

### Visuals
- [ ] Logo overlay in the top-right corner throughout the terminal shots. Small, ~10% of screen width. This is your branding across the whole video.
- [ ] Dark terminal theme (Solarized Dark, Dracula, or similar).
- [ ] Monospace font that renders cleanly at small sizes (JetBrains Mono, Berkeley Mono, Fira Code).
- [ ] No personal notifications visible in the menu bar. Screenshot the menu bar before recording and sanity-check.

---

## 🛠 Tools

### Screen recording
- **OBS Studio** (https://obsproject.com) — free, high quality, full control over scenes and overlays. This is the right tool.
- QuickTime Player works in a pinch but has no overlay/scene support. Only use it if you want a one-shot unedited demo.

### Terminal
- **iTerm2** with a clean 16pt monospace font. Drop the scrollbar, drop the tab bar, drop every decoration — just the text.

### Editing
- **iMovie** for the Solscan cuts and the hook/wrap. Free, bundled with macOS. Enough for this video.
- **DaVinci Resolve** if you want finer control over audio ducking.

### Voiceover
- AirPods Pro or a USB microphone, **not** the MacBook built-in.
- Record the voiceover **separately**, after the screencast is done. Read it from this script into QuickTime's audio recorder, then drag the audio file into iMovie on top of the screencast. Speaking while operating a terminal is much harder than it sounds, and the result is always worse.

---

## 🚨 Failure modes

- **The sender or receiver binary hits an RPC timeout.** Devnet is occasionally flaky. Re-run the take. Do not edit around the timeout — judges will see the edit.
- **The cargo build takes 90 seconds.** Pre-build in release mode before starting the take. Also consider running the same binary once before recording so the OS cache is warm.
- **The Merkle tree rebuild reports `replay mismatch`.** This means you ran the demo on a pool that has old-format deposit logs. Use the `HalfSol` denomination (`--amount 0.5`) — it is the clean demo pool.
- **Your voice cracks or you stumble.** Re-record the voiceover. It is 2 minutes of audio. Do 10 takes and pick the best one.

---

## 📝 Key lines to nail

If you forget everything else in the script, these are the lines
that **must** be in the voiceover verbatim:

1. `"Real devnet. Real wallet. Real balance. No mocks."` (setup)
2. `"Privacy by default, transparency by choice."` (Act 3)
3. `"I grant access, not permission."` (wrap)

Everything else is supporting narration. These three are the
brand.

---

**When you are ready to record: do 5 takes back-to-back without
reviewing them, then review all 5 and pick the best. That is the
fastest path to a good demo video.**
