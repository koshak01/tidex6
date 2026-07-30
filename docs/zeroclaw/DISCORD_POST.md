# Showcase post for #solana-bounty

**Deadline: 7 August 2026, 02:59 UTC.** Prizes 1800 / 1200 / 1000 USDG plus four
honourable mentions at 250.

**Where it goes, in this order:**

1. `#solana-bounty` on the ZeroClaw Discord — the showcase post below, with the
   video attached to the same message. Their words: *"A submission is a showcase
   post. There is no other submission format."*
2. Superteam Earn — "Submit Now" on the listing, linking to that Discord post.

**Do not** open a plugin PR against their registry: *"Registry merges happen
separately after judging."*

**The video** — 3 minutes or less, and they say what they want to see: *"No
slides. Terminal + phone is perfect."* So the terminal is not a problem here, it
is the point. See `video/SHOOT.md`.

Discord caps a message at 2000 characters; the post below is 1996, and the full
write-up lives in the repo. Paste it as one message.

**Before posting, replace `<VIDEO>`** — either attach the file to the message
(then delete the line) or paste the link.

**Optional tiebreak:** *"build-in-public logs on X during the bounty."* If you
post anything on X between now and the 7th, it counts.

---

**A payment agent that hides the payment, not the key**

Paying contractors on a public chain publishes your payroll, permanently. Hiding
everything doesn't fix it: the accountant still has to see every payment.

In Telegram: `pay 1 USDT to 2GdZ…, memo — July retainer, auditor 9BpK…`

On chain: a commitment hash. No sender, no recipient, **no amount**. Once a month
the accountant signs once in their own browser and reads every payment with
amounts and memos — because the payer handed them that key, and only that key.
One chain, three viewers, three levels of visibility.

**Custody, both ways.** T1 hosted: no key held, agent prepares, human signs. T2
local (in the video): key on my own machine, bounded in code — 5 per payment, 25
per rolling day, USDC/USDT only, `amount` is an enum so "100 USDC" has no wire
representation, and the recipient must already be in the on-chain registry, so a
fresh attacker address isn't a valid destination. Worst case for an injection: 5
USDC to an address the attacker registered beforehand, every step visible in
Telegram. Two transcripts in the write-up — one direct, one hidden in an invoice.

**Tier 2 by your ladder.** Stock release binary, no plugin, no fork: ZeroClaw is
an MCP client, tidex6 runs an MCP server. Telegram, sqlite memory, one skill.

tidex6 is Rust, live on mainnet, verifier immutable and OtterSec-verified:
Token-2022 Confidential Transfers hide the amount, a Groth16 pool hides the link,
ML-KEM-768 envelopes carry the note so the payer transmits nothing. Your listing
names *"stealth addresses, hidden amounts, compliance viewing keys"* — that's
these three, running.

Reported, not hidden: what the operator sees on the send path, that our
verification key is a dev key until the ceremony has contributors, and two
ZeroClaw rough edges (#9486 address redaction, filed; `config migrate` dropping
bearer tokens).

Write-up + configs + skill:
<https://github.com/koshak01/tidex6/blob/master/docs/ZEROCLAW_SUBMISSION.md>

<VIDEO>
