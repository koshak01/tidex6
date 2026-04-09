# private-payroll — the tidex6 flagship example

> Lena lives in Amsterdam. Her elderly parents live in a country
> where bank transfers from Europe get flagged by compliance
> systems that cannot tell love from laundering. With tidex6 she
> does what her grandmother did with cash in envelopes — sends
> dignity home, invisibly. At tax time her accountant Kai imports
> her scan file, sees every transfer with memos, and prepares a
> compliant report.
>
> **I grant access, not permission.**

This example is a three-binary end-to-end demo of the tidex6
shielded pool, showcasing the three actors of the flagship story:

| Binary | Actor | What it does |
|---|---|---|
| `sender` | Lena (Amsterdam) | Makes a private monthly deposit + appends a local scan entry for Kai |
| `receiver` | Parents (home) | Redeems the note into their wallet via a zero-knowledge withdraw |
| `accountant` | Kai | Reads Lena's scan file, prints a Markdown tax report |

The demo runs against live Solana devnet and uses the production
`tidex6-client` SDK under the hood. Each binary is ~150 lines of
Rust. Together they prove that a user can have financial privacy
by default *and* compliance by choice, without a central auditor.

## Prerequisites

1. Rust stable (edition 2024).
2. Solana CLI configured for devnet:
   ```bash
   solana config set --url https://api.devnet.solana.com
   ```
3. A devnet wallet with a few SOL at `~/.config/solana/id.json`.
   `solana airdrop 2` works if you need more.
4. The `tidex6-verifier` program deployed on devnet — already live
   at `77CwxmFdDaFpKHXTjR5fHVpUJ36DmhnfBNBzn8dXKo42`, no action
   needed.

## Running the individual binaries

### Step 1 — Lena sends

```bash
cargo run --release --bin sender -- \
    deposit \
    --amount 0.5 \
    --memo "october medicine" \
    --recipient-label parents \
    --note-out /tmp/parents.note
```

This creates a fresh `DepositNote`, sends the deposit transaction
to the `HalfSol` pool, saves the note to `/tmp/parents.note`, and
appends one entry to `~/.tidex6/payroll_scan.jsonl`.

### Step 2 — Parents redeem

```bash
# Get a recipient pubkey — the parents' wallet.
RECIPIENT=$(solana-keygen pubkey ~/.config/solana/id.json)

cargo run --release --bin receiver -- \
    withdraw \
    --note /tmp/parents.note \
    --to $RECIPIENT
```

The receiver binary rebuilds the offchain Merkle tree via
`tidex6-indexer`, finds the leaf index of the note's commitment,
generates a Groth16 withdrawal proof, and submits it to the
verifier program. The parents end up with `0.5 SOL` in their
wallet, with no on-chain link back to Lena's original deposit
beyond what the nullifier PDA exposes (and that only reveals the
pool has been spent, not who by).

### Step 3 — Kai audits

```bash
cargo run --release --bin accountant -- \
    scan \
    --scan-file ~/.tidex6/payroll_scan.jsonl \
    --output /tmp/lena_tax_report.md
```

Kai reads the scan file Lena shared, groups by month and by
recipient label, and emits `/tmp/lena_tax_report.md` — a clean
Markdown report with monthly totals and a grand total ready to
attach to a tax return.

## Running the full demo

For the three-terminal demo used in the demo video, use the
convenience wrapper:

```bash
./scripts/run_demo.sh
```

This script uses `tmux` to split one terminal into three panes
and runs `sender`, `receiver` and `accountant` in sequence so the
full workflow fits on one screen. Uses
`~/.config/solana/id.json` as the payer across all three roles
for simplicity; in a real three-party setup each actor would have
their own wallet.

## MVP note: selective disclosure

The full tidex6 vision has the accountant receive a *viewing
key* from Lena and use it to decrypt encrypted memos attached to
each on-chain deposit. The MVP ships a simpler, equally
demo-friendly version: Lena writes memos to a local JSONL scan
file, and shares that file with the accountant at tax time. This
is the same selective-disclosure idea (Lena decides what Kai
sees) without the full ElGamal + Baby Jubjub machinery. That
machinery is planned for v0.2 — see `docs/release/ROADMAP.md`.

## What this demo proves

1. **Privacy by default.** Lena's `sender` transaction publishes
   only a commitment hash — no sender, no receiver, no amount
   visible on-chain beyond "someone deposited into the 0.5 SOL
   pool".
2. **Spend on a private key.** The `receiver` binary can spend
   the note as long as the parents have the `DepositNote` file.
   No tx history, no linkage.
3. **Compliance by choice.** Kai sees everything Lena has
   shared, nothing she has not. The scan file is the capability,
   and Lena controls it.
4. **No central auditor.** There is no server, no admin, no
   special account. The protocol has one opinion: the user
   decides.
