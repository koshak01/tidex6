# private-payroll — the tidex6 flagship example

> Lena lives in Amsterdam. Her elderly parents live in a country
> where bank transfers from Europe get flagged by compliance
> systems that cannot tell love from laundering. With tidex6 she
> does what her grandmother did with cash in envelopes — sends
> dignity home, invisibly. At tax time her accountant Kai scans
> the chain with his own key — Lena sealed an auditor slot to him
> on every deposit — sees every transfer with memos, and prepares
> a compliant report.
>
> **I grant access, not permission.**

This example is a three-binary end-to-end demo of the tidex6
shielded pool, showcasing the three actors of the flagship story:

| Binary | Actor | What it does |
|---|---|---|
| `sender` | Lena (Amsterdam) | Seals a private monthly deposit to the parents' ML-KEM key + an auditor slot to Kai; keeps the note locally as a refund copy only |
| `receiver` | Parents (home) | Scans the chain with their ML-KEM secret, reconstructs the note, and withdraws via a zero-knowledge proof — nothing was handed over |
| `accountant` | Kai | Scans the chain with his own ML-KEM secret and prints a Markdown tax report |

The demo runs against live Solana mainnet-beta and uses the production
`tidex6-client` SDK under the hood. Each binary is ~150 lines of
Rust. Together they prove that a user can have financial privacy
by default *and* compliance by choice, without a central auditor.

## Prerequisites

1. Rust stable (edition 2024).
2. Solana CLI configured for mainnet-beta:
   ```bash
   solana config set --url https://api.mainnet-beta.solana.com
   ```
3. A mainnet wallet with a few SOL at `~/.config/solana/id.json`.
4. The `tidex6-verifier` program deployed on mainnet-beta — already
   live and immutable at
   `CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd`, no action needed.
5. ML-KEM-768 identities for the parents and Kai. Generate one each
   with `tidex6 keygen --out <file>`; the parents and Kai each keep
   their own secret, while Lena uses only their public keys (printed
   by `tidex6 keygen print-mlkem-pk --identity <file>`).

## Running the individual binaries

### Step 1 — Lena sends

```bash
cargo run --release --bin sender -- \
    deposit \
    --amount 0.5 \
    --memo "october medicine" \
    --recipient <parents_mlkem_pk_hex> \
    --auditor <kai_mlkem_pk_hex> \
    --revoke-after-days 30 \
    --recipient-label parents \
    --note-out /tmp/parents.note
```

This creates a fresh `DepositNote`, seals it for the parents'
ML-KEM key and an amount+memo slot for Kai's auditor key, and sends
the deposit transaction to the `HalfSol` pool. The note is written
to `/tmp/parents.note` and kept by Lena **only** as a local refund
copy — the parents never receive it. The local
`~/.tidex6/payroll_scan.jsonl` line is Lena's own bookkeeping. With
`--revoke-after-days 30`, if the parents never withdraw, Lena can
refund the deposit after the window.

### Step 2 — Parents redeem

```bash
# Get a recipient pubkey — the parents' wallet.
RECIPIENT=$(solana-keygen pubkey ~/.config/solana/id.json)

cargo run --release --bin receiver -- \
    receive \
    --identity ~/.tidex6/parents.json \
    --to $RECIPIENT
```

The receiver binary scans the chain with the parents' ML-KEM
secret, finds every payment Lena sealed to them, reconstructs each
note from the decrypted recipient slot, rebuilds the offchain
Merkle tree via `tidex6-indexer`, generates a Groth16 withdrawal
proof, and submits it to the verifier program. The parents end up
with `0.5 SOL` in their wallet, with no on-chain link back to
Lena's original deposit beyond what the nullifier PDA exposes (and
that only reveals the pool has been spent, not who by). Nothing was
handed over — the chain itself delivered the money.

### Step 3 — Kai audits

```bash
cargo run --release --bin accountant -- \
    scan \
    --identity ~/.tidex6/kai.json \
    --output /tmp/lena_tax_report.md
```

Kai scans the chain with his own ML-KEM secret (via
`AccountantScanner`), decrypts every auditor slot Lena addressed to
him, and emits `/tmp/lena_tax_report.md` — a clean Markdown report
with the amount and memo of each transfer and a grand total ready to
attach to a tax return. Kai can read, but cannot spend, and Lena
sent him nothing.

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

## Selective disclosure

Selective disclosure is on-chain and post-quantum. On every deposit
Lena seals an **auditor slot** — the amount and memo, encrypted to
Kai's ML-KEM-768 public key (ADR-014) — into a dedicated account
beside the commitment. Kai scans the chain with his own ML-KEM
secret and reconstructs exactly the transfers Lena addressed to him,
nothing more. He can read; he cannot spend. There is no shared file,
no key escrow, no mandatory auditor: Lena decides what Kai sees by
choosing whether to include his key, deposit by deposit.

## What this demo proves

1. **Privacy by default.** Lena's `sender` transaction publishes
   only a commitment hash — no sender, no receiver, no amount
   visible on-chain beyond "someone deposited into the 0.5 SOL
   pool".
2. **Spend on a private key.** The `receiver` binary reconstructs
   and spends the note as long as the parents hold their ML-KEM
   secret — Lena never hands them a note. No tx history, no linkage.
3. **Compliance by choice.** Kai sees everything Lena has
   disclosed, nothing she has not. The auditor slot, sealed to his
   ML-KEM key, is the capability, and Lena controls it.
4. **No central auditor.** There is no server, no admin, no
   special account. The protocol has one opinion: the user
   decides.
