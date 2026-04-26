# tidex6-tip-jar

Reference integration example: a third-party Anchor program that
uses [`tidex6-verifier`](../tidex6-verifier/) as a **privacy
primitive** via Cross-Program Invocation.

**Live on Solana mainnet, OtterSec-verified** at
[`5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`](https://solscan.io/account/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x)
(latest deploy tx
[`5svz5fvBqnf4YWwFYbd99qZkEy6KmYZwEtegd3KNuYkV3brEXPrkaXU9QcoLpJwSrgFqp5GjcAqC8owrVydXvpSP`](https://solscan.io/tx/5svz5fvBqnf4YWwFYbd99qZkEy6KmYZwEtegd3KNuYkV3brEXPrkaXU9QcoLpJwSrgFqp5GjcAqC8owrVydXvpSP),
executable hash `d472146fa4d8b4f3bade8354ddf6480a02b91b95a13321681244a1bb018b66d9`,
~96 KB BPF). Embeds a `solana_security_txt!` block so explorers
display the project name, source URL, and `source_release =
"2.5.20"`. Public verification badge:
<https://verify.osec.io/status/5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x>.
Upgrade authority retained by the project — this is a reference
example, not consensus-critical infrastructure.

> **What this answers:** "Can my own protocol on Solana use tidex6
> for privacy without rewriting half of it?" — Yes, in about thirty
> lines of Rust, deployed and verifiable on mainnet today.

## What it does

Anyone calls `tip(creator, commitment, memo_payload)` on this
program. Inside the instruction we forward the deposit straight
into `tidex6_verifier::deposit` via CPI:

```rust
let cpi_program_id = ctx.accounts.tidex6_verifier_program.key();
let cpi_accounts = VerifierDeposit {
    pool: ctx.accounts.pool.to_account_info(),
    vault: ctx.accounts.vault.to_account_info(),
    payer: ctx.accounts.tipper.to_account_info(),
    system_program: ctx.accounts.system_program.to_account_info(),
};
let cpi_ctx = CpiContext::new(cpi_program_id, cpi_accounts);
tidex6_verifier::cpi::deposit(cpi_ctx, commitment, memo_payload)?;

emit!(TipEvent {
    creator: ctx.accounts.creator.key(),
    commitment,
});
```

That's the entire privacy integration. The note returned to the
tipper is **identical** to what `tidex6 deposit` from the CLI would
produce — same Poseidon commitment, same Merkle insertion, same
[ADR-012 envelope](../../docs/release/adr/ADR-012-opaque-note-envelope-memo.md).
The creator redeems it through the normal withdraw flow whenever
they want.

## What it demonstrates

| Property | tip-jar inherits from tidex6-verifier |
|---|---|
| **Sender hidden on chain** | yes — only `tipper` shows up as fee-payer; recipient is invisible |
| **Fixed denominations only** | yes — same `(0.1 / 0.5 / 1 / 10)` SOL pools |
| **ADR-012 padded envelope** | yes — same memo encryption and constant-size ciphertext |
| **Note format** | identical opaque hex; fully interoperable with the main CLI/SDK |
| **Withdraw path** | unchanged — `tidex6 withdraw` or `tidex6.com` redeem this exactly the same |

The third-party program **never sees the user's secret material**.
The tipper computes `(secret, nullifier, commitment, memo_payload)`
locally with `tidex6-client`, then passes only the public commitment
+ envelope into the program. Privacy is preserved end-to-end.

## What is intentionally NOT here

- **Per-creator state** — no PDA tracking "creator earnings". That
  data lives off-chain in the creator's note set; any UI that wants
  aggregation listens to `TipEvent` logs.
- **Tipping with custom amounts** — the verifier enforces fixed
  denominations. A real product would maintain a one-pool-per-tier
  routing table or split a tip across multiple deposits.
- **On-chain reply / acknowledgement** — irrelevant here; that
  belongs in a higher-level messaging layer.

## Build

This program compiles as part of the workspace:

```bash
cargo check -p tidex6-tip-jar --features no-entrypoint
```

For an actual on-chain deploy, follow the
[`reference_deploy_runbook`](../../docs/release/) pattern — same as
the verifier deploy, just point at this crate's `.so` instead.

## Future use cases (sketches)

The same one-CPI pattern enables, with a few more accounts:

- **DAO Payroll** — iterate over an employee Vec, do one CPI deposit
  per employee per pay cycle. Treasury stays public; salaries don't.
- **NFT royalty splitter** — when a sale lands, split the royalty
  across creators using one CPI deposit per share.
- **Subscription protocol** — monthly automated tip from each
  subscriber to the creator they follow.
- **Dark-pool DEX hook** — match orders publicly but settle through
  the shielded pool so post-trade balances don't leak strategy.

In every case the integrating program writes the protocol-specific
logic; tidex6 handles the privacy.
