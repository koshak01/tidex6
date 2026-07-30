# tidex6-client

The Rust SDK for [tidex6](https://tidex6.com) — private stablecoin payments on
Solana, where the amount is hidden and the sender chooses who may read it.

```rust
// Deposit: the note never leaves this process.
let pool = PrivatePool::connect(rpc_url, program_id)?;
let deposit = pool.deposit().amount(500_000_000).send(&payer)?;

// Withdraw: rebuilds the tree from chain, proves, submits.
pool.withdraw()
    .note(&note)
    .to(recipient)
    .via_relayer("https://relayer.tidex6.com", relayer_pubkey)
    .send(&payer)?;
```

Builder-pattern API (ADR-006), plus a `confidential` module for the hidden-amount
flow: sealing a note into an ML-KEM envelope, paying the pool operator, scanning
the chain as recipient or as auditor, and spend limits enforced before the first
transaction rather than after.

Two things worth knowing before you build on this:

**The recipient is never handed a note.** They scan the chain with their own key
and reconstruct it. There is nothing to transmit and nothing to intercept.

**An auditor slot carries the amount and the memo and not the spend material.**
The separation is in the ciphertext, not in a rule someone promises to keep.

## Status

Live on Solana mainnet. The verifier program
[`CSDD31Zm…`](https://solscan.io/account/CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd)
is immutable and OtterSec-verified; the pools and the reader registry are
verified and still upgradeable.

**Pre-audit.** The verifying key comes from a single-contributor trusted setup, so
proofs against it are forgeable by whoever ran that setup. A public ceremony is
live at [ceremony.tidex6.com](https://ceremony.tidex6.com) and needs
contributors — it takes a minute in a browser, spends nothing, and authorises no
payment. Until it finalises, do not use this to secure real funds.

- Repository: <https://github.com/koshak01/tidex6>
- Docs: [THE_LEGEND](https://github.com/koshak01/tidex6/blob/master/docs/release/THE_LEGEND.md) ·
  [PROJECT_BRIEF](https://github.com/koshak01/tidex6/blob/master/docs/release/PROJECT_BRIEF.md) ·
  [security](https://github.com/koshak01/tidex6/blob/master/docs/release/security.md)

License: MIT OR Apache-2.0.
