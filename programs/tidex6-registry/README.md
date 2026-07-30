# tidex6-registry

The tidex6 reader registry — the program that makes a wallet address the only
thing a sender needs to know.

A wallet publishes its ML-KEM reader key once, into a PDA derived from the
address itself. After that, anyone can seal a payment to it without a prior
exchange, a handle, or a name.

Names were considered and rejected on purpose (ADR-019): `@petr` and `@реtr` are
indistinguishable to a human and different to a computer, and a payment system
where the destination can be spoofed by a lookalike is a phishing system with
extra steps. An address has no lookalikes.

Deployed on Solana mainnet at
[`D1dCoBuiRehhT24XTF8Dmhm9cFERpmfANLB1bb3aGxLJ`](https://solscan.io/account/D1dCoBuiRehhT24XTF8Dmhm9cFERpmfANLB1bb3aGxLJ),
OtterSec-verified.

Use `features = ["no-entrypoint"]` when depending on this from another program or
from a client.

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
