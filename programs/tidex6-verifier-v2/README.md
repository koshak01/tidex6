# tidex6-verifier-v2

The tidex6 Groth16 verifier program, as a library — for building instructions and
CPI calls against
[`CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd`](https://solscan.io/account/CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd)
without depending on a local build.

Deployed on Solana mainnet, **immutable** — upgrade authority renounced — and
OtterSec-verified. Verification runs through the `alt_bn128` syscalls; double
spends are prevented by one PDA per nullifier; the recipient is bound into the
proof so a front-runner cannot redirect a withdrawal.

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
