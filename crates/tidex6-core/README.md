# tidex6-core

Core primitives for [tidex6](https://tidex6.com), a Rust privacy framework for
Solana: **I grant access, not permission.**

This crate holds the parts every other one builds on, and nothing else:

- **Commitment / Nullifier / NullifierHash** — newtypes over field elements, with
  rejection sampling so a value out of the BN254 field cannot exist at all
- **Merkle tree** — append-only, Tornado-style filled/zero subtrees, depth 20
- **Poseidon** — a wrapper over `light-poseidon` with circom parameters, chosen so
  that offchain hashing is byte-for-byte identical to the Solana syscall
- **Keys** — spending key and viewing key, derived by Poseidon; the separation
  between "can spend" and "can read" lives here
- **ML-KEM-768 envelopes** — post-quantum sealed payloads with an X25519 view tag,
  so a recipient scanning the chain discards ~255 of every 256 envelopes with one
  scalar multiplication before any ML-KEM work
- **DepositNote** — the note format, with a `Debug` that prints `<redacted>`
  rather than spend material

No network, no wallet, no async. If you want to *make* a payment rather than
compute over one, use [`tidex6-client`](https://crates.io/crates/tidex6-client).

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
