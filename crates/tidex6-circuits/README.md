# tidex6-circuits

Groth16 circuits for [tidex6](https://tidex6.com) — the arithmetic that makes a
private payment provable on Solana.

- **Poseidon gadget** — in-circuit hashing that matches `light-poseidon::new_circom`
  byte for byte, which is what lets an offchain-built proof verify against the
  onchain syscall
- **`WithdrawCircuit<20>`** — membership in a depth-20 Merkle tree, nullifier
  derivation, and Tornado-style binding of recipient, relayer and fee, so that
  rewriting any of them invalidates the proof
- **`DepositCircuit`** — commitment well-formedness
- **`solana_bytes`** — conversion from arkworks proofs to the `groth16-solana`
  byte layout the verifier program expects
- **Ceremony tooling** — `ceremony_finalize` and `ceremony_extract_vk` for a
  multi-party Phase-2 setup (ADR-017)

Curve is BN254, and not by preference: it is the only curve with native Solana
syscall support (`alt_bn128`), at roughly 100-bit security. That trade-off is
documented rather than hidden — see `docs/release/security.md`.

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
