# Contributing to tidex6

Two very different kinds of contribution are welcome, and one of them needs no
code at all.

## 1. Contribute randomness to the trusted setup ceremony

This is the most useful thing most people can do for the project, and it takes
about a minute in a browser: <https://ceremony.tidex6.com>

Groth16 needs public parameters generated once, up front, and generating them
produces secret randomness — the "toxic waste". Whoever knows it can forge
proofs. A multi-party ceremony makes the setup safe as long as **at least one**
contributor was honest, so every additional contributor strictly strengthens the
guarantee.

Your entropy is generated locally, mixed into the parameters by our prover
compiled to WebAssembly, and discarded — only the new parameters are uploaded.
The full contribution chain is public and independently verifiable; see
[`docs/release/CEREMONY.md`](docs/release/CEREMONY.md) for how to check that your
own contribution is in there.

No wallet funds are involved: the connected wallet only labels the contribution.

## 2. Contribute code

```bash
cargo build
cargo test
cargo clippy -- -D warnings
cargo fmt
```

Onchain programs additionally need `anchor build` / `anchor test`; the browser
prover is built with `wasm-pack` for `wasm32-unknown-unknown`.

Before starting anything substantial, please read
[`docs/release/PROJECT_BRIEF.md`](docs/release/PROJECT_BRIEF.md) and the ADRs in
[`docs/release/adr/`](docs/release/adr/) — the architecture has fixed invariants
(curve, hash, commitment scheme, verifier immutability), and changing one of them
breaks several decisions at once.

### If your change touches proof logic

Circuit definitions, transcript construction, the MPC engine, or any
cryptographic primitive: complete
[`docs/release/PR_CHECKLIST_PROOF_LOGIC.md`](docs/release/PR_CHECKLIST_PROOF_LOGIC.md)
in the pull request. Its first rule is *"anything the prover touches goes into
the transcript"*. Such changes need a second reviewer besides the author — this
is the class of bug that has quietly broken similar systems, and the checklist
exists to catch it.

The MPC engine (`crates/tidex6-circuits/src/mpc.rs`) is marked TRUST-CRITICAL.
Review of that file is especially welcome.

### Reporting a vulnerability

Please do not open a public issue for security problems — see
[`SECURITY.md`](SECURITY.md).

## Licensing

The project is dual-licensed under [MIT](LICENSE-MIT) and
[Apache-2.0](LICENSE-APACHE). Unless you state otherwise, any contribution you
submit for inclusion is licensed under those same terms, as described in the
Apache-2.0 license. **No copyright assignment and no CLA is required.**
