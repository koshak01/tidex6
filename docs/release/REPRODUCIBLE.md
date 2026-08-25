# Reproducible WASM prover

Your privacy in tidex6 depends on the code running in your browser being honest.
The proving code — where your secret is generated and the Groth16 proof is built
— ships as a WebAssembly module. This document lets **anyone** confirm that the
`.wasm` served at `tidex6.com` is byte-for-byte the open source in this
repository, with no hidden backdoor slipped in between.

## Published hashes

Built with `crates/tidex6-prover-wasm/build-reproducible.sh`
(rustc `1.95.0`, wasm-pack `0.15.0`):

| Artifact | sha256 |
|----------|--------|
| `tidex6_prover_wasm_bg.wasm` | `c17c1d5788004aa43015c201d152e84bf28cb4e00702bb341a469495fabdbbd5` |
| `tidex6_prover_wasm.js` (glue) | `f6159dfe978d6045276e0c252a2b4f2d9b188c3c9b55961fcf978869d401e78c` |

Rebuilt on 2026-08-25, four times. First when the identity derivation started
accepting the 65-byte signature an EVM wallet returns; then when the prover
learned to rebuild a Merkle path from a leaf list and to hand a proof to a
Solidity verifier; then to remove a timer that cannot exist in a browser —
`Instant::now()` panics on `wasm32-unknown-unknown`, and one such call sat in
the Poseidon gadget, so every in-browser proof died on its first hash. The
earlier two builds carried it; the later ones do not. The fourth build gives the
prover a second output layout: EVM precompiles reject the byte form Solana
accepts, because arkworks packs serialisation flags into the spare high bits of
a coordinate — and a chain that checks points itself will not tolerate them. The second chain has no indexer to answer "where does my
leaf sit", and putting a server there would mean a person could not collect
their own money while it was down.

**The wasm-pack version moved with it**, from `0.13.1` to `0.15.0`. It is named
here for the same reason rustc is: `wasm-opt` runs as part of the build, and a
different version of it optimises differently. Building this source with the
old wasm-pack will produce a different hash — not a tampered artefact, a
differently optimised one. Reproducing means matching both pins.

These hashes are pinned by the commit that carries this file. When the prover is
rebuilt, this table and `src/verify_hash.rs::REPRODUCIBLE_WASM_SHA256` in
`tidex6-web` are updated together.

## Verify in the browser (no tools)

Open <https://tidex6.com/verify>. The page computes the sha256 of the `.wasm`
your browser actually loaded (locally, via SubtleCrypto — nothing is sent
anywhere) and compares it to:

1. what your browser holds,
2. what the server serves,
3. the published hash above.

All three equal → the WebAssembly in your tab is the published open source.

## Reproduce it yourself

```bash
git clone <tidex6 repo> && cd tidex6
git checkout <commit these hashes were published at>
cd crates/tidex6-prover-wasm
./build-reproducible.sh
# compare the printed sha256 to the table above
```

## What makes the build deterministic

- **Pinned toolchain** — `rust-toolchain.toml` locks rustc `1.95.0` and the
  `wasm32-unknown-unknown` target.
- **Path remapping** — `--remap-path-prefix` strips absolute paths (`$HOME`,
  cwd) from the binary, so the hash does not depend on where the repo lives.
- **`SOURCE_DATE_EPOCH=0`** — zeroed timestamps.
- **`Cargo.lock`** — pinned dependency versions.
- **wasm-pack / wasm-opt** — deterministic at the pinned version.

The glue `.js` is already reproducible across machines; the `.wasm` matches when
built with the pinned toolchain. For belt-and-suspenders assurance, build twice
(or on a second machine) and confirm the hash is identical.
