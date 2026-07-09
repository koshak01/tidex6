# Reproducible WASM prover

Your privacy in tidex6 depends on the code running in your browser being honest.
The proving code — where your secret is generated and the Groth16 proof is built
— ships as a WebAssembly module. This document lets **anyone** confirm that the
`.wasm` served at `tidex6.com` is byte-for-byte the open source in this
repository, with no hidden backdoor slipped in between.

## Published hashes

Built with `crates/tidex6-prover-wasm/build-reproducible.sh`
(rustc `1.95.0`, wasm-pack `0.13.1`):

| Artifact | sha256 |
|----------|--------|
| `tidex6_prover_wasm_bg.wasm` | `e4b82e5045caa0cc735fe80c92981511253ff34544f1090ad4d14c76133f0b67` |
| `tidex6_prover_wasm.js` (glue) | `c01b19f6498d8d00b6435b4b7bd5e7b58560641b608b1401e67dcf408937313e` |

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
