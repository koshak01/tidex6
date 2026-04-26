# tidex6-prover-wasm

Browser-side Groth16 proving for the tidex6 withdraw circuit. The
user's `(secret, nullifier)` pair never leaves their machine — the
proof is generated locally in WebAssembly and the relayer only ever
sees the public proof bytes.

> **Why this matters:** without WASM proving, the browser would have
> to ship `secret` and `nullifier` to a backend prover. That single
> hop is enough to break the threat model — anyone who logs the
> request body can later link a withdraw back to the depositor.
> Doing it in WASM keeps the secret on the user's machine end-to-end.

## Wire format

`proveWithdraw(...)` returns a 256-byte `Uint8Array`:

```
proof_a (64) || proof_b (128) || proof_c (64)
```

Already in the byte layout the on-chain `groth16-solana` verifier
expects — splice into the relayer's `POST /withdraw` body as
`proof_{a,b,c}_hex` after `Buffer.from(out).toString("hex")`-style
encoding. The five public inputs (`merkle_root`, `nullifier_hash`,
`recipient`, `relayer_address`, `relayer_fee`) are computed by the
caller (already known before proving — they come from the indexer's
Merkle path build and the user's chosen recipient/relayer) and not
re-derived here. Keeping them out of the WASM bundle saves
~250 KB and avoids duplicating the Poseidon parameters in two
places.

## Build

```bash
cd crates/tidex6-prover-wasm
wasm-pack build --release --target web --out-dir pkg
```

Output:
- `pkg/tidex6_prover_wasm_bg.wasm` — ~1.8 MB after wasm-opt
- `pkg/tidex6_prover_wasm.js` — wasm-bindgen ESM glue
- `pkg/tidex6_prover_wasm.d.ts` — TypeScript types
- `pkg/package.json` — npm-publishable manifest

The crate is **excluded from the workspace** (`Cargo.toml` root
`[workspace.exclude]`) because it targets `wasm32-unknown-unknown`
and pulls in browser-only crates (`getrandom/js` + `wasm_js`,
`wasm-bindgen`). Building it inside the workspace would force every
host build to compile WASM-only deps and fail.

## Usage from the browser

```js
import init, { initPanicHook, proveWithdraw } from "./pkg/tidex6_prover_wasm.js";

await init();
initPanicHook();

// Fetched once and cached — same artifact as
// crates/tidex6-circuits/artifacts/withdraw_pk_depth20.bin
const provingKey = new Uint8Array(
  await (await fetch("/static/withdraw_pk_depth20.bin")).arrayBuffer()
);

const proofBytes = proveWithdraw(
  secret,                  // Uint8Array(32)
  nullifier,               // Uint8Array(32)
  pathSiblingsConcat,      // Uint8Array(20 * 32 = 640)
  pathIndicesPacked,       // Uint8Array(20)  — each byte 0 or 1
  merkleRoot,              // Uint8Array(32)
  nullifierHash,           // Uint8Array(32)  — Poseidon(secret, nullifier) reduced to BN254
  recipient,               // Uint8Array(32)  — 32-byte pubkey, mod-reduced
  relayerAddress,          // Uint8Array(32)  — same
  relayerFee,              // Uint8Array(32)  — big-endian u64 padded to 32
  provingKey,              // Uint8Array(2.1 MB)
);

const proofA = proofBytes.slice(0, 64);
const proofB = proofBytes.slice(64, 192);
const proofC = proofBytes.slice(192, 256);
```

## Performance

On a 2024 MacBook M-series, `proveWithdraw` (WASM, including PK
deserialisation) runs in **~3.1 s per proof** — comfortably inside
the ADR-009 30 s budget. End-to-end correctness of the same proof
under the on-chain `groth16-solana` verifier is exercised by
`crates/tidex6-circuits/tests/withdraw_end_to_end.rs`.

A persistent prover that keeps the deserialised `ProvingKey` in
WASM memory between calls is a v0.2 optimisation; the MVP demo runs
one proof per session, so the per-call PK deserialisation cost is
acceptable.
