# tidex6 on EVM

Solidity side of the protocol. The proving system does not change here: the
same circuits, the same trusted setup and the same browser prover that back the
Solana programs feed these contracts. BN254 is the curve the EVM verifies
natively in precompiles `0x06`, `0x07` and `0x08`, so a Groth16 proof produced
for Solana is the same proof an EVM contract checks.

First target: **Whitechain Sepolia** (chain id `1874`, OP Stack, Cancun EVM).

## What is here

| Path | What it is |
|---|---|
| `src/Tidex6Verifier.sol` | Groth16 verifier for `WithdrawCircuit<20>`. Generated — never edit by hand. |
| `test/Tidex6Verifier.t.sol` | Proof produced by the Rust prover, asserted to verify on-chain, plus four rejection cases. Generated. |
| `test/fixture.json` | The same proof as data, for other tooling. |
| `foundry.toml` | Build settings and the Whitechain Sepolia endpoints. |

## Regenerating

Both generated files come from the Rust side, so the on-chain verifying key can
never drift from the one the prover uses:

```sh
cargo run --bin export_solidity_verifier --release   # → src/Tidex6Verifier.sol
cargo run --bin export_solidity_fixture  --release   # → test/fixture.json
```

`export_solidity_verifier` reads `~/.tidex6-ceremony/final.state` when it
exists and falls back to the development setup otherwise. The generated header
says which one was used, in a block that is hard to miss.

The verifying key is cross-checked against the Solana verifier
(`programs/tidex6-verifier/src/withdraw_vk.rs`): all seven G1 points and three
G2 points match, with the `[c1, c0]` coordinate order both `groth16-solana` and
the EVM pairing precompile expect.

## Running the tests

Foundry only — no npm, no hardhat:

```sh
forge test -vv
```

Expected: five passing tests. `test_acceptsRealProof` is the one that matters;
the four rejection tests exist because a verifier that accepts everything is
not a verifier.

## Status and the honest caveat

The verifier currently ships with the **development** verifying key, derived
from a seed committed to this public repository. Anyone can forge proofs
against it. It is fine for a testnet deployment that demonstrates the pipeline
and worthless as a security boundary.

The production key comes from the public trusted-setup ceremony
(`ceremony.tidex6.com`), which is not finalized yet. Until it is, no real value
goes behind an EVM deployment — the same rule that keeps every mainnet
operation on Solana capped at 5 tokens today.

## Not a bridge

Each network gets its own pool, its own Merkle tree and its own nullifier set.
Deposit on Whitechain, withdraw on Whitechain. Nothing here proves anything
about another chain's state, and nothing here should ever start to.
