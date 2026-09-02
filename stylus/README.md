# tidex6 on Arbitrum Stylus

Rust (WASM) contracts for the Arbitrum deployment of tidex6: Arbitrum Sepolia
and Robinhood Chain. They answer to the **same ABI, events and errors** as the
Solidity contracts in `../contracts`, so the browser client, the relayer and
the prover talk to either without knowing which one they hit.

| Crate | What it is | Solidity twin |
|---|---|---|
| `common/` | Field moduli and Poseidon-T3 over `U256`. Pure arithmetic, no VM. | `PoseidonT3.sol` |
| `verifier/` | Groth16 verifier for `WithdrawCircuit<20>`; curve work via precompiles `0x06/0x07/0x08`. | `Tidex6Verifier.sol` |
| `pool/` | Shielded pool for one ERC-20: incremental Merkle tree, root ring, nullifiers. | `Tidex6Pool.sol` |
| `registry/` | Reader registry: a wallet publishes the key payments are sealed to. | `Tidex6Registry.sol` |

## Generated files

Two files are generated from the Rust side so the on-chain constants can never
drift from what the prover uses:

```sh
cargo run --bin export_solidity_verifier --release   # → verifier/src/vk.rs (+ contracts/src/Tidex6Verifier.sol)
cargo run --bin export_solidity_poseidon --release   # → common/src/poseidon_consts.rs (+ contracts/src/PoseidonT3.sol)
```

One verifying key, one Poseidon parameter set, three verifiers (Solana,
Solidity, Stylus).

## Building

This is its own Cargo workspace (excluded from the repository root), pinned to
the toolchain in `rust-toolchain.toml`.

```sh
cargo install --force cargo-stylus
cd stylus
cargo stylus check  --endpoint $RPC             # compiles, checks the 24 KB limit
cargo stylus deploy --endpoint $RPC --private-key-path $KEY \
    --constructor-args <token> <verifier> <denomination>   # pool only
cargo stylus verify --endpoint $RPC --deployment-tx <hash>
```

Networks:

| Network | Chain id | RPC |
|---|---|---|
| Arbitrum Sepolia | 421614 | `https://sepolia-rollup.arbitrum.io/rpc` |
| Robinhood Chain testnet | 46630 | `https://rpc.testnet.chain.robinhood.com` |

## Status and the honest caveat

The verifier ships with the **development** verifying key — derived from a seed
in this repository, forgeable by anyone. Fine for a testnet deployment that
demonstrates the pipeline, worthless as a security boundary. The production key
comes from the public ceremony (`ceremony.tidex6.com`), not finalized yet.
Until it is, no real value goes behind these contracts.

## Not a bridge

Each network gets its own pool, its own tree and its own nullifier set.
Deposit on a chain, withdraw on that chain. Nothing here proves anything about
another chain's state, and nothing here should ever start to.
