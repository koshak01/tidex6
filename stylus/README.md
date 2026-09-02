# tidex6 on Arbitrum Stylus

Rust (WASM) contracts for the Arbitrum deployment of tidex6: Arbitrum Sepolia
and Robinhood Chain. They answer to the **same ABI, events and errors** as the
Solidity contracts in `../contracts`, so the browser client, the relayer and
the prover talk to either without knowing which one they hit.

| Crate | What it is | Solidity twin |
|---|---|---|
| `common/` | Field arithmetic (Montgomery, four u64 limbs) and the Poseidon-T3 permutation. Pure, no VM. | `PoseidonT3.sol` |
| `poseidon/` | `hash(uint256,uint256)` as a contract of its own; the pool calls it for every Merkle parent. | `PoseidonT3.sol` |
| `verifier/` | Groth16 verifier for `WithdrawCircuit<20>`; curve work via precompiles `0x06/0x07/0x08`. | `Tidex6Verifier.sol` |
| `pool/` | Shielded pool for one ERC-20: incremental Merkle tree, root ring, nullifiers. Constructor `(token, verifier, poseidon, denomination)`. | `Tidex6Pool.sol` |
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
    --constructor-args <token> <verifier> <poseidon> <denomination>   # pool only
cargo stylus verify --endpoint $RPC --deployment-tx <hash>
```

Networks:

| Network | Chain id | RPC |
|---|---|---|
| Arbitrum Sepolia | 421614 | `https://sepolia-rollup.arbitrum.io/rpc` |
| Robinhood Chain testnet | 46630 | `https://rpc.testnet.chain.robinhood.com` |

## Deployments

### Robinhood Chain testnet (chain id 46630)

Deployed 2 September 2026 from `0xe84041bd169532f5c74666fff6a527257048f3a7`.

| Contract | Address | Notes |
|---|---|---|
| `verifier` | `0x2c94135fb49840a0d6e0985ab1a6c48ee6c140d6` | 9.3 KB compressed |
| `registry` | `0x8eb05cb1b5e46e58c8ca91e3a3738cf534c1e74f` | 12.8 KB compressed |
| `pool` | `0x23831ceec6381d69e2f551c16e71357a1ce95b55` | 35.0 KB, two fragments; constructor `(TSLA, verifier, 1e18)`; deployed at block 111913787 |
| TSLA (Stock Token, testnet) | `0xC9f9c86933092BbbfFF3CCb4b105A4A94bf3Bd4E` | 18 decimals, from the network faucet |

`cargo stylus deploy` creates contracts that have a constructor through the
`StylusDeployer` factory. Robinhood Chain testnet does not ship one at the
canonical address, so a copy was deployed at
`0xC821B4BF26CF181253b60C1116Bb1Fa6D7dCB0D4` from
[OffchainLabs/nitro-contracts](https://github.com/OffchainLabs/nitro-contracts)
tag `v3.2.0` (commit `2695e7b3e3f460531e2b77fed48a60561c54d90e`,
`src/stylus/StylusDeployer.sol`, solc 0.8.17, optimizer 2000 runs, EVM london).
Its runtime bytecode matches the factory on Arbitrum Sepolia
(`0xcEcba2F1DC234f70Dd89F2041029807F8D03A990`) byte for byte apart from the
compiler's CBOR metadata tail. Pass it to later deployments with
`--deployer-address`. The factory is part of the deployment path only; nothing
at run time depends on it.

### Arbitrum Sepolia (chain id 421614)

Deployed 2–3 September 2026 from the same deployer, so `verifier` and
`registry` landed at the same addresses as on Robinhood Chain.

| Contract | Address | Notes |
|---|---|---|
| `verifier` | `0x2c94135fb49840a0d6e0985ab1a6c48ee6c140d6` | 9.3 KB compressed |
| `registry` | `0x8eb05cb1b5e46e58c8ca91e3a3738cf534c1e74f` | 12.8 KB compressed |
| `poseidon` | `0x1c2beb781d478379924232424863df1821682f0a` | 13.0 KB compressed; `hash(0,1)` on chain matches the reference vector |
| `pool` | pending gas | 22.8 KB compressed, one piece; constructor `(USDC, verifier, poseidon, 1e6)` |
| USDC (Circle testnet) | `0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d` | 6 decimals, from `faucet.circle.com` |

The pool on Robinhood Chain above is the earlier 35 KB build (Poseidon inside,
two fragments); it will be replaced by the poseidon + pool pair once the first
round of checks on it is done.

## Why the hash is a separate contract

A Stylus contract must fit 24 KB after Brotli. The Poseidon round constants
are 195 random field elements — six kilobytes that do not compress — and with
them inside, the pool came out at 35 KB: deployable only as fragments through
the `StylusDeployer` factory, which on Arbitrum Sepolia costs ~11M gas and
fails whenever the base fee moves between estimate and send. Moving the hash
into its own contract keeps every piece under the limit and every deploy a
single ordinary transaction. The pool pays one static call per Merkle parent
(twenty per deposit) for that.

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
