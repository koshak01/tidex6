# Stealth CLI (library demo)

Thin binaries over `tidex6-client::confidential`. Same functions local MCP will call.

Config: `~/.tidex6-local/config.toml` (`keypair_path`, `rpc_*`, `pool_service`, optional `proving_key_path`).

```bash
cargo build --release -p tidex6-wusdc-cli --bin send --bin collect --bin audit

# 1) Send — network, amount, recipient; optional auditor / memo / lifetime
./target/release/send mainnet usdt0_1 <RECIPIENT> --memo "invoice 12"
./target/release/send mainnet usdc0_1 <RECIPIENT> --auditor <AUDITOR> --lifetime 12h

# 2) Collect — network only; USDC+USDT auto; all waiting for config wallet
./target/release/collect mainnet

# 3) Audit — network only; USDC+USDT auto; as auditor for config wallet
./target/release/audit mainnet
```

| bin | library | argv |
|-----|---------|------|
| `send` | `send_payment` | network, amount, to, [--auditor] [--memo] [--lifetime] |
| `collect` | `collect_waiting` | network |
| `audit` | `scan(ReadAs::Auditor)` | network |

Signer is always the config keypair. Collect pays out to that same wallet.
