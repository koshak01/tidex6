# tidex6-mcp-local

An MCP server that lets an AI agent make **private stablecoin payments on
Solana** — USDC and USDT, with the amount hidden on chain and the link between
sender and recipient broken by a zero-knowledge proof.

The signing key stays on your machine. The agent asks; you decide.

- MCP Registry name: `mcp-name: io.github.koshak01/tidex6-mcp-local`
- Protocol: [tidex6](https://tidex6.com) · [source](https://github.com/koshak01/tidex6)

## Install

```bash
cargo install tidex6-mcp-local
```

Then point your MCP client at the binary. For Claude Desktop / Claude Code,
add to the MCP servers config:

```json
{
  "mcpServers": {
    "tidex6": {
      "command": "tidex6-mcp-local",
      "args": []
    }
  }
}
```

## Configure

Create `~/.tidex6-local/config.toml`:

```toml
keypair_path = "/path/to/solana/id.json"   # the wallet that pays
rpc_mainnet  = "https://your-rpc-endpoint"
rpc_devnet   = "https://your-devnet-endpoint"
pool_service = "https://tidex6.com"

per_payment  = 5.0     # spending limits, enforced before anything moves
per_day      = 25.0
```

Start on `devnet` until you have read [the security notes](#custody-and-limits).

## Tools

| Tool | What it does |
|---|---|
| `about` | version, custody mode, ceremony link |
| `whoami` | which wallet is paying, and the limits in force |
| `send` | make a private payment — **moves money** |
| `payments` | payments addressed to you, and whether they were collected |
| `collect` | withdraw the ones still waiting — **moves money** |
| `audit` | what senders disclosed to you as auditor: date, amount, memo |
| `ceremony` | trusted-setup status and a link to contribute |

A payment takes 15–30 seconds: the proof is built locally.

## Custody and limits

**This is T2 custody: the spending key is on this machine**, and `send`
signs and broadcasts by itself — it does not hand you a link to approve. That
is the point of running it locally, and it is also the risk.

Three things stand between an agent and your funds:

1. **Spending limits in the config** (`per_payment`, `per_day`), checked before
   anything moves.
2. **Fixed denominations.** The schema accepts `usdc1`, `usdt10` and so on — an
   injected instruction cannot express "send everything".
3. **Your MCP client's approval gate.** Keep `send` and `collect` *out* of any
   auto-approve list. Read-only tools are safe to allow.

If you want the agent to hold nothing at all, use the hosted server at
`mcp.tidex6.com` instead: it prepares a link, and you sign in your own wallet.

## Fees

1% of the payment with a 0.1 floor, paid by the sender on top of the amount —
the recipient gets exactly what was sent. The floor is the real cost of a
private payment (account rent for the encrypted memo plus transaction fees),
and it does not scale with the amount. That makes the `0.1` denominations a
devnet tool: on mainnet they cost 0.1 to move 0.1.

## Status

Live on Solana mainnet. The verifier program is immutable and
[OtterSec-verified](https://verify.osec.io/status/CSDD31Zmm3pRMHAMB8c3TBqsj9mbmH2rXBzV7jrsJhcd).

**The trusted setup is not finished yet.** Until the public ceremony completes,
the verifying key is a development key, which means proofs are forgeable by
whoever holds the setup secret. Amounts are capped accordingly. If you want
this fixed sooner, [contribute a minute of randomness](https://ceremony.tidex6.com/)
— it costs nothing and signs no transaction.

## License

MIT OR Apache-2.0
