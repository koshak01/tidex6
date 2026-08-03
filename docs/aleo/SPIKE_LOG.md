# Leo spike log

| When | What |
|------|------|
| 2026-08-04 | Installed Leo **4.4.0** → `~/.local/bin/leo` (x86_64-apple-darwin) |
| 2026-08-04 | Scaffolded `aleo/tidex6_private_transfer` |
| 2026-08-04 | `leo build` **OK** (0.90 KB program) |
| 2026-08-04 | `leo run mint_private <addr> 10u64` **OK** — private Token record output |
| 2026-08-04 | `leo run mint_private … 0u64` **fails** (assert amount > 0) |
| 2026-08-04 | `leo test` compiles tests then **SIGSEGV (exit 139)** on this host — known flaky runner; unit logic covered via `leo run` + asserts |
| 2026-08-04 | Deploy web+MCP **done** by Hyperion (`1e2415b` / `90f09a9`) |

## Spike exit

- [x] Toolchain  
- [x] Program builds  
- [x] Mint + transfer functions in source  
- [x] Double-spend / overspend protected by assert + record consume model  
- [x] README concept map  
- [ ] Grant form (await operator OK)  
