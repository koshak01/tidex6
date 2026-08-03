# tidex6 on Aleo / Leo (spike)

Privacy contour of **tidex6** expressed in **Leo** for the [Aleo Developer Grants](https://aleo.org/grants) track.

| Path | Role |
|------|------|
| `tidex6_private_transfer/` | Leo program: private mint + transfer + split |
| `../docs/aleo/` | Grant research, spike plan, security checklist |

## Toolchain

```bash
# binary (example v4.4.0 macOS)
export PATH="$HOME/.local/bin:$PATH"
leo --version   # leo 4.4.0
```

## Build / test

```bash
cd tidex6_private_transfer
leo build
leo test
```

## Concept map (tidex6 → Leo)

| tidex6 (Solana) | Leo / Aleo |
|-----------------|------------|
| Deposit note | `record Token { owner, amount }` |
| Spend / nullifier | Record consumed as `private token: Token` input (once) |
| Hidden amount | `amount: u64` private on record |
| Hidden link | Private `owner`; no public who↔whom |
| Double-spend | Protocol rejects second spend of same record |
| Auditor slot | **Not in MVP** — next milestone |
| Token-2022 CT | **N/A** — native private records instead |
| ML-KEM memo | **Not in MVP** |

## Security (wrong vs right)

See `docs/aleo/ALEO_LEO_SECURITY_CHECKLIST_AID.md`.

## Status

- [x] Leo 4.4 installed  
- [x] Program compiles (`leo build`)  
- [ ] `leo test` green  
- [ ] Grant form after operator OK  

**Not** a full tidex6 port. Grant MVP only.
