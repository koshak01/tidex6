# UI-copy canon (task 902)

**Source:** forge design-system §5 (`forge/docs/design_system/00_overview.md`)  
**Rule:** смысл экрана, не инструкция «как нажать».

## Test

Убрать hint — оператор всё равно поймёт экран? Да → hint лишний.

## Applied 2026-08-04

| Surface | Before (tutorial) | After (meaning) |
|---------|-------------------|-----------------|
| Ceremony lead | `Connect wallet → mix … → done` | Entropy mixed & destroyed in-tab; only params leave; $0 · ~1 min |

## Still OK (meaning / constraints)

- Wallet age rule (30 days) — data constraint  
- 1-of-N crypto explanation — meaning  
- Distinct wallets vs contributions — security semantics  

## Ongoing

Any new UI in tidex6-web / MCP strings / agent cards: no “click X then Y” when X is already on screen.
