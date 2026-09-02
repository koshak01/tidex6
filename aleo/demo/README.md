# tidex6 → Aleo private transfer demo (English)

Minimal micro-demo for the **Aleo Developer Grants** track.

## What it shows

1. **Private token** — amount is private on a Leo `Token` record.  
2. **Transfer** — full or split (see program).  
3. **Auditor slip** — `issue_audit_slip` gives an `AuditSlip` to an auditor **without** giving them spend rights on the `Token`.

## Requirements

- Leo **4.4+** on `PATH` (`leo --version`)
- macOS/Linux shell

```bash
# Install example (macOS x86_64 binary from ProvableHQ releases)
# export PATH="$HOME/.local/bin:$PATH"
```

## Run

```bash
cd aleo/demo
./run_demo.sh
```

Or manually:

```bash
cd aleo/tidex6_private_transfer
leo build
leo run mint_private aleo1639nwum2mt0n0ukqwd4pay90u7uy2msmuvcc2htsc6djg94hdsrqzdjzdu 10u64
```

## Concept map (tidex6 Solana → Leo)

| tidex6 (Solana) | This demo (Leo / Aleo) |
|-----------------|-------------------------|
| Deposit note | `record Token` |
| Spend / nullifier | Consuming a `Token` as function input (once) |
| Hidden amount | `amount` private on the record |
| Hidden link | Private `owner` |
| Auditor slot | `record AuditSlip` + `issue_audit_slip` |
| Token-2022 CT | Not used — privacy is native to records |
| ML-KEM memo | Out of scope for Stage A |

## Security notes


Honest limits of this MVP:

- `mint_private` is unrestricted (demo only).  
- `AuditSlip` is a separate record type (auditor cannot spend `Token` via the slip).  
- Full client “view key” UX is a later milestone.

## Grant

Do **not** submit the grant form until this demo builds and runs on your machine.  
