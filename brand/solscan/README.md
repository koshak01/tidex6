# Solscan / explorer logo submission kit

Square PNG variants of the tidex6 brand mark, generated from
`brand/logo/hat-solana.svg` (gradient) and `brand/logo/hat.svg`
(mono purple). Centered with transparent letterboxing — explorers
that letterbox themselves stay clean, explorers that don't get a
square brand mark out of the box.

| File | Use |
|---|---|
| `tidex6-256.png` | smallest required size (Solscan, list views) |
| `tidex6-512.png` | most requested size (Solscan profile, label submissions) |
| `tidex6-1024.png` | high-DPI / OG-image / apple-touch-icon |

## Submitting to Solscan

1. Visit https://solscan.io and look for the **Suggest** /
   **Contact** link (bottom of the page) — or go to the program
   page at
   https://solscan.io/account/2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C
   and click the small **edit / pencil** icon next to the placeholder
   account name.

2. Fill in:

   - **Account address:** `2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C`
   - **Account type:** Program
   - **Display name:** `tidex6`
   - **Description:**
     ```
     tidex6 — the Rust-native privacy framework for Solana.
     Shielded pool with Groth16 zero-knowledge proofs verified on
     chain via alt_bn128 syscalls. Selective disclosure via
     viewing keys. OtterSec verified.
     I grant access, not permission.
     ```
   - **Website:** https://tidex6.com
   - **Repository:** https://github.com/koshak01/tidex6
   - **Logo:** upload `tidex6-512.png`

3. **Proof of ownership:** Solscan will ask you to sign a challenge
   string with the program's `upgrade-authority` keypair
   (`Cs9F9sdycNUfYDLg7WGsYwbxRMubo2b4u8V4Mdv8Y8n6`). Run:

   ```bash
   solana sign-offchain-message <their-challenge> \
     --keypair ~/.config/solana/id.json
   ```

   Paste the resulting signature into the form.

4. Submit. Approval typically takes **1–3 weeks** through manual
   review.

## Submitting to Solana Explorer (explorer.solana.com)

Solana Explorer doesn't have a labels portal of its own; it pulls
from a Solana Foundation registry. The cleanest path is to open a
PR against
[`solana-labs/token-list`](https://github.com/solana-labs/token-list)
or its successor — though for *programs* (non-token), the
recommended path is to wait for the OtterSec verified record to
propagate (already published since 2026-04-25), and to submit a
ticket via https://solana.com/contact requesting a metadata
listing.

## Submitting to Helius

Helius has a programs registry for their explorer / dashboard. Reach
out via https://dashboard.helius.dev → support, attach the same logo
+ description block above.

## Submitting `tidex6-tip-jar` (Solscan Labeling Form)

The tip-jar reference CPI program is a separate label submission
on the same form (https://forms.blockscan.com/form/mW5b8Nd5gBPwtAvdO8hi8nkt5PUyjg3Hl3RXNRpnHRY).

Fields to fill:

- **Address / Program ID:** `5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x`
- **Type:** Program
- **Label / Display name:** `tidex6 — tip-jar (CPI integration example)`
- **Website:** https://tidex6.com
- **Repository:** https://github.com/koshak01/tidex6 (sub-path: `programs/tidex6-tip-jar`)
- **Description:**
  ```
  Reference Cross-Program Invocation (CPI) integration example for
  the tidex6 privacy framework. A third-party Anchor program that
  forwards SOL into tidex6_verifier::deposit (program
  2qEmhLEnTDu2RiabWT7XaQj5ksmbzDDs6Z7Mr2nBcU9C) in 30 lines of Rust,
  demonstrating how any Solana protocol — DAO payroll, NFT royalty
  splitter, subscription protocol, dark-pool DEX hook — can adopt
  shielded transfers as a primitive. Open-source.
  ```
- **Logo:** the same SVG used for the verifier:
  https://tidex6.com/static/images/hat-solana.svg

**Proof of Labeling:**

```
1. Source code (Anchor program declares this exact program ID):
   https://github.com/koshak01/tidex6/blob/master/programs/tidex6-tip-jar/src/lib.rs

2. Deploy transaction:
   https://solscan.io/tx/2JR7CADCrj5BWgJKoGU2rCkcRy3vjqBoCLKGnUoJEhGtPjy28ooeShDVwi2sCwt4waaeJnnC2myBT5wzwwAnHmBg

3. Same upgrade authority as the verified main verifier program
   (Cs9F9sdycNUfYDLg7WGsYwbxRMubo2b4u8V4Mdv8Y8n6) — the canonical
   tidex6 project key.

4. Project website lists this program ID:
   https://tidex6.com/roadmap (search "5WohQRRzC31SkFMSWgEqJC9p2KvNhGkQbzUSsNUi9b9x")

If signed-message proof of ownership is required, the upgrade
authority can sign any challenge string via:

  solana sign-offchain-message <challenge> \
    --keypair ~/.config/solana/id.json
```

## Programs Registry standard (future)

Solana is rolling out an on-chain program metadata standard
(`Metadata1111111111111111111111111111111111111` PDA derived from
the program ID) where the logo URL, description, and website live
in a structured account. Once that lands and explorers index it,
the manual submission flow disappears.

For tidex6 v0.2 we'll wire this up once the spec stabilises — until
then, the manual submission to Solscan above is the most visible
fix.
