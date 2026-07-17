# ADR-015 — Confidential amounts: two independent layers (CT-wrapped asset + amount-in-circuit pool)

**Status:** Proposed — 2026-07-04
**Depends on:** ADR-001 (commitment scheme), ADR-005 (verifier immutability),
ADR-009 (proving-time budget), ADR-014 (ML-KEM memo account)
**Related roadmap:** D1–D4, E1–E4, F1–F10, N1–N7
**Prototype:** `tidex6-phase2` (`transfer_circuit`, `withdraw_circuit` with
amounts; conservation + range; ~17–30 ms proof) — built during the hackathon
freeze, proves the circuit side is feasible.
**Mainnet spikes (2026-07-04):** confidential transfer verified live
(tx `3bzWixWp…`); confidential mint-burn wrap cycle verified live
(mint `AupUFasK…`, mint tx `4KdKEBH6…`, burn tx `5xSfWGFG…`).

## Context

Today tidex6 hides **who ↔ whom** but not **how much**. Deposits and
withdrawals move native SOL in fixed denominations (ADR-008 pool
isolation, uniform-note anonymity). The amount is public.

The user's goal: hide the amount as well, and do it for **USDC first**
(a stablecoin most of the target audience actually holds and can cash out
P2P), without a custodial backdoor — disclosure stays a user choice
(ADR-007, ADR-014 auditor slots).

Two facts frame the decision:

1. **Solana re-enabled the ZK ElGamal Proof program on mainnet**
   (feature `zkexuyPRdy…`, active since epoch 982 / 2026-06-04). Token-2022
   Confidential Transfers work again. Verified live on 2026-07-04 — the
   first full confidential transfer on mainnet since the June-2025
   shutdown was ours. This is an open first-mover window.
2. **If an amount is hidden from an observer, it is also hidden from our
   own pool program.** Something must prove the amount to the program
   without revealing it. That is the whole design question.

Naming: throughout this ADR **wUSDC** is a Token-2022 mint with the
`ConfidentialTransferMint` + `ConfidentialMintBurn` extensions, backed
1:1 by real USDC held in a vault. It is *our* wrapper, not Circle's USDC
(an existing mint cannot retro-fit extensions — they are fixed at mint
creation).

## Decision

Hide the amount with **two independent layers**, each hiding a different
fact, neither depending on the other:

| Layer | Hides | Mechanism | Ceremony? |
|---|---|---|---|
| **Amount** | *how much* | Token-2022 CT on the **wUSDC** mint (twisted-ElGamal, verified by the native `ZkE1Gama1Proof` program) | No — native Solana |
| **Link** | *who ↔ whom* | our Groth16/BN254 pool, now with the **amount inside the commitment** | Yes — new circuit → new verifier → new setup |

### Layer 1 — CT-wrapped asset (wUSDC)

A Token-2022 mint carrying `ConfidentialTransferMint` (with an optional
`auditor_elgamal_pubkey`) and `ConfidentialMintBurn`, authority held by a
**PDA of the wrap program**:

- **wrap:** user deposits real USDC into the program vault → the PDA
  confidentially mints wUSDC 1:1 into the user's confidential balance.
- **unwrap:** user confidentially burns wUSDC → the PDA releases USDC
  from the vault.
- Confidential transfers, balances, and supply are all opaque on chain;
  amounts are visible **only** to the holder, and — if configured — to a
  native **auditor** ElGamal key (our regulated-pool / H10 case, for free).

The heavy proofs (equality + ciphertext-validity + range) are verified by
the native `ZkE1Gama1Proof` program in **context-state accounts**; our
program never verifies CT proofs — it only does the vault-USDC transfer
and the mint/burn CPI. Confirmed by the mainnet spike.

### Layer 2 — amount inside the pool circuit

The pool commitment gains an amount field:

```
commitment = Poseidon(secret, nullifier, amount)          # was Poseidon(secret, nullifier)
```

The withdraw circuit additionally proves, in zero knowledge:

- **range:** `0 ≤ amount < 2^64` (no negative / overflow amounts);
- **conservation:** `Σ inputs == Σ outputs` (you cannot turn 100 into 1000);
- everything else as today (Merkle membership, nullifier, recipient
  binding).

Because the amount is proven, not shown, the program accepts a deposit /
withdrawal of any value without ever learning it — and **fixed
denominations are no longer needed**. Arbitrary amounts with change, one
note per payment. The phase2 prototype already runs this at ~17–30 ms,
well inside the ADR-009 30 s budget.

### Why both layers, and why they are orthogonal

- **wUSDC alone** hides amounts of ordinary transfers, but the pool would
  still need fixed denominations to keep the link private — and the entry
  `USDC → wUSDC` reveals the wrapped amount anyway.
- **amount-in-circuit alone** hides pool amounts, but outside the pool the
  asset is a plain visible-balance token.
- **Together:** the amount is hidden both inside the pool (circuit) and
  outside it (CT), and the pool no longer needs denominations. One
  Groth16 system hides *both* link and pool-amount — the "one algorithm
  for everything" the roadmap calls for. CT supplies the confidential
  asset and the native auditor around it.

### What stays visible (stated honestly)

The **`USDC → wUSDC` wrap is always visible** — USDC is a public token, so
the vault balance grows by a visible amount when a user wraps. Everything
*inside* the wUSDC world is hidden: transfers, balances, supply, and — via
layer 2 — amounts inside the pool. Privacy of the amount therefore
requires value to **live in wUSDC** and be cashed out in a liquid,
crowded venue, not round-tripped solo USDC → wUSDC → USDC. This mirrors
the CT deposit/withdraw visibility boundary and is documented for users
in `security.md`.

### Ceremony coupling — one cycle, paid once

Changing the commitment changes `WithdrawCircuit`, which changes the VK,
which needs a **new trusted setup** and a **new verifier program**. Per
ADR-005 the current verifier `CSDD31Zm…` is immutable and is **not
touched**. The amount-in-circuit change is therefore batched into the
single new-verifier cycle together with the other circuit-level changes
already queued (GAP-1 dev-VK fix via real multi-party ceremony, GAP-2
recipient/relayer binding fix, on-chain auditor, 30-day revoke). The
public ceremony (`ceremony.tidex6.com`, ADR-017) freezes this
final circuit and runs once. "Pay the migration once."

## Consequences

**Positive**

- Amount hidden on both axes; sender, recipient, and amount all private.
- Denominations eliminated — arbitrary amounts with change.
- Native CT auditor gives regulated-pool disclosure with zero extra code.
- First-mover: CT re-enabled ~1 month ago, no product has shipped on it.
- Reuses proven pieces: phase2 circuit prototype, our Groth16→solana byte
  path, ML-KEM auditor/recipient slots (ADR-014).

**Negative / risks**

- Two ZK systems coexist: BN254/Groth16 (ours) and curve25519/ElGamal
  (Solana CT). More surface, more CU. CT proofs already need multiple
  context-state transactions — CU/tx budgeting is a real design task.
- A new circuit ⇒ new verifier ⇒ mandatory new ceremony and re-audit.
  Higher-stakes than an off-chain change.
- CT went dark for a year over a Fiat-Shamir soundness bug — exactly the
  class `PR_CHECKLIST_PROOF_LOGIC` guards. The amount-in-circuit work
  triggers the two-reviewer transcript discipline.
- wUSDC carries USDC freeze-authority risk at the vault (ADR E4);
  documented, not hidden.
- The phase2 `tidex6-confidential-amounts` Pedersen sandbox and the
  mainnet toy `6r8Jfo…` are **reference-only** and superseded by this
  decision; the toy has trust-based withdraw and must be marked
  deprecated.

## Open questions

1. Does `amount` enter the commitment directly (`Poseidon(secret,
   nullifier, amount)`) or via a separate value-commitment bound into the
   circuit? Prototype uses the direct form.
2. wUSDC ⇄ pool coupling: does the pool hold wUSDC (a confidential token
   account under a pool PDA) or unwrapped USDC? Trade-off: double-hidden
   vs. simpler vault.
3. CU/transaction partitioning for the combined browser flow (CT proof
   context-state txns + Groth16 withdraw) — measure before freezing.
4. Ceremony scope freeze: exact final `WithdrawCircuit` (amount + revoke +
   on-chain auditor + binding fix) before contributions open — one circuit
   for all use-cases (ADR-017).
