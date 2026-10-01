# ADR-023 — Confidential token on Baby Jubjub: the amount disappears at the pool's border too

**Status:** Accepted in direction (01.10.2026, Petr). Details below are decided
unless listed under *Open questions*.
**Date:** 2026-10-01
**Builds on:** ADR-015 (two layers for confidential amounts), ADR-022 (note
format v2). **Design study:** `docs/evm/HIDDEN_AMOUNTS_DESIGN_SPACE.md` §5–7.

## Context

Note format v2 hides who pays whom and every amount *inside* the pool. Two
numbers are still public on EVM chains: the amount a payer deposits (an ERC-20
transfer into the pool) and the amount a recipient withdraws (an ERC-20
transfer out). On Solana these borders are already hidden, because Token-2022
keeps balances encrypted. EVM has no such token, so the borders leak.

Confidential tokens are now arriving on EVM chains (Fairblock CUSD on Arbitrum,
30.09.2026, homomorphic balances for one stablecoin). What none of them gives is
the combination we already have half of: hidden amounts *and* a hidden
payer–recipient link, for any token, with disclosure to an auditor the payer
chooses.

## Decision

Build a confidential wrapper token for any ERC-20 (`cUSDC`, `cUSDG`, `cTSLA`…)
whose balances are twisted ElGamal ciphertexts on **Baby Jubjub**, and connect
it to the v2 pool so value can move token → pool → token without a number
appearing anywhere.

### 1. Curve and cipher

- **Baby Jubjub** (EIP-2494), the twisted Edwards curve defined over BN254's
  scalar field. Point arithmetic inside our Groth16 circuits is native: units
  and thousands of constraints, not hundreds of thousands as with BN254 G1.
- **Twisted ElGamal** (PGC; the construction Token-2022 uses): a ciphertext is
  a Pedersen commitment `C = m·G + r·H` plus handles `D_i = r·PK_i`, one per
  reader (owner, auditor). Equality of what each reader sees holds by
  construction.
- Keys are derived from the wallet signature, like the reader key today. The
  ElGamal key is a separate key, never the wallet key.

### 2. Reading amounts: the envelope, not a discrete log

The opening `(m, r)` travels in the existing ML-KEM envelope to the recipient
and to the named auditor. They check `C == m·G + r·H` locally. No
baby-step/giant-step table, no 48-bit ceiling: amounts are full 64-bit. The
ElGamal handle is the fallback if an envelope is lost. A symmetric
`decryptable_balance`, as on Solana, lets an owner read their own balance
instantly.

### 3. Token contract (Solidity and Stylus, one ABI)

| call | what the chain sees |
|---|---|
| `wrap(amount)` | address A wrapped N (the one public entry) |
| `transfer(proof, …)` | two ciphertexts changed; no amount |
| `applyPending()` | owner folds incoming ciphertexts into available |
| `unwrap(proof, amount)` | address D unwrapped N (the one public exit) |
| `depositToPool(proof, …)` | sender's ciphertext changed, a v2 leaf appended; no amount, no recipient |

Balances are `available` and `pending` ciphertexts. Incoming transfers land in
`pending`, so a transfer someone sends you cannot invalidate a proof you are
building against `available`. The contract only **adds** ciphertexts and never
multiplies points by scalars: on Solidity that is a few `mulmod`s, on Stylus
plain u64-limb arithmetic like our Poseidon.

### 3a. Custody: the token holds the ERC-20 for the pool too

A pool that accepts value from an encrypted balance cannot receive an ERC-20
transfer for it: the transfer would print the amount. So the pool for a
confidential token (`Tidex6TokenPoolV2`) holds **no** ERC-20. Every unit of
the underlying sits in the token contract and backs both the encrypted
balances and the pool's notes. Crossing between them moves no tokens:

- `depositToPool` (token) verifies `DepositFromToken`, debits the ciphertext of
  payment plus fee, checks that the proof used the pool's treasury key and fee
  floor, and calls the pool's `depositFromToken`, which files the two leaves.
- `withdrawToToken` (pool) verifies `WithdrawToToken`, spends the nullifier and
  calls the token's `creditPending`.
- A public `withdraw` (pool, `withdraw_v2` proof) is paid by the token's
  `payOut` from the same custody.

Plain v2 pools (open deposits, refunds) stay as they are; a token pool is a
separate deployment per confidential token. Notes there have no refund: the
refund path rebuilds the leaf from a public amount, and these notes never had
one.

### 4. Circuits (Groth16, BN254, browser prover)

1. `TokenTransfer`: knowledge of the sender's key; new available = old − m;
   recipient and auditor handles encrypt the same m; m and the remainder are in
   `[0, 2⁶⁴)` by bit decomposition.
2. `DepositFromToken`: a ciphertext debit of m equals the amount committed in a
   v2 leaf `H(H(core, m), refund)`. The pool files the leaf as today. The fee
   note is proved inside the same circuit (1 %, floor 0.1).
3. `WithdrawToToken`: a v2 note spent by its owner key (the ADR-022 withdraw
   statement), paid out as a ciphertext to the recipient's ElGamal key instead
   of an ERC-20 transfer.

Plain `withdraw_v2` and `transfer_v2` stay as they are.

### 4a. Curve form

`ark-ed-on-bn254` writes Baby Jubjub as `x² + y² = 1 + d'·x²y²` with
`d' = 168696/168700`, the isomorphic image of the EIP-2494 form
(`a = 168700, d = 168696`, map `x' = √a·x`). Checked on 01.10.2026: the
arkworks generator is in the prime-order subgroup, and EIP-2494 `Base8` maps
onto the curve and into the same subgroup. Our canonical coordinates are the
arkworks ones; contracts add points with `a = 1, d = d'`. Interoperability with
iden3 tooling, if ever needed, is a coordinate map, not a different curve.

### 5. Ceremony

The token circuits get **their own** trusted-setup ceremony once they are
frozen. The v2 ceremony (two circuits, open now) is not extended, so that v2
mainnet is not held back by work that takes weeks. *Pending Petr's
confirmation (chat 2024.5).*

### 6. Fee

Unchanged policy: 1 %, floor 0.1, enforced by the pool on `depositToPool`.
Token-to-token transfers outside the pool carry no fee in the first version.

## Order of work

1. Baby Jubjub and twisted ElGamal in Rust (arkworks gadgets plus native code).
   **Done** (`crates/tidex6-confidential/src/token/elgamal.rs`, `gadget.rs`,
   since 15.09.2026), curve form checked (§4a).
2. Circuits. **Done:** `PubkeyValidity`, `TokenTransfer`, `TokenUnwrap`
   (22.09); `DepositFromToken` and `WithdrawToToken` moved to note format v2 on
   01.10.2026. `token_selftest` proves and verifies each and rejects a tampered
   commitment, an overspend, a fee below the floor, and a spend with someone
   else's key. Sizes: 3.5k / 18.9k / 7.2k / 14.3k / 11.9k constraints, proofs
   0.05–0.25 s natively.
3. Baby Jubjub point addition for Solidity and Stylus. **Solidity done**
   (`BabyJubjub.sol`, generated constants, 17.09); Stylus next.
4. Token contract on both stacks; token pool with `depositFromToken` and
   `withdrawToToken`. **Solidity:** `Tidex6ConfidentialToken.sol` (17.09) moved
   to the v2 deposit and given `payOut`; `Tidex6TokenPoolV2.sol` written
   01.10.2026. Stylus next.
5. Client: ElGamal key from the signature, encryption, openings in the
   envelope, WASM prover, Wrap / Transfer / Unwrap screens.
6. Ceremony for the token circuits; keys into the verifiers.
7. Live runs on Arbitrum Sepolia and Robinhood (Stylus), Base (Solidity).

Every step ends in something visible: test vectors, a circuit with passing
tests, a contract on a testnet, a transfer in the browser.

## Open questions

1. **Wrap without scalar multiplication on chain.** `wrap` must produce a
   ciphertext for a public amount. Options: a small `Wrap` circuit proving the
   client-supplied ciphertext encrypts the public amount, or a public
   `pending_plain` counter folded into `available` by the next proof. Decide by
   measured gas.
2. **Auditor at the token level** (a pool- or mint-wide viewing key, as in our
   regulated-pools note) in addition to the per-payment auditor. Same
   cryptography, one more handle; policy decision later.
3. **Solana parity.** Token-2022 already hides balances there; joining it to
   the v2 pool's `DepositFromToken` path is a separate step after EVM.

## Honest caveat

This is new cryptography in our code, not an application of a construction
others have run for years. Until an external audit, the token is for testnets
and demonstrations, not for money anyone needs back.
