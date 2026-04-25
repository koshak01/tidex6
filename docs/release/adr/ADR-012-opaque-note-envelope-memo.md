# ADR-012: Opaque note format and envelope-encrypted memo

**Status:** Accepted — Supersedes the relevant parts of ADR-010
**Date:** 2026-04-25

> ADR-010 (memo as a first-class field of the verifier, encrypted for the auditor) was the right answer to the question it was asking — "where does the memo live for an accountant scanner". It is the **wrong** answer to the question this ADR asks: "what does the note look like to a sender who has no auditor and just wants to attach a private message for the recipient?". This ADR replaces the on-chain memo scheme with an envelope-encryption design and changes the off-chain note from a structured colon-separated string to an opaque base58 blob.

## Context

Two issues with the ADR-010 design surfaced during integration on `tidex6.com`:

### Issue 1 — note leaks the memo plaintext

The current `DepositNote::to_text` produces strings of the form:

```
tidex6-note-v1:0.1:<secret_hex>:<nullifier_hex>:Rand Match 2026
```

The memo is stored **as plaintext inside the note**. This was a deliberate choice in the original Lena/Kai story (the recipient should see the memo offline, no decryption needed), but it has two consequences:

- **Anyone who intercepts the note (Signal channel, copy-paste history, screenshot) sees the memo in clear text.** Confidentiality of the memo is the same as confidentiality of the secret material — you cannot leak the secret without leaking the memo.
- **The note shape is recognisable.** `tidex6-note-v1:` prefix and the colon-separated structure tell anyone who sees the string that this is a tidex6 note, what denomination it is for, and what the memo says. The leakage is obvious to the eye.

A user concretely raised this: *"я эту строку отдал и всё, и никто не знает, что в строке. Ни tidex, ни хуядекс"*. That is the right product instinct.

### Issue 2 — auditor-only encryption is a half measure

Under ADR-010, the on-chain memo is encrypted **for the auditor**. If there is no auditor (the common case for a sender who only wants to send a message to a recipient), the on-chain memo is a placeholder — wasted bytes, no value to anyone. If there is an auditor, the recipient still cannot read the on-chain memo (they do not have the auditor's secret key) and must rely on the plaintext in the note. So the on-chain memo serves at most one of the two parties at a time.

Both parties (recipient and auditor) **read the same memo text**. There is no separate "auditor-only" content. The architecture should reflect that.

## Decision

**Two changes shipped together.**

### Change 1 — opaque note

`DepositNote::to_text` returns a base58-encoded blob containing:

| Field | Bytes | Notes |
|---|---|---|
| Version tag | 1 | `0x02` for this format |
| Denomination tag | 1 | enum: 0=0.1 SOL, 1=1 SOL, 2=10 SOL |
| Secret | 32 | random 32-byte BN254 scalar |
| Nullifier | 32 | random 32-byte BN254 scalar |

Total 66 bytes → ~90 base58 characters. Sample:

```
4FjxYg9LnZk2ApR5tWqSe8mNbV1cD3hGu6vXeZpJ4yQrK7TfBxLwAdNgPoIE9sJrYmX2vUdBnHsTcQpZ
```

No `tidex6-note-v1` prefix, no separators, no embedded memo. Indistinguishable from any other base58 string of the same length.

The memo plaintext **is no longer stored in the note**. It lives only on-chain, encrypted (see Change 2). When the recipient redeems the note, the SDK decrypts the on-chain memo and surfaces the plaintext to the UI.

### Change 2 — envelope-encrypted on-chain memo

`memo_payload` becomes an **envelope**:

```
┌─────────────────────────────────────────────────────────────┐
│ MemoEnvelope wire format (binary, length-prefixed)          │
├─────────────────────────────────────────────────────────────┤
│ version: u8                                          // 0x01 │
│ flags:   u8                                                  │
│   bit 0: auditor_present (0 = no auditor, 1 = auditor)       │
│ ciphertext_len: u16 (big-endian)                             │
│ ciphertext:    AES-256-GCM(K, memo_plaintext)                │
│   ├── nonce: 12 bytes                                        │
│   ├── tag:   16 bytes                                        │
│   └── data:  variable (max 256 bytes plaintext)              │
│                                                              │
│ wrapped_K_for_recipient (always present): 60 bytes           │
│   ├── nonce: 12 bytes                                        │
│   ├── tag:   16 bytes                                        │
│   └── ciphertext-of-K: 32 bytes                              │
│                                                              │
│ wrapped_K_for_auditor (present only when flag bit 0 set):    │
│   ECDH-style payload, ~92 bytes:                             │
│   ├── ephemeral_pk: 32 bytes (Baby Jubjub G1)                │
│   ├── nonce: 12 bytes                                        │
│   ├── tag:   16 bytes                                        │
│   └── ciphertext-of-K: 32 bytes                              │
└─────────────────────────────────────────────────────────────┘
```

`K` is a per-deposit random 32-byte AES-256 key. The memo plaintext is encrypted **once** under `K`. The same `K` is then wrapped twice (or once, if no auditor): with a key derived from the note, and with the auditor's public key.

**Recipient-side decryption** (any holder of the note can do this):

```
seal_key = HKDF-SHA256(
  ikm  = secret || nullifier,
  salt = empty,
  info = "tidex6-memo-seal-v1"
)[..32]

K = AES-256-GCM-Decrypt(seal_key, wrapped_K_for_recipient)
plaintext = AES-256-GCM-Decrypt(K, ciphertext)
```

**Auditor-side decryption** (only when `flag bit 0 = 1`, with the matching `AuditorSecretKey`):

```
shared_secret = ECDH(auditor_sk, ephemeral_pk)  // Baby Jubjub
unwrap_key    = HKDF-SHA256(shared_secret, "tidex6-memo-auditor-v1")[..32]
K             = AES-256-GCM-Decrypt(unwrap_key, wrapped_K_for_auditor)
plaintext     = AES-256-GCM-Decrypt(K, ciphertext)
```

Both paths recover the **same** `K` and decrypt the **same** ciphertext to the **same** plaintext. There is no per-reader content.

### Three valid modes (unchanged)

| Memo | Auditor | What ships |
|---|---|---|
| ✅ | ✅ | Envelope with both wrapped-K slots; both reader and auditor can decrypt |
| ✅ | ❌ | Envelope with only recipient wrapped-K slot; only the note holder can decrypt |
| ❌ | ❌ | Placeholder envelope: random 32-byte ciphertext + random wrapped-K, no real plaintext exists |
| ❌ | ✅ | Rejected at builder time — auditor without memo is meaningless |

The placeholder for case (3) is generated by `tidex6_core::memo::placeholder_envelope_for_anonymous()`, which produces a syntactically valid `MemoEnvelope` whose ciphertext is random bytes addressable by no one. Anonymous deposits look identical on-chain to deposits with real memos.

### `MEMO_PAYLOAD_MAX_LEN` extension

ADR-010 set the on-chain ceiling at `60 (prefix) + 256 (ciphertext) = 316` bytes. The envelope is larger:

```
header                      :   4 bytes  (version + flags + ciphertext_len)
ciphertext                  :  28 + max 256 = 284 bytes
wrapped_K_for_recipient     :  60 bytes
wrapped_K_for_auditor       :  92 bytes (when present)
                              ─────────
Maximum                     : 440 bytes
```

`MEMO_PAYLOAD_MAX_LEN` increases from 316 to **512 bytes** (round number with headroom). `MEMO_PAYLOAD_MIN_LEN` increases from 60 to **152** (header + minimal ciphertext + recipient slot, no auditor slot). The verifier program redeploys to pick up the new bounds.

### Note format versioning

The new format ships as version `0x02`. Version `0x01` (the colon-separated text format) remains parseable in `DepositNote::from_text` for backward compatibility — old notes from before this ADR can still be read by the SDK if any user has them. They cannot be redeemed against the post-redeploy verifier (which expects v2 envelope), but the parser does not crash on them. Withdrawal of v1 notes is a manual cleanup operation, not a supported flow.

## Consequences

**Positive:**

- **Note becomes truly opaque.** A note in transit reveals nothing — not the framework name, not the denomination, not the memo. Just a base58 string.
- **Memo plaintext lives in exactly one place.** On-chain, encrypted. The note no longer carries it. Intercept the note → still cannot read the memo (you can spend the deposit, but the message is not visible).
- **Single source of truth for the memo.** Recipient and auditor both decrypt the same ciphertext; there is no risk of the two views diverging.
- **Cleaner mental model.** "One letter, multiple sealed envelopes" — anyone who has been around symmetric+asymmetric envelope encryption recognises the pattern.
- **Anonymous deposits are indistinguishable from authored ones on-chain.** Whether or not a memo is present, the on-chain bytes look the same shape. Adversary cannot bucket users by "this guy never attaches memos".

**Negative:**

- **One more verifier redeploy.** ADR-011 already booked one redeploy this week; this is the second. Upgrade authority is still held until Day 17 — capacity exists.
- **Existing test deposits in the mainnet pool become unredeemable.** Their notes are v1 (with plaintext memo) and their on-chain `memo_payload` is the ADR-010 ECDH-only format. After redeploy, the verifier expects v2 envelope. We accept the loss; these are our own test SOL.
- **Memo decryption now requires an extra round-trip.** The recipient cannot read the memo offline from the note alone — the SDK must fetch the on-chain `memo_payload` after the deposit is confirmed to decrypt and surface the text. In practice this is a single RPC call after `getTransaction`, fast enough that the user never notices.
- **Crypto code grows.** New `MemoEnvelope` type, new wrapping/unwrapping functions, new HKDF info strings. Manageable, but reviewers must trace the new code path.

## Fiat-Shamir / PR_CHECKLIST

This ADR does not touch circuit logic or any Groth16 transcript. The withdraw circuit's public inputs and constraints are unchanged. No PR_CHECKLIST_PROOF_LOGIC sign-off is required for this change.

The changes are purely in the off-chain symmetric/asymmetric encryption around the memo and in the verifier's `MEMO_PAYLOAD_MAX_LEN` constant. The verifier itself does not interpret memo bytes; it only enforces length bounds.

## Migration

Day-by-day execution is owned by `/Users/koshak01/.claude/plans/nested-humming-harp.md` (the live plan file). High level:

1. `tidex6-core::memo` — new module-level types `MemoEnvelope`, `derive_seal_key`, `placeholder_envelope_for_anonymous`. Existing `MemoPayload` remains for v1-format parsing only.
2. `tidex6-core::note::DepositNote` — refactor `to_text`/`from_text` to base58 v2; drop `memo_plaintext` field.
3. `tidex6-client::DepositBuilder` — build envelope; `with_memo` no longer needs `with_auditor`; `without_memo` ships placeholder envelope.
4. `tidex6-client::WithdrawBuilder` — after tx confirmation, fetch on-chain `memo_payload`, decrypt with seal key derived from note, return plaintext alongside `signature`.
5. `tidex6-verifier` (programs/) — increase `MEMO_PAYLOAD_MAX_LEN` to 512, `MEMO_PAYLOAD_MIN_LEN` to 152. **Redeploy.**
6. `tidex6-indexer::PoolIndexer::AccountantScanner` — switch from `try_decrypt_for_auditor` to envelope auditor-slot decryption. Same input/output shape; only the inner crypto path changes.
7. `tidex6-cli` — `tidex6 withdraw` shows decrypted memo in output. `tidex6 deposit` no longer prints memo into the note text.
8. `tidex6-web` — show memo to recipient as soon as the note is pasted (preview), and again after withdraw confirmation.
9. ADR-010 marked Superseded by this ADR.

## Related

- **ADR-001** — commitment scheme. Unchanged: `commitment = Poseidon(secret, nullifier)`.
- **ADR-007** — killer features (Shielded Memo). The feature is preserved; only the wire format changes.
- **ADR-010** — memo transport via SPL Memo / verifier first-class field. **Superseded** by this ADR for the memo encryption scheme; the "memo lives in the verifier event" decision from ADR-010 stays.
- **ADR-011** — relayer architecture. Unaffected: the envelope is just bytes the relayer forwards verbatim.
- `crates/tidex6-core/src/memo.rs` — gets a v2 envelope module alongside the existing v1 code.
- `crates/tidex6-core/src/note.rs` — base58 codec.
- `programs/tidex6-verifier/src/pool.rs` — `MEMO_PAYLOAD_MIN_LEN` / `MAX_LEN` widening.
