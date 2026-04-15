# /accountant/ — web specification

This document specifies the `/accountant/` page of `tidex6.com`. The page is the browser counterpart of `tidex6 accountant scan` — a read-only ledger reconstruction for whoever holds an auditor secret key.

The page lives in the separate `tidex6-web` repository. This document is the contract: anything described here can be implemented against the current `tidex6-client` crate with no further protocol changes.

---

## Goal

A bookkeeper (Kai, in the flagship story) opens `https://tidex6.com/accountant/` in a browser, pastes the auditor secret key they were handed by their client, and gets back a chronological ledger of every Shielded Memo that was addressed to that key.

The ledger includes enough information to produce a tax report: dates, amounts, memo plaintexts, commitment hashes, and Solana transaction signatures.

The page never asks for the user's spending key. It never moves money. It never writes anything to chain.

---

## Routes

All routes end in a trailing slash per the tidex6.com convention.

| Method | Path | Purpose |
|---|---|---|
| GET  | `/accountant/`              | Render the entry form. |
| POST | `/accountant/scan/`         | Run a scan. Returns JSON. |
| GET  | `/accountant/export/csv/`   | Download the most recent scan as CSV. |

The session between GET `/accountant/scan/` and the export endpoint is held in memory only, scoped to the browser session. No persistent storage of secret material.

---

## UI wireframe

```
┌────────────────────────────────────────────────────────────┐
│  tidex6 · accountant view                                  │
│                                                            │
│  Paste your auditor secret key to reconstruct every memo   │
│  addressed to it. The key never leaves this session.       │
│                                                            │
│  Auditor secret key (64 hex chars)                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │                                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                            │
│  Denomination (optional — scans all by default)            │
│  ( ) all  ( ) 0.1 SOL  ( ) 0.5 SOL  ( ) 1 SOL  ( ) 10 SOL  │
│                                                            │
│               [ Scan pool ]                                │
│                                                            │
├────────────────────────────────────────────────────────────┤
│  Ledger — 12 entries                                       │
│                                                            │
│  # │ Date       │ Amount   │ Memo               │ Tx       │
│  1 │ 2026-01-15 │ 0.5 SOL  │ Rent January       │ 3xKz…9Qw │
│  2 │ 2026-02-15 │ 0.5 SOL  │ Rent February      │ 7pLm…4vT │
│  3 │ 2026-02-22 │ 0.1 SOL  │ Pharmacy           │ nQj8…aYw │
│  …                                                         │
│                                                            │
│  [ Export CSV ]  [ Print ]                                 │
└────────────────────────────────────────────────────────────┘
```

Layout guidelines:

- Monospace for hex fields and transaction signatures.
- Memo column renders UTF-8; long memos truncate with a hover-to-expand.
- Signatures link to `https://explorer.solana.com/tx/<sig>`.
- Page matches the existing tidex6-web palette; no extra brand assets needed.

---

## Backend contract

The web server uses the `tidex6-client` crate directly — it is already part of the microservice stack per CLAUDE.md. No CLI subprocess. No HTTP round-trip to a separate daemon.

### POST `/accountant/scan/`

**Request body** (JSON):

```json
{
  "auditor_secret_key_hex": "02859290dc64d7c3200b42572abd7b76cc347dbae08fd60c9f8952afbc04bdfd",
  "denomination": "all"
}
```

- `auditor_secret_key_hex` — 64-character lowercase hex. Validated server-side as a valid Baby Jubjub scalar via `tidex6_core::elgamal::AuditorSecretKey::from_bytes`.
- `denomination` — one of `"all"`, `"0.1"`, `"0.5"`, `"1"`, `"10"`.

**Server flow:**

1. Parse the hex into an `AuditorSecretKey`. On failure return HTTP 400 with `{"error":"invalid secret key"}`.
2. Resolve the set of pool PDAs to scan (one or four) via `tidex6_client::PrivatePool::connect` for each denomination. `connect` is offline — it only derives the PDA — so this is cheap.
3. For each pool, call `tidex6_client::AccountantScanner::scan`. This fetches `getSignaturesForAddress`, pulls each transaction, decodes the SPL Memo instruction, attempts decryption.
4. Collect entries from all pools, sort ascending by block time, serialise to JSON.
5. Return HTTP 200 with the response body below. **Zeroise the `AuditorSecretKey` on its way out of request scope.** Rust drops on scope exit suffice; do not extend the lifetime by stashing it in a session cache.

**Response body** (HTTP 200):

```json
{
  "entries": [
    {
      "leaf_index": 42,
      "commitment_hex": "…",
      "signature": "5xKz…9Qw",
      "block_time": 1745000000,
      "date": "2026-04-15",
      "amount": "0.5 SOL",
      "amount_lamports": 500000000,
      "memo": "Rent March 2026"
    },
    ...
  ],
  "count": 12,
  "scanned_pools": ["0.1", "0.5", "1", "10"]
}
```

**Error responses:**

- `400 Bad Request` — malformed input (bad hex, unknown denomination). Body: `{"error": "<human readable>"}`.
- `502 Bad Gateway` — RPC failure. Body: `{"error": "Solana RPC unreachable", "retry_after_seconds": 10}`.
- `500 Internal Server Error` — reserved for unexpected panics. Should never happen in practice.

### GET `/accountant/export/csv/`

Returns the scan cached in the browser session (the frontend keeps the response in `sessionStorage`, not the server). Streamed as `Content-Type: text/csv; charset=utf-8` with the header row from `tidex6` CLI's CSV output.

---

## Frontend implementation notes

- Vanilla JS / Alpine.js, matching the existing tidex6-web stack. No SPA framework.
- Client-side validation: hex length 64, `/^[0-9a-f]+$/i`, before sending.
- The entered secret key lives only in a JavaScript variable for the lifetime of the scan; on success it is cleared from the form and from memory.
- `sessionStorage` holds the scan result (not the key) so the Export CSV button works without a second RPC round trip.
- After five minutes of inactivity, clear `sessionStorage` automatically.

---

## Security requirements

1. **HTTPS only.** Enforce HSTS with `max-age=31536000; includeSubDomains; preload`.
2. **No logging of the auditor secret key.** The server must not write the key to stdout, stderr, access logs, error logs, or an APM provider. Annotate the handler with a comment documenting this rule so a future refactor does not accidentally log the request body.
3. **Secret travels in the POST body only.** Never in a URL, never in a querystring, never in a cookie.
4. **CSP** that blocks all third-party scripts on `/accountant/`. Analytics scripts in particular have no business loading on this page.
5. **Content-Security-Policy: `default-src 'self'; connect-src 'self' <rpc-url>; script-src 'self'; style-src 'self' 'unsafe-inline'`**.
6. **Explicit user warning** above the input: *"Your auditor secret key grants read access to every deposit addressed to you. Treat it like a password — do not paste it on a shared computer, do not send it over unencrypted email."*

Known non-mitigations:

- **XSS on tidex6.com is a total compromise.** An attacker who can inject script into `/accountant/` can exfiltrate the key during paste. Mitigate only with CSP and an aggressive npm/dependency audit discipline — this is the same failure mode as any sensitive-data web form.
- **Browser extensions can read the form.** This is structural; no web app can defend against a malicious extension. Note it in the disclaimer.

---

## Parity checks

The web implementation must pass these comparisons against the CLI:

1. For a given fixture pool and auditor key, the set of entries returned by the web scan and by `tidex6 accountant scan --format json` must be equal modulo ordering.
2. The CSV returned by `/accountant/export/csv/` must byte-for-byte match `tidex6 accountant scan --format csv`.
3. A fake auditor key (one with no memos addressed to it) must return `{"entries": [], "count": 0, …}` without errors.

---

## What this page is *not*

- It is not a deposit UI. Users wanting to send memos use the existing `/app/` page.
- It is not a withdraw UI. Read-only.
- It does not need a Solana wallet connection. The auditor secret is an auditor key, not a Solana keypair.
- It is not a multi-account view. One key → one ledger per visit. A bookkeeping firm with many clients visits the page many times (or uses the CLI in a loop).

---

## Out of scope, v0.2+

- Pagination / infinite scroll. MVP serves the whole ledger in one response.
- Date range filtering. CLI has this, the web version can add it later without a protocol change.
- Multi-auditor-per-deposit. Ruled out in ADR-007 for MVP.
- Live updates (WebSocket push). The ledger is fetched on demand; a "Refresh" button is enough.
- Integration with accounting packages (QuickBooks, Xero). The CSV export is the interop boundary.
