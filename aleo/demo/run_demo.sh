#!/usr/bin/env bash
# Stage A micro-demo: build + mint private token.
# English-only output for grant reviewers.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROG="$ROOT/tidex6_private_transfer"
export PATH="${HOME}/.local/bin:${PATH}"

# Fixed valid addresses (from leo account new) — deterministic demo.
OWNER="aleo1639nwum2mt0n0ukqwd4pay90u7uy2msmuvcc2htsc6djg94hdsrqzdjzdu"
AUDITOR="aleo1275hjhv92r8yfzvce7jd2ymd265tlme568aj0ppqe7fqms6a9vqs2uk4tv"

echo "==> 1/4  leo version"
if ! command -v leo >/dev/null 2>&1; then
  echo "ERROR: leo not on PATH. Install Leo 4.4+ and retry." >&2
  exit 1
fi
leo --version

echo "==> 2/4  build program"
cd "$PROG"
leo build

echo "==> 3/4  mint_private (10 units → owner)"
leo run mint_private "$OWNER" 10u64

echo "==> 4/4  notes"
cat <<EOF

OK: program builds and mint returns a private Token record.

Next functions (same program, call with leo run after you hold a Token record):
  - transfer_full / transfer_private  — move value
  - issue_audit_slip                  — owner keeps Token, auditor gets AuditSlip

Program source: $PROG/src/main.leo
English map:    $ROOT/demo/README.md

EOF
