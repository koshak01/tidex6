#!/usr/bin/env bash
#
# run_demo.sh — three-terminal demo of the tidex6 private payroll
# example. This is the scene used in the demo video: one tmux
# session split into three panes running sender, receiver and
# accountant against live Solana mainnet-beta.
#
# Usage:
#   ./scripts/run_demo.sh
#
# Prerequisites:
#   - tmux installed
#   - Rust stable with workspace already built in release mode
#     (the script calls `cargo run --release`, so cold runs will
#      compile on first launch — ~90 seconds)
#   - Solana CLI configured for mainnet-beta with a wallet that has
#     at least 0.6 SOL
#
# For simplicity, all three roles share the same payer keypair
# (`~/.config/solana/id.json`). In a real three-party setup each
# actor would have their own wallet; we collapse them here so the
# demo fits on one screen and the SOL round-trips back to the
# same wallet at the end.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXAMPLE_DIR="$REPO_ROOT/examples/private-payroll"

# Lena keeps the note locally ONLY as a refund copy — the parents
# never receive it; they scan the chain for their payment.
NOTE_PATH="/tmp/parents.note"
REPORT_PATH="/tmp/lena_tax_report.md"

# ML-KEM-768 identities (ADR-014). The parents and Kai each own a
# keypair; Lena only ever sees their PUBLIC keys.
PARENTS_IDENTITY="${HOME}/.tidex6/parents.json"
KAI_IDENTITY="${HOME}/.tidex6/kai.json"

# Recipient for the receiver binary. Default is the same wallet
# as the payer so SOL round-trips. Override via $RECIPIENT to use
# a separate keypair.
RECIPIENT="${RECIPIENT:-$(solana-keygen pubkey "$HOME/.config/solana/id.json")}"

# Make sure the example is built before opening tmux panes so the
# user sees terminal output immediately rather than 90 seconds of
# cargo compilation in three panes at once.
echo "Pre-building private-payroll binaries (release profile)..."
(cd "$EXAMPLE_DIR" && cargo build --release --bin sender --bin receiver --bin accountant)
echo "Build done."
echo

# Generate fresh ML-KEM identities for the parents and Kai, then
# read back their public keys. Lena seals the deposit to the
# parents' key (--recipient) and an auditor slot to Kai's
# (--auditor); only they hold the matching secrets.
echo "Generating ML-KEM identities for the parents and Kai..."
(cd "$REPO_ROOT" && cargo run --release -q -p tidex6-cli -- keygen --out "$PARENTS_IDENTITY" --force >/dev/null)
(cd "$REPO_ROOT" && cargo run --release -q -p tidex6-cli -- keygen --out "$KAI_IDENTITY" --force >/dev/null)
PARENTS_PK="$(cd "$REPO_ROOT" && cargo run --release -q -p tidex6-cli -- keygen print-mlkem-pk --identity "$PARENTS_IDENTITY")"
KAI_PK="$(cd "$REPO_ROOT" && cargo run --release -q -p tidex6-cli -- keygen print-mlkem-pk --identity "$KAI_IDENTITY")"
echo "Identities ready:"
echo "  parents : $PARENTS_IDENTITY"
echo "  kai     : $KAI_IDENTITY"
echo

SESSION="tidex6-demo"
tmux kill-session -t "$SESSION" 2>/dev/null || true

tmux new-session -d -s "$SESSION" -x 240 -y 60

# Pane 0 (top) — Lena. Runs sender immediately.
tmux send-keys -t "$SESSION:0.0" "clear; echo '=== LENA (Amsterdam) ==='; echo" C-m
tmux send-keys -t "$SESSION:0.0" \
    "cd '$EXAMPLE_DIR' && cargo run --release --bin sender -- deposit --amount 0.5 --memo 'october medicine' --recipient '$PARENTS_PK' --auditor '$KAI_PK' --revoke-after-days 30 --recipient-label parents --note-out '$NOTE_PATH'" C-m

# Split horizontally for pane 1 — parents. They scan the chain with
# their own ML-KEM secret; the note file is never consumed here. We
# wait on it only as a timing cue that Lena's deposit confirmed.
tmux split-window -h -t "$SESSION:0.0"
tmux send-keys -t "$SESSION:0.1" \
    "clear; echo '=== PARENTS (home) ==='; echo; echo 'Scanning the chain for payments addressed to us (no note handed over)...'" C-m
tmux send-keys -t "$SESSION:0.1" \
    "while [ ! -s '$NOTE_PATH' ]; do sleep 1; done; sleep 12; cd '$EXAMPLE_DIR' && cargo run --release --bin receiver -- receive --identity '$PARENTS_IDENTITY' --to '$RECIPIENT'" C-m

# Split pane 1 vertically for pane 2 — Kai the accountant.
tmux split-window -v -t "$SESSION:0.1"
tmux send-keys -t "$SESSION:0.2" \
    "clear; echo '=== KAI (accountant) ==='; echo; echo 'Scanning the chain with Kai ML-KEM key for transfers Lena disclosed...'" C-m
tmux send-keys -t "$SESSION:0.2" \
    "sleep 45; cd '$EXAMPLE_DIR' && cargo run --release --bin accountant -- scan --identity '$KAI_IDENTITY' --output '$REPORT_PATH'; echo; echo '--- REPORT PREVIEW ---'; head -30 '$REPORT_PATH'" C-m

# Attach the session so the user watches the demo live.
tmux select-pane -t "$SESSION:0.0"
tmux attach -t "$SESSION"
