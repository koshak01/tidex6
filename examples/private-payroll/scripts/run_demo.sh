#!/usr/bin/env bash
#
# run_demo.sh — three-terminal demo of the tidex6 private payroll
# example. This is the scene used in the demo video: one tmux
# session split into three panes running sender, receiver and
# accountant against live Solana devnet.
#
# Usage:
#   ./scripts/run_demo.sh
#
# Prerequisites:
#   - tmux installed
#   - Rust stable with workspace already built in release mode
#     (the script calls `cargo run --release`, so cold runs will
#      compile on first launch — ~90 seconds)
#   - Solana CLI configured for devnet with a wallet that has at
#     least 0.6 SOL
#
# For simplicity, all three roles share the same payer keypair
# (`~/.config/solana/id.json`). In a real three-party setup each
# actor would have their own wallet; we collapse them here so the
# demo fits on one screen and the SOL round-trips back to the
# same wallet at the end.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
EXAMPLE_DIR="$REPO_ROOT/examples/private-payroll"

NOTE_PATH="/tmp/parents.note"
REPORT_PATH="/tmp/lena_tax_report.md"
SCAN_FILE="${HOME}/.tidex6/payroll_scan.jsonl"

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

SESSION="tidex6-demo"
tmux kill-session -t "$SESSION" 2>/dev/null || true

tmux new-session -d -s "$SESSION" -x 240 -y 60

# Pane 0 (top) — Lena. Runs sender immediately.
tmux send-keys -t "$SESSION:0.0" "clear; echo '=== LENA (Amsterdam) ==='; echo" C-m
tmux send-keys -t "$SESSION:0.0" \
    "cd '$EXAMPLE_DIR' && cargo run --release --bin sender -- deposit --amount 0.5 --memo 'october medicine' --recipient-label parents --note-out '$NOTE_PATH'" C-m

# Split horizontally for pane 1 — parents.
tmux split-window -h -t "$SESSION:0.0"
tmux send-keys -t "$SESSION:0.1" \
    "clear; echo '=== PARENTS (home) ==='; echo; echo 'Waiting for note file from Lena...'" C-m
tmux send-keys -t "$SESSION:0.1" \
    "while [ ! -s '$NOTE_PATH' ]; do sleep 1; done; sleep 10; cd '$EXAMPLE_DIR' && cargo run --release --bin receiver -- withdraw --note '$NOTE_PATH' --to '$RECIPIENT'" C-m

# Split pane 1 vertically for pane 2 — Kai the accountant.
tmux split-window -v -t "$SESSION:0.1"
tmux send-keys -t "$SESSION:0.2" \
    "clear; echo '=== KAI (accountant) ==='; echo; echo 'Waiting for Lena to finish so the scan file has the latest entry...'" C-m
tmux send-keys -t "$SESSION:0.2" \
    "sleep 45; cd '$EXAMPLE_DIR' && cargo run --release --bin accountant -- scan --scan-file '$SCAN_FILE' --output '$REPORT_PATH'; echo; echo '--- REPORT PREVIEW ---'; head -30 '$REPORT_PATH'" C-m

# Attach the session so the user watches the demo live.
tmux select-pane -t "$SESSION:0.0"
tmux attach -t "$SESSION"
