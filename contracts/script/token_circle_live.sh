#!/usr/bin/env bash
# One full confidential-token round against contracts already on a live
# network (ADR-023). Same steps and proofs as TokenCircle.s.sol, but sent with
# `cast send`: `forge script` replays every call in its own EVM before
# broadcasting, and Stylus contracts are WASM that EVM cannot run.
#
#   RPC=https://arbitrum-sepolia-rpc.publicnode.com \
#   TOKEN=0x… POOL=0x… ALICE_PK=0x… \
#   CIRCLE=script/token_circle_arb_sepolia.json \
#   ./script/token_circle_live.sh
#
# Alice must hold `.wrapped` units of the token's ERC-20 and some ETH; Bob
# (keccak256("tidex6 token circle: bob")) is funded with BOB_FUND by Alice.
set -euo pipefail

: "${RPC:?}" "${TOKEN:?}" "${POOL:?}" "${ALICE_PK:?}" "${CIRCLE:?}"
BOB_FUND="${BOB_FUND:-0.002ether}"
GAS="${GAS_FLAGS:-}"

BOB_PK="$(cast keccak "tidex6 token circle: bob")"
ALICE="$(cast wallet address --private-key "$ALICE_PK")"
BOB="$(cast wallet address --private-key "$BOB_PK")"
[ "${ALICE,,}" = "$(jq -r .aliceAddress "$CIRCLE" | tr A-Z a-z)" ] || { echo "Alice address differs from the proofs"; exit 1; }
[ "${BOB,,}" = "$(jq -r .bobAddress "$CIRCLE" | tr A-Z a-z)" ] || { echo "Bob address differs from the proofs"; exit 1; }

USDC="$(cast call "$TOKEN" "token()(address)" --rpc-url "$RPC")"
WRAPPED="$(jq -r .wrapped "$CIRCLE")"

# Proof parts and inputs of one step, in cast's array syntax.
a() { jq -r "\"[\" + (.$1.proof[0:2] | join(\",\")) + \"]\"" "$CIRCLE"; }
b() { jq -r "\"[[\" + (.$1.proof[2:4] | join(\",\")) + \"],[\" + (.$1.proof[4:6] | join(\",\")) + \"]]\"" "$CIRCLE"; }
c() { jq -r "\"[\" + (.$1.proof[6:8] | join(\",\")) + \"]\"" "$CIRCLE"; }
input() { jq -r "\"[\" + (.$1.input | join(\",\")) + \"]\"" "$CIRCLE"; }
key() { jq -r "\"[\" + (.$1 | join(\",\")) + \"]\"" "$CIRCLE"; }

send() { # pk, target, signature, args…
  local pk="$1" to="$2" sig="$3"; shift 3
  echo "→ $sig"
  cast send --rpc-url "$RPC" --private-key "$pk" $GAS "$to" "$sig" "$@" | grep -E "^(status|transactionHash|gasUsed)"
}

usdc_of() { cast call "$USDC" "balanceOf(address)(uint256)" "$1" --rpc-url "$RPC" | awk '{print $1}'; }
ALICE_BEFORE="$(usdc_of "$ALICE")"; BOB_BEFORE="$(usdc_of "$BOB")"; CUSTODY_BEFORE="$(usdc_of "$TOKEN")"

echo "== fund Bob, approve, register Alice, wrap"
cast send --rpc-url "$RPC" --private-key "$ALICE_PK" "$BOB" --value "$BOB_FUND" | grep -E "^status"
send "$ALICE_PK" "$USDC" "approve(address,uint256)" "$TOKEN" "$WRAPPED"
send "$ALICE_PK" "$TOKEN" "register(uint256[2],uint256[2],uint256[2][2],uint256[2])" "$(key aliceKey)" "$(a registerAlice)" "$(b registerAlice)" "$(c registerAlice)"
send "$ALICE_PK" "$TOKEN" "wrap(uint64)" "$WRAPPED"
send "$ALICE_PK" "$TOKEN" "applyPending()"

echo "== register Bob"
send "$BOB_PK" "$TOKEN" "register(uint256[2],uint256[2],uint256[2][2],uint256[2])" "$(key bobKey)" "$(a registerBob)" "$(b registerBob)" "$(c registerBob)"

echo "== Alice pays Bob, Alice funds Bob's pool note"
send "$ALICE_PK" "$TOKEN" "transfer(uint256[2],uint256[2][2],uint256[2],uint256[18],bytes)" "$(a transfer)" "$(b transfer)" "$(c transfer)" "$(input transfer)" 0x
send "$ALICE_PK" "$TOKEN" "depositToPool(uint256[2],uint256[2][2],uint256[2],uint256[14],bytes,bytes)" "$(a deposit)" "$(b deposit)" "$(c deposit)" "$(input deposit)" 0x 0x
ROOT="$(cast call "$POOL" "currentRoot()(uint256)" --rpc-url "$RPC" | awk '{print $1}')"
[ "$ROOT" = "$(cast to-dec "$(jq -r .poolRootAfterDeposit "$CIRCLE")")" ] || { echo "pool root differs: $ROOT"; exit 1; }

echo "== Bob takes the note onto his balance, both unwrap"
send "$BOB_PK" "$TOKEN" "applyPending()"
EXIT_IN="$(jq -r '.exit.input' "$CIRCLE")"
e() { echo "$EXIT_IN" | jq -r ".[$1]"; }
send "$BOB_PK" "$POOL" "withdrawToToken(uint256[2],uint256[2][2],uint256[2],uint256,uint256,(uint256[2],uint256[2],uint256[2]))" \
  "$(a exit)" "$(b exit)" "$(c exit)" "$(e 0)" "$(e 1)" "([$(e 2),$(e 3)],[$(e 4),$(e 5)],[$(e 6),$(e 7)])"
send "$BOB_PK" "$TOKEN" "applyPending()"
send "$BOB_PK" "$TOKEN" "unwrap(uint256[2],uint256[2][2],uint256[2],uint256[7])" "$(a unwrapBob)" "$(b unwrapBob)" "$(c unwrapBob)" "$(input unwrapBob)"
send "$ALICE_PK" "$TOKEN" "unwrap(uint256[2],uint256[2][2],uint256[2],uint256[7])" "$(a unwrapAlice)" "$(b unwrapAlice)" "$(c unwrapAlice)" "$(input unwrapAlice)"

echo "== what the chain shows"
ALICE_DELTA=$(( $(usdc_of "$ALICE") - ALICE_BEFORE ))
BOB_DELTA=$(( $(usdc_of "$BOB") - BOB_BEFORE ))
CUSTODY_DELTA=$(( $(usdc_of "$TOKEN") - CUSTODY_BEFORE ))
echo "alice $ALICE_DELTA bob $BOB_DELTA custody $CUSTODY_DELTA"
[ "$BOB_DELTA" = "$(jq -r .bobUnwraps "$CIRCLE")" ] || { echo "bob payout differs"; exit 1; }
[ "$ALICE_DELTA" = "$(( $(jq -r .aliceUnwraps "$CIRCLE") - WRAPPED ))" ] || { echo "alice payout differs"; exit 1; }
[ "$CUSTODY_DELTA" = "$(( WRAPPED - $(jq -r .bobUnwraps "$CIRCLE") - $(jq -r .aliceUnwraps "$CIRCLE") ))" ] || { echo "custody differs"; exit 1; }
echo "token circle (live): OK"
