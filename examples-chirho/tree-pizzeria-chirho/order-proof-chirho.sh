#!/usr/bin/env bash
# For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
#
# Phase-1 order proof: the FIRST blessed-WRITE in the directory-structure-IS-DAG model, served end to
# end through the REAL cairn engine over localhost HTTP. The order DAG is
#   validate_order (pure) -> save_order (blessed reify, write-store:orders-chirho) -> render_confirmation (pure)
# A valid order is persisted under the orders-chirho namespace and confirmed; an invalid one is kindly
# rejected; an identical re-POST is idempotent (same content key). This uses a hand-written source
# manifest that mirrors the tree; Phase 2 emits the same wiring from the tree itself (tree-build).
# Honest scope: a dine-in order (table + items, no PII) in plain input mode; pricing binds to the menu
# stone (awaits pin-threading) and a list/read-back route lands with the menu/order routes in Phase 2.
set -euo pipefail

demo_dir_chirho="$(cd "$(dirname "$0")" && pwd)"
engine_dir_chirho="$(cd "$demo_dir_chirho/../.." && pwd)"
manifest_chirho="$demo_dir_chirho/place-order-source-manifest-chirho.json"
port_chirho="${CAIRN_PIZZERIA_ORDER_PORT_CHIRHO:-8822}"
root_chirho="$(mktemp -d /tmp/tree-pizzeria-order-chirho.XXXXXX)"
server_pid_chirho=""

cleanup_chirho() {
  [ -n "$server_pid_chirho" ] && kill "$server_pid_chirho" 2>/dev/null || true
  rm -rf "$root_chirho" 2>/dev/null || true
}
trap cleanup_chirho EXIT

echo "==> building the cairn engine CLI"
( cd "$engine_dir_chirho" && cargo build -q -p cairn-cli-chirho )
cli_chirho="$engine_dir_chirho/target/debug/cairn-chirho"

echo "==> registering a local owner"
owner_chirho="$("$cli_chirho" --root "$root_chirho" identity-register --kind owner | head -1 | cut -f1)"
echo "    owner=$owner_chirho"

echo "==> deploying the place-order manifest (builds the order wasm guests from the tree's crate)"
( cd "$demo_dir_chirho" && "$cli_chirho" --root "$root_chirho" app-source-deploy "$manifest_chirho" --owner "$owner_chirho" )

echo "==> serving on 127.0.0.1:$port_chirho"
"$cli_chirho" --root "$root_chirho" serve --port "$port_chirho" >/dev/null 2>&1 &
server_pid_chirho="$!"
for _ in $(seq 1 50); do
  curl -fsS "http://127.0.0.1:$port_chirho/health-chirho" >/dev/null 2>&1 && break
  sleep 0.2
done

echo "==> POST a valid dine-in order"
order_chirho='{"table_chirho":5,"items_chirho":[{"name_chirho":"Margherita","qty_chirho":2},{"name_chirho":"Diavola","qty_chirho":1}]}'
response_chirho="$(curl -fsS -X POST -H 'content-type: application/json' \
  --data "$order_chirho" "http://127.0.0.1:$port_chirho/app-chirho/tree-pizzeria-order")"
echo "    response: $response_chirho"
for needle_chirho in 'data-order-chirho="received"' 'table 5' '2 &times; Margherita' '1 &times; Diavola'; do
  if ! printf '%s' "$response_chirho" | grep -qF "$needle_chirho"; then
    echo "FAIL: confirmation missing '$needle_chirho' (blessed write -> render chain)" >&2
    exit 1
  fi
done

echo "==> POST the SAME order again — the content-keyed write must be idempotent"
again_chirho="$(curl -fsS -X POST -H 'content-type: application/json' \
  --data "$order_chirho" "http://127.0.0.1:$port_chirho/app-chirho/tree-pizzeria-order")"
if [ "$again_chirho" != "$response_chirho" ]; then
  echo "FAIL: identical re-POST produced a different confirmation (key not stable)" >&2
  exit 1
fi

echo "==> POST an invalid order (no items) — must be kindly rejected, not crash"
rejected_chirho="$(curl -fsS -X POST -H 'content-type: application/json' \
  --data '{"table_chirho":5,"items_chirho":[]}' "http://127.0.0.1:$port_chirho/app-chirho/tree-pizzeria-order")"
echo "    response: $rejected_chirho"
if ! printf '%s' "$rejected_chirho" | grep -qF 'data-order-chirho="rejected"'; then
  echo "FAIL: expected a kind rejection partial from the tree's validate_order" >&2
  exit 1
fi
if ! printf '%s' "$rejected_chirho" | grep -qF 'please add at least one item'; then
  echo "FAIL: expected the validator's kind reason in the rejection" >&2
  exit 1
fi

echo "PASS: the blessed-write order page served end-to-end through the real cairn engine."
