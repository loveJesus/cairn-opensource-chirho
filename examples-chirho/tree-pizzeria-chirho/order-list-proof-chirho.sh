#!/usr/bin/env bash
# For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
#
# MANUAL-ONLY / CI-UNVERIFIED authoring example. The typed query-refusal invariant is gated by
# crates/cairn-serve-runtime-chirho/src/serve_chirho/tests_chirho.rs and its
# contact_flow_chirho/app_route_write_query_tests_chirho.rs callers.
#
# Order-list transition proof: the blessed order WRITE is served through the real Cairn engine,
# while the authored order-list QUERY route fails closed on the retired legacy money road. The
# hand-written manifest mirrors the tree. v0 scope: dine-in orders (no PII), plain mode.
set -euo pipefail

demo_dir_chirho="$(cd "$(dirname "$0")" && pwd)"
engine_dir_chirho="$(cd "$demo_dir_chirho/../.." && pwd)"
manifest_chirho="$demo_dir_chirho/order-list-source-manifest-chirho.json"
port_chirho="${CAIRN_PIZZERIA_LIST_PORT_CHIRHO:-8823}"
root_chirho="$(mktemp -d /tmp/tree-pizzeria-order-list-chirho.XXXXXX)"
tenant_chirho="tree-pizzeria-orders-manual-chirho"
app_chirho="tree-pizzeria-orders"
server_pid_chirho=""
server_log_chirho="$root_chirho/server-chirho.log"

cleanup_chirho() {
  if [ -n "$server_pid_chirho" ]; then
    kill "$server_pid_chirho" 2>/dev/null || true
    wait "$server_pid_chirho" 2>/dev/null || true
  fi
  rm -rf "$root_chirho" 2>/dev/null || true
}
trap cleanup_chirho EXIT

echo "==> building the cairn engine CLI"
( cd "$engine_dir_chirho" && cargo build -q -p cairn-cli-chirho )
cli_chirho="$engine_dir_chirho/target/debug/cairn-chirho"

echo "==> registering a local owner"
owner_chirho="$("$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" identity-register --kind owner | head -1 | cut -f1)"

echo "==> deploying the order-list manifest through the labeled local-dev bypass"
( cd "$demo_dir_chirho" && "$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" app-source-deploy "$manifest_chirho" --owner "$owner_chirho" --allow-unreviewed-dev )

echo "==> serving on 127.0.0.1:$port_chirho"
"$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" serve --port "$port_chirho" \
  >"$server_log_chirho" 2>&1 &
server_pid_chirho="$!"
server_ready_chirho=0
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$port_chirho/healthz-chirho" >/dev/null 2>&1; then
    server_ready_chirho=1
    break
  fi
  sleep 0.2
done
if [ "$server_ready_chirho" -ne 1 ]; then
  cat "$server_log_chirho" >&2
  echo "FAIL: local pizzeria server did not become ready" >&2
  exit 1
fi

post_order_chirho() {
  curl -fsS -X POST -H 'content-type: application/json' --data "$1" \
    "http://127.0.0.1:$port_chirho/app-chirho/$app_chirho"
}
get_list_status_chirho() {
  curl -sS -o "$list_body_path_chirho" -w '%{http_code}' \
    "http://127.0.0.1:$port_chirho/app-chirho/$app_chirho/order-list-chirho"
}
list_body_path_chirho="$root_chirho/order-list-refusal-chirho.txt"

echo "==> POST order #1 (table 7)"
post_order_chirho '{"table_chirho":7,"items_chirho":[{"name_chirho":"Margherita","qty_chirho":2}]}' >/dev/null

echo "==> POST order #2 (table 3)"
post_order_chirho '{"table_chirho":3,"items_chirho":[{"name_chirho":"Diavola","qty_chirho":1}]}' >/dev/null

echo "==> GET the order list — the retired legacy money road must refuse the authored query route"
list_status_chirho="$(get_list_status_chirho)"
list_chirho="$(cat "$list_body_path_chirho")"
echo "    status: $list_status_chirho"
echo "    body: $list_chirho"
if [ "$list_status_chirho" != "400" ]; then
  echo "FAIL: expected HTTP 400 from the retired legacy money query road, got $list_status_chirho" >&2
  exit 1
fi
for needle_chirho in 'legacy money road' 'QueryEffectChirho'; do
  if ! printf '%s' "$list_chirho" | grep -qF "$needle_chirho"; then
    echo "FAIL: order-list refusal missing '$needle_chirho'" >&2
    exit 1
  fi
done

echo "PASS: orders wrote successfully, and the authored query route failed closed on the retired legacy money road."
