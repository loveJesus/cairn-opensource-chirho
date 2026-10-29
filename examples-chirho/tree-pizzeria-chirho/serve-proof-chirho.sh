#!/usr/bin/env bash
# For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
#
# MANUAL-ONLY / CI-UNVERIFIED authoring example. The typed query-refusal invariant is gated by
# crates/cairn-serve-runtime-chirho/src/serve_chirho/tests_chirho.rs and its
# contact_flow_chirho/app_route_write_query_tests_chirho.rs callers.
#
# Pizzeria serve proof: dogfoods the tree-build toolchain on a SECOND app, MULTI-ROUTE. Checks the
# tree, emits ONE manifest (home root + order WRITE route + order-list QUERY route) from the tree +
# app descriptor, deploys through the real engine, serves, and asserts Rosa's static home page, the
# blessed-write order page (validate_order -> blessed save_order -> render_confirmation), and the
# current typed refusal of the legacy-money-backed query route. The menu page (menu as an editable
# input stone) still awaits pin-threading — surfaced honestly.
set -euo pipefail

demo_dir_chirho="$(cd "$(dirname "$0")" && pwd)"
engine_dir_chirho="$(cd "$demo_dir_chirho/../.." && pwd)"
port_chirho="${CAIRN_PIZZERIA_PORT_CHIRHO:-8821}"
root_chirho="$(mktemp -d /tmp/tree-pizzeria-serve-chirho.XXXXXX)"
tenant_chirho="tree-pizzeria-manual-chirho"
emitted_chirho="$demo_dir_chirho/.emitted-manifest-chirho.json"
server_pid_chirho=""
server_log_chirho="$root_chirho/server-chirho.log"

cleanup_chirho() {
  if [ -n "$server_pid_chirho" ]; then
    kill "$server_pid_chirho" 2>/dev/null || true
    wait "$server_pid_chirho" 2>/dev/null || true
  fi
  rm -rf "$root_chirho" 2>/dev/null || true
  rm -f "$emitted_chirho" 2>/dev/null || true
}
trap cleanup_chirho EXIT

echo "==> building the engine CLI + tree-build toolchain"
( cd "$engine_dir_chirho" && cargo build -q -p cairn-cli-chirho -p cairn-tree-build-chirho --bin tree-build-chirho )
cli_chirho="$engine_dir_chirho/target/debug/cairn-chirho"
tree_build_chirho="$engine_dir_chirho/target/debug/tree-build-chirho"

echo "==> dag-check the pizzeria tree"
"$tree_build_chirho" check "$demo_dir_chirho"

echo "==> emit the manifest from the tree (dogfooding tree-build on a second app)"
"$tree_build_chirho" emit "$demo_dir_chirho" > "$emitted_chirho"

echo "==> registering a local owner"
owner_chirho="$("$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" identity-register --kind owner | head -1 | cut -f1)"

echo "==> deploying the emitted manifest through the labeled local-dev bypass"
( cd "$demo_dir_chirho" && "$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" app-source-deploy "$emitted_chirho" --owner "$owner_chirho" --allow-unreviewed-dev )

echo "==> serving on 127.0.0.1:$port_chirho"
"$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" serve --port "$port_chirho" \
  >"$server_log_chirho" 2>&1 &
server_pid_chirho="$!"
server_ready_chirho=0
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$port_chirho/app-chirho/tree-pizzeria/" >/dev/null 2>&1; then
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

echo "==> GET the home page at /app-chirho/tree-pizzeria/"
response_chirho="$(curl -fsS "http://127.0.0.1:$port_chirho/app-chirho/tree-pizzeria/")"
echo "    response: $response_chirho"
if ! printf '%s' "$response_chirho" | grep -q "Rosa's Pizzeria"; then
  echo "FAIL: expected Rosa's static home page from the tree's render_home implementation" >&2
  exit 1
fi

echo "==> POST a dine-in order to the blessed order route /app-chirho/tree-pizzeria/order-chirho"
order_chirho='{"table_chirho":7,"items_chirho":[{"name_chirho":"Margherita","qty_chirho":2}]}'
order_response_chirho="$(curl -fsS -X POST -H 'content-type: application/json' \
  --data "$order_chirho" "http://127.0.0.1:$port_chirho/app-chirho/tree-pizzeria/order-chirho")"
echo "    response: $order_response_chirho"
for needle_chirho in 'data-order-chirho="received"' 'table 7' '2 &times; Margherita'; do
  if ! printf '%s' "$order_response_chirho" | grep -qF "$needle_chirho"; then
    echo "FAIL: blessed-write order route missing '$needle_chirho' (the emit -> deploy -> serve loop)" >&2
    exit 1
  fi
done

echo "==> POST an invalid order — must be kindly rejected, not crash"
reject_chirho="$(curl -fsS -X POST -H 'content-type: application/json' \
  --data '{"table_chirho":7,"items_chirho":[]}' "http://127.0.0.1:$port_chirho/app-chirho/tree-pizzeria/order-chirho")"
if ! printf '%s' "$reject_chirho" | grep -qF 'data-order-chirho="rejected"'; then
  echo "FAIL: expected a kind rejection from validate_order on the emitted order route" >&2
  exit 1
fi

echo "==> GET the order list — the retired legacy money road must refuse the authored query route"
list_body_path_chirho="$root_chirho/order-list-refusal-chirho.txt"
list_status_chirho="$(curl -sS -o "$list_body_path_chirho" -w '%{http_code}' \
  "http://127.0.0.1:$port_chirho/app-chirho/tree-pizzeria/order-list-chirho")"
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

echo "PASS: pizzeria home + blessed-write order served, and the tree-authored query route failed closed on the retired legacy money road."
