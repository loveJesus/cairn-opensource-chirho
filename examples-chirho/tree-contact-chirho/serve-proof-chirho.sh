#!/usr/bin/env bash
# For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
#
# T3 serve proof: the directory-structure-IS-DAG demo, deployed and served through the REAL cairn
# engine over localhost HTTP. Builds the wasm guests, registers a local owner, deploys the
# hand-written manifest (which mirrors the tree), serves it, posts a contact form, and asserts the
# tree's own pure implementations produced the thank-you HTML. Honest scope: v0 happy path; the
# max_length pin is baked into the validate guest (the tree keeps it as a content-in) until the
# multi-input ABI + pin-threading lands in the tooling (T4).
set -euo pipefail

demo_dir_chirho="$(cd "$(dirname "$0")" && pwd)"
engine_dir_chirho="$(cd "$demo_dir_chirho/../.." && pwd)"
manifest_chirho="$demo_dir_chirho/receive-message-source-manifest-chirho.json"
port_chirho="${CAIRN_TREE_DEMO_PORT_CHIRHO:-8799}"
root_chirho="$(mktemp -d /tmp/tree-contact-serve-chirho.XXXXXX)"
server_pid_chirho=""

cleanup_chirho() {
  [ -n "$server_pid_chirho" ] && kill "$server_pid_chirho" 2>/dev/null || true
  rm -rf "$root_chirho" 2>/dev/null || true
}
trap cleanup_chirho EXIT

echo "==> building the cairn engine CLI + the tree-build toolchain (debug)"
( cd "$engine_dir_chirho" && cargo build -q -p cairn-cli-chirho -p cairn-tree-build-chirho --bin tree-build-chirho )
cli_chirho="$engine_dir_chirho/target/debug/cairn-chirho"
tree_build_chirho="$engine_dir_chirho/target/debug/tree-build-chirho"

echo "==> dag-check the tree (the pipeline gates on a clean tree before anything is built)"
"$tree_build_chirho" check "$demo_dir_chirho"

echo "==> registering a local owner"
owner_chirho="$("$cli_chirho" --root "$root_chirho" identity-register --kind owner | head -1 | cut -f1)"
echo "    owner=$owner_chirho"

# Optionally prove the GENERATED manifest (tree-build emit) instead of the hand-written one —
# closing the loop: the same tree that checks clean also serves through emitted wiring.
if [ "${CAIRN_TREE_DEMO_EMIT_CHIRHO:-0}" = "1" ]; then
  echo "==> emitting the manifest from the tree (tree-build emit) and serving THAT"
  ( cd "$engine_dir_chirho" && cargo build -q -p cairn-tree-build-chirho --bin tree-build-chirho )
  emitted_chirho="$demo_dir_chirho/.emitted-manifest-chirho.json"
  "$engine_dir_chirho/target/debug/tree-build-chirho" emit "$demo_dir_chirho" > "$emitted_chirho"
  manifest_chirho="$emitted_chirho"
  trap 'cleanup_chirho; rm -f "$emitted_chirho"' EXIT
fi

echo "==> deploying the demo manifest (builds the wasm guests from the tree's own crate)"
( cd "$demo_dir_chirho" && "$cli_chirho" --root "$root_chirho" app-source-deploy "$manifest_chirho" --owner "$owner_chirho" )

echo "==> serving on 127.0.0.1:$port_chirho"
"$cli_chirho" --root "$root_chirho" serve --port "$port_chirho" >/dev/null 2>&1 &
server_pid_chirho="$!"

echo "==> waiting for health"
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$port_chirho/health-chirho" >/dev/null 2>&1; then break; fi
  sleep 0.2
done

echo "==> POST a contact form to /app-chirho/tree-contact"
body_chirho='{"name_chirho":" Rosa ","body_chirho":" ciao! "}'
response_chirho="$(curl -fsS -X POST -H 'content-type: application/json' \
  --data "$body_chirho" "http://127.0.0.1:$port_chirho/app-chirho/tree-contact")"
echo "    response: $response_chirho"

echo "==> asserting the tree's render produced the thank-you"
if ! printf '%s' "$response_chirho" | grep -q "Thank you, Rosa!"; then
  echo "FAIL: expected thank-you HTML from the tree's render_thanks implementation" >&2
  exit 1
fi

echo "==> asserting an empty name is refused kindly"
empty_chirho="$(curl -fsS -X POST -H 'content-type: application/json' \
  --data '{"name_chirho":"","body_chirho":"hi"}' "http://127.0.0.1:$port_chirho/app-chirho/tree-contact")"
if ! printf '%s' "$empty_chirho" | grep -q "please tell us your name"; then
  echo "FAIL: expected kind validation error from the tree's validate_message implementation" >&2
  exit 1
fi

echo "PASS: the directory-structure-IS-DAG demo served end-to-end through the real cairn engine."
