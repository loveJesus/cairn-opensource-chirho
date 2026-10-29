#!/usr/bin/env bash
# For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
#
# SP4.1 proof: a fresh tree-build scaffold can be checked, emitted, built, deployed to a
# disposable root, served locally, and fetched over HTTP. Honest scope: this proves the new template
# is runnable with the current explicit disposable owner registration; SP4.2 removes the manual owner
# typing for dev roots only.
#
# WHAT THIS PROOF DOES NOT COVER: the REVIEWED deploy path. It uses the labeled local-dev deploy flag
# because it targets a disposable root. `app-source-review` + `review-promote` -- the path the LLM
# fleet guide documents for real promotion -- is proven by `source-platform-smoke`.

set -euo pipefail

script_dir_chirho="$(cd "$(dirname "$0")" && pwd)"
engine_dir_chirho="$(cd "$script_dir_chirho/../../../.." && pwd)"
port_chirho="${CAIRN_SP4_1_PORT_CHIRHO:-8897}"
app_root_chirho="$(mktemp -d /tmp/sp4-1-new-scaffold-app-chirho.XXXXXX)"
runtime_root_chirho="$(mktemp -d /tmp/sp4-1-new-scaffold-root-chirho.XXXXXX)"
server_pid_chirho=""

cleanup_chirho() {
  if [ -n "$server_pid_chirho" ]; then
    kill "$server_pid_chirho" 2>/dev/null || true
    wait "$server_pid_chirho" 2>/dev/null || true
  fi
  rm -rf "$app_root_chirho" "$runtime_root_chirho" 2>/dev/null || true
}
trap cleanup_chirho EXIT

echo "==> building cairn CLI and tree-build porcelain"
( cd "$engine_dir_chirho" && CARGO_TARGET_DIR="$engine_dir_chirho/target" cargo build -q -p cairn-cli-chirho -p cairn-tree-build-chirho --bin tree-build-chirho )

cli_chirho="$engine_dir_chirho/target/debug/cairn-chirho"
tree_build_chirho="$engine_dir_chirho/target/debug/tree-build-chirho"

echo "==> scaffolding a fresh contact-form app"
"$tree_build_chirho" new contact-form-chirho "$app_root_chirho"

echo "==> checking the fresh app tree"
"$tree_build_chirho" check "$app_root_chirho"

echo "==> emitting app-source manifest from the scaffolded tree"
manifest_chirho="$app_root_chirho/.emitted-manifest-chirho.json"
"$tree_build_chirho" emit "$app_root_chirho" > "$manifest_chirho"

echo "==> building the scaffolded WASM guest"
( cd "$app_root_chirho" && CARGO_TARGET_DIR="$app_root_chirho/target" cargo build -q --example render_contact_form_guest_chirho --target wasm32-unknown-unknown )

echo "==> registering disposable local owner"
# TENANT-SCOPED throughout. The app is deployed into a tenant and the route is served from that
# tenant, so identity, deploy and serve must all name the same one -- this script previously named it
# NOWHERE, which is why the route never became reachable even though the deploy reported success.
tenant_chirho="starter-contact-chirho"
owner_chirho="$("$cli_chirho" --root "$runtime_root_chirho" --tenant "$tenant_chirho" identity-register --kind owner | head -1 | cut -f1)"
echo "    owner=$owner_chirho"

echo "==> deploying emitted manifest"
# `--allow-unreviewed-dev` is REQUIRED here and is not a bypass of the authoring path: deploying
# without review is refused by design, and this proof deploys to a DISPOSABLE temp root to show the
# scaffold runs. The reviewed path -- app-source-review then review-promote -- is proven separately by
# `source-platform-smoke`, which is the baseline composition proof the LLM guide names. Splitting them
# keeps each honest about what it shows.
( cd "$app_root_chirho" && "$cli_chirho" --root "$runtime_root_chirho" --tenant "$tenant_chirho" app-source-deploy "$manifest_chirho" --owner "$owner_chirho" --allow-unreviewed-dev )

echo "==> serving on 127.0.0.1:$port_chirho"
"$cli_chirho" --root "$runtime_root_chirho" --tenant "$tenant_chirho" serve --port "$port_chirho" >/tmp/sp4-1-new-scaffold-serve-chirho.log 2>&1 &
server_pid_chirho="$!"

route_chirho="http://127.0.0.1:$port_chirho/app-chirho/starter-contact-chirho/"
response_file_chirho="$runtime_root_chirho/scaffold-response-chirho.html"
ready_chirho=0

echo "==> waiting for scaffolded route"
for _ in $(seq 1 50); do
  if curl -fsS "$route_chirho" > "$response_file_chirho" 2>/dev/null; then
    ready_chirho=1
    break
  fi
  sleep 0.2
done
if [ "$ready_chirho" != "1" ]; then
  echo "FAIL: scaffolded route did not become reachable: $route_chirho" >&2
  exit 1
fi
if ! grep -q "Contact us" "$response_file_chirho"; then
  echo "FAIL: expected contact form heading in scaffolded route response" >&2
  exit 1
fi
if ! grep -q "name_chirho" "$response_file_chirho"; then
  echo "FAIL: expected Chirho-suffixed contact input in scaffolded route response" >&2
  exit 1
fi

echo "PASS: SP4.1 fresh scaffold checked, emitted, deployed, served, and fetched."
