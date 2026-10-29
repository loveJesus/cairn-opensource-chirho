#!/usr/bin/env bash
# For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
#
# SP4.2 proof: the scaffold-to-serve loop can use a dev owner profile so the operator does not
# hand-copy an owner principal. Honest scope: dev-only /tmp roots; real owner-gated promote remains
# unchanged.

set -euo pipefail

script_dir_chirho="$(cd "$(dirname "$0")" && pwd)"
engine_dir_chirho="$(cd "$script_dir_chirho/../../../.." && pwd)"
profile_helper_chirho="$script_dir_chirho/dev_owner_profile_chirho.sh"
port_chirho="${CAIRN_SP4_2_PORT_CHIRHO:-8898}"
app_root_chirho="$(mktemp -d /tmp/sp4-2-dev-owner-app-chirho.XXXXXX)"
runtime_root_chirho="$(mktemp -d /tmp/sp4-2-dev-owner-root-chirho.XXXXXX)"
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

echo "==> proving dev owner helper refuses non-/tmp roots by default"
non_tmp_root_chirho="$engine_dir_chirho/target/sp4-2-non-tmp-dev-owner-root-chirho"
rm -rf "$non_tmp_root_chirho"
if "$profile_helper_chirho" "$engine_dir_chirho" "$non_tmp_root_chirho" >/tmp/sp4-2-non-tmp-owner-out-chirho.txt 2>/tmp/sp4-2-non-tmp-owner-err-chirho.txt; then
  echo "FAIL: dev owner helper accepted a non-/tmp root without explicit override" >&2
  exit 1
fi
rm -rf "$non_tmp_root_chirho"

echo "==> proving dev owner helper resolves lexical /tmp escapes"
escaped_non_tmp_root_chirho="/tmp/../var/tmp/sp4-2-escaped-dev-owner-root-chirho-$$"
rm -rf "$escaped_non_tmp_root_chirho"
if "$profile_helper_chirho" "$engine_dir_chirho" "$escaped_non_tmp_root_chirho" >/tmp/sp4-2-escaped-owner-out-chirho.txt 2>/tmp/sp4-2-escaped-owner-err-chirho.txt; then
  echo "FAIL: dev owner helper accepted a lexical /tmp escape without explicit override" >&2
  exit 1
fi
rm -rf "$escaped_non_tmp_root_chirho"

echo "==> proving dev owner helper follows symlinked roots for emptiness checks"
symlink_target_chirho="$(mktemp -d /tmp/sp4-2-symlink-target-chirho.XXXXXX)"
symlink_root_chirho="/tmp/sp4-2-symlink-root-chirho-$$"
rm -f "$symlink_root_chirho"
touch "$symlink_target_chirho/existing-chirho"
ln -s "$symlink_target_chirho" "$symlink_root_chirho"
if "$profile_helper_chirho" "$engine_dir_chirho" "$symlink_root_chirho" >/tmp/sp4-2-symlink-owner-out-chirho.txt 2>/tmp/sp4-2-symlink-owner-err-chirho.txt; then
  echo "FAIL: dev owner helper accepted a populated symlinked /tmp root" >&2
  exit 1
fi
rm -f "$symlink_root_chirho"
rm -rf "$symlink_target_chirho"

echo "==> scaffolding a fresh contact-form app"
"$tree_build_chirho" new contact-form-chirho "$app_root_chirho"

echo "==> checking and emitting the fresh app tree"
"$tree_build_chirho" check "$app_root_chirho"
manifest_chirho="$app_root_chirho/.emitted-manifest-chirho.json"
"$tree_build_chirho" emit "$app_root_chirho" > "$manifest_chirho"

echo "==> building the scaffolded WASM guest"
( cd "$app_root_chirho" && CARGO_TARGET_DIR="$app_root_chirho/target" cargo build -q --example render_contact_form_guest_chirho --target wasm32-unknown-unknown )

echo "==> resolving disposable owner through dev profile"
owner_chirho="$("$profile_helper_chirho" "$engine_dir_chirho" "$runtime_root_chirho")"
owner_again_chirho="$("$profile_helper_chirho" "$engine_dir_chirho" "$runtime_root_chirho")"
if [ "$owner_chirho" != "$owner_again_chirho" ]; then
  echo "FAIL: dev owner profile did not reuse the same owner principal" >&2
  exit 1
fi
echo "    owner profile resolved"

echo "==> deploying emitted manifest with owner from dev profile"
( cd "$app_root_chirho" && "$cli_chirho" --root "$runtime_root_chirho" app-source-deploy "$manifest_chirho" --owner "$owner_chirho" )

echo "==> serving on 127.0.0.1:$port_chirho"
"$cli_chirho" --root "$runtime_root_chirho" serve --port "$port_chirho" >/tmp/sp4-2-dev-owner-serve-chirho.log 2>&1 &
server_pid_chirho="$!"

echo "==> waiting for scaffolded route"
for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:$port_chirho/app-chirho/starter-contact-chirho/" >/tmp/sp4-2-dev-owner-response-chirho.html 2>/dev/null; then
    break
  fi
  sleep 0.2
done

if ! grep -q "Contact us" /tmp/sp4-2-dev-owner-response-chirho.html; then
  echo "FAIL: expected contact form heading in scaffolded route response" >&2
  exit 1
fi
if ! grep -q "name_chirho" /tmp/sp4-2-dev-owner-response-chirho.html; then
  echo "FAIL: expected Chirho-suffixed contact input in scaffolded route response" >&2
  exit 1
fi

echo "PASS: SP4.2 scaffold-to-serve proof used a dev owner profile without hand-copying an owner principal."
