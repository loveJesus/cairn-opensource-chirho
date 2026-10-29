#!/usr/bin/env bash
# For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
#
# serve-proof-chirho.sh: integration serve proof for the template landing example app.
# Builds the WASM guest, compiles CSS, checks the source tree, reviews and promotes the exact
# emitted manifest inside one tenant root, serves locally, and verifies end-to-end rendering.

set -euo pipefail

demo_dir_chirho="$(cd "$(dirname "$0")" && pwd)"
engine_dir_chirho="$(cd "$demo_dir_chirho/../.." && pwd)"
port_chirho="${CAIRN_TEMPLATE_PORT_CHIRHO:-8833}"
root_chirho="$(mktemp -d /tmp/tree-template-landing-serve-chirho.XXXXXX)"
tenant_chirho="tree-template-landing-chirho"
server_pid_chirho=""
emitted_manifest_chirho="$demo_dir_chirho/.serve-proof-manifest-chirho.json"

cleanup_chirho() {
  if [ -n "$server_pid_chirho" ]; then
    kill "$server_pid_chirho" 2>/dev/null || true
    wait "$server_pid_chirho" 2>/dev/null || true
  fi
  rm -rf "$root_chirho" 2>/dev/null || true
  rm -f "$emitted_manifest_chirho" 2>/dev/null || true
}
trap cleanup_chirho EXIT

start_server_chirho() {
  "$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" serve --port "$port_chirho" >/dev/null 2>&1 &
  server_pid_chirho="$!"

  for _attempt_chirho in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:$port_chirho/healthz-chirho" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done

  echo "FAIL: local server did not become healthy" >&2
  return 1
}

review_and_promote_chirho() {
  local manifest_path_chirho="$1"
  local review_json_chirho
  local candidate_chirho
  local source_review_report_chirho
  review_json_chirho="$(
    cd "$demo_dir_chirho"
    "$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" \
      app-source-review --manifest "$manifest_path_chirho" --owner "$owner_chirho" --json
  )"
  candidate_chirho="$(python3 -c 'import json, sys; report_chirho = json.load(sys.stdin); print(report_chirho["candidate_chirho"]["root_dag_chirho"])' <<<"$review_json_chirho")"
  source_review_report_chirho="$(python3 -c 'import json, sys; report_chirho = json.load(sys.stdin); print(report_chirho["source_review_report_chirho"])' <<<"$review_json_chirho")"

  "$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" \
    review-promote \
    --app tree-template-landing \
    --owner "$owner_chirho" \
    --candidate "$candidate_chirho" \
    --source-review-report "$source_review_report_chirho"
}

echo "==> building the cairn engine CLI + the tree-build toolchain (debug)"
( cd "$engine_dir_chirho" && cargo build -q -p cairn-cli-chirho -p cairn-tree-build-chirho --bin tree-build-chirho )
cli_chirho="$engine_dir_chirho/target/debug/cairn-chirho"
tree_build_chirho="$engine_dir_chirho/target/debug/tree-build-chirho"

echo "==> check the example template landing tree"
"$tree_build_chirho" check "$demo_dir_chirho"

echo "==> compiling style assets"
"$tree_build_chirho" style-compile "$demo_dir_chirho" \
  --style "styles_chirho/ui_css_chirho.css" \
  --style "styles_chirho/landing_chirho.scss" \
  --output "assets_chirho/landing-chirho.css"

echo "==> generating reviewed public source dictionary"
"$tree_build_chirho" source-dictionary "$demo_dir_chirho" \
  --json "content_chirho/landing_public_copy_chirho.json" \
  --value-type "crate::types_chirho::app_params_landing_v1_chirho::AppParamsLandingV1Chirho" \
  --const "LANDING_PUBLIC_COPY_JSON_CHIRHO" \
  --function "landing_public_copy_chirho" \
  --output "src/content_chirho/landing_public_copy_chirho.rs"

echo "==> generating template render source"
"$tree_build_chirho" template-render "$demo_dir_chirho" \
  --template "templates_chirho/pages_chirho/landing_chirho.html" \
  --model-type "crate::types_chirho::http_request_v1_chirho::HttpRequestV1Chirho" \
  --template-struct "LandingTemplateChirho" \
  --function "render_template_landing_chirho" \
  --output "src/implementations_chirho/render_template_landing_chirho.rs"

echo "==> building the WASM guest"
( cd "$demo_dir_chirho" && cargo build -q --example render_template_landing_guest_chirho --target wasm32-unknown-unknown )

echo "==> registering a local owner"
owner_chirho="$("$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" identity-register --kind owner | head -1 | cut -f1)"
echo "    owner=$owner_chirho"

echo "==> emitting initial manifest without parameters"
"$tree_build_chirho" emit "$demo_dir_chirho" > "$emitted_manifest_chirho"

echo "==> reviewing and promoting the initial app"
review_and_promote_chirho "$emitted_manifest_chirho"

echo "==> serving on 127.0.0.1:$port_chirho"
start_server_chirho

echo "==> fetching the page without parameters (should render reviewed source dictionary copy)"
response_no_params_chirho="$(curl -fsS "http://127.0.0.1:$port_chirho/app-chirho/tree-template-landing/")"
if ! printf '%s' "$response_no_params_chirho" | grep -q "Riverbend Roasters"; then
  echo "FAIL: expected source dictionary HTML since no runtime parameters are registered" >&2
  exit 1
fi
if ! printf '%s' "$response_no_params_chirho" | grep -q "Roasters on Main"; then
  echo "FAIL: expected source dictionary tagline" >&2
  exit 1
fi

echo "==> asserting stylesheet link points to the assets route"
if ! printf '%s' "$response_no_params_chirho" | grep -q 'href="/app-assets-chirho/tree-template-landing/by-name-chirho/landing-chirho.css"'; then
  echo "FAIL: stylesheet link is incorrect" >&2
  exit 1
fi

echo "==> running app-verify"
"$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" app-verify

echo "==> running privacy-scan"
"$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" privacy-scan --fail-on-findings

echo "==> running run-cache-verify"
"$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" run-cache-verify

echo "==> running volatile-effects-verify"
"$cli_chirho" --root "$root_chirho" --tenant "$tenant_chirho" volatile-effects-verify

echo "==> verifying HTML copy lint on rendered page"
rendered_html_file_chirho="$root_chirho/rendered.html"
printf '%s' "$response_no_params_chirho" > "$rendered_html_file_chirho"
"$tree_build_chirho" copy-lint "$rendered_html_file_chirho" \
  --policy "$demo_dir_chirho/copy-lint-policy-chirho.toml" \
  --route-kind "landing-chirho"

echo "PASS: public source app reviewed, promoted in one tenant, served, and verified clean."
