#!/usr/bin/env bash
# For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
#
# Development-only owner profile helper. It wraps the existing cairn-chirho identity-register command
# for disposable local roots, then prints the owner principal so proof scripts can pass --owner without
# asking the operator to hand-copy the value. This script is a skin over existing CLI authority.

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: dev_owner_profile_chirho.sh <engine_dir_chirho> <runtime_root_chirho>" >&2
  exit 2
fi

engine_dir_chirho="$1"
runtime_root_chirho="$2"
profile_path_chirho="$runtime_root_chirho/dev-owner-profile-chirho.env"
cli_chirho="$engine_dir_chirho/target/debug/cairn-chirho"

if [ -d "$runtime_root_chirho" ]; then
  resolved_root_chirho="$(cd "$runtime_root_chirho" && pwd -P)"
else
  parent_chirho="$(dirname "$runtime_root_chirho")"
  base_chirho="$(basename "$runtime_root_chirho")"
  if [ -d "$parent_chirho" ]; then
    resolved_root_chirho="$(cd "$parent_chirho" && pwd -P)/$base_chirho"
  else
    resolved_root_chirho="$runtime_root_chirho"
  fi
fi

case "$resolved_root_chirho" in
  /tmp/* | /private/tmp/*) ;;
  *)
    if [ "${CAIRN_ALLOW_NON_TMP_DEV_OWNER_ROOT_CHIRHO:-0}" != "1" ]; then
      echo "refusing dev owner profile outside /tmp without CAIRN_ALLOW_NON_TMP_DEV_OWNER_ROOT_CHIRHO=1: $resolved_root_chirho" >&2
      exit 1
    else
      echo "WARNING: CAIRN_ALLOW_NON_TMP_DEV_OWNER_ROOT_CHIRHO=1 is overriding the /tmp root restriction. Operating on non-temporary root: $resolved_root_chirho" >&2
    fi
    ;;
esac

read_profile_owner_chirho() {
  awk -F= '$1 == "owner_chirho" { print $2; exit }' "$profile_path_chirho"
}

if [ -f "$profile_path_chirho" ]; then
  owner_chirho="$(read_profile_owner_chirho)"
  case "$owner_chirho" in
    owner/*)
      printf '%s\n' "$owner_chirho"
      exit 0
      ;;
    *)
      echo "invalid dev owner profile at $profile_path_chirho" >&2
      exit 1
      ;;
  esac
fi

if [ -d "$runtime_root_chirho" ] && find -L "$runtime_root_chirho" -mindepth 1 -maxdepth 1 | grep -q .; then
  echo "refusing to create a dev owner profile in a non-empty root without an existing profile: $runtime_root_chirho" >&2
  exit 1
fi

mkdir -p "$runtime_root_chirho"
owner_chirho="$("$cli_chirho" --root "$runtime_root_chirho" identity-register --kind owner | head -1 | cut -f1)"
case "$owner_chirho" in
  owner/*) ;;
  *)
    echo "identity-register did not return an owner principal: $owner_chirho" >&2
    exit 1
    ;;
esac

umask 077
printf 'owner_chirho=%s\n' "$owner_chirho" > "$profile_path_chirho"
printf '%s\n' "$owner_chirho"
