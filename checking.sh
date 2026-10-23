#!/bin/sh
set -eu

fail() { printf '%s\n' "phpcheck: $*" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || fail 'curl is required'

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) fail 'supported systems: Linux and macOS' ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  i386|i486|i586|i686) arch=386 ;;
  *) fail 'unsupported CPU architecture' ;;
esac
[ "$os-$arch" != darwin-386 ] || fail '32-bit macOS is not supported'

repo=https://github.com/v1xingyue/phpcheck-hids
# prepare-private.sh fills these two values for a self-contained private mirror.
download_base=''
release_version=''
protocols='=https'
case "$download_base" in http://*) protocols='=http,https' ;; esac
download() {
  curl --fail --silent --show-error --location --proto "$protocols" --proto-redir "$protocols" \
    --retry 3 --connect-timeout 10 --max-time 120 "$@"
}
asset=phpcheck-$os-$arch
if [ -n "$download_base" ]; then
  [ -n "$release_version" ] || fail 'private mirror version is missing'
  base=$download_base
  version=$release_version
else
  # Resolve latest once so the binary and checksum cannot come from different releases.
  release_url=$(download --output /dev/null --write-out '%{url_effective}' "$repo/releases/latest")
  case "$release_url" in
    "$repo"/releases/tag/v*) version=${release_url##*/} ;;
    *) fail 'cannot resolve latest release tag' ;;
  esac
  case "$version" in *[!a-zA-Z0-9._-]*|'') fail 'invalid release tag' ;; esac
  base=$repo/releases/download/$version
fi

umask 077
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/phpcheck.XXXXXX")
trap 'rm -rf "$temp_dir"' 0
trap 'exit 130' INT
trap 'exit 143' TERM
download --output "$temp_dir/$asset" "$base/$asset"
download --output "$temp_dir/SHA256SUMS" "$base/SHA256SUMS"

expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$temp_dir/SHA256SUMS")
[ "${#expected}" -eq 64 ] || fail 'checksum entry missing or duplicated'
case "$expected" in *[!a-fA-F0-9]*) fail 'invalid SHA-256 checksum' ;; esac
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$temp_dir/$asset")
elif command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$temp_dir/$asset")
else
  fail 'sha256sum or shasum is required'
fi
actual=${actual%% *}
[ "$actual" = "$expected" ] || fail 'SHA-256 mismatch; refusing to execute'
chmod 700 "$temp_dir/$asset"
printf 'phpcheck: running %s (%s)\n' "$asset" "$version" >&2
"$temp_dir/$asset" "$@"
