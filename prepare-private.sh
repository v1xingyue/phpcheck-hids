#!/bin/sh
set -eu

fail() { printf '%s\n' "prepare-private: $*" >&2; exit 1; }
usage() {
  printf '%s\n' 'Usage: sh prepare-private.sh --url https://host/phpcheck --static-dir /srv/www/phpcheck [--version v0.3.0]'
}
url=
static_dir=
version=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --url|--static-dir|--version)
      [ "$#" -ge 2 ] || fail "missing value for $1"
      case "$1" in --url) url=$2 ;; --static-dir) static_dir=$2 ;; --version) version=$2 ;; esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown argument: $1" ;;
  esac
done
[ -n "$url" ] && [ -n "$static_dir" ] || { usage >&2; fail '--url and --static-dir are required'; }
while [ "${url%/}" != "$url" ]; do url=${url%/}; done
case "$url" in http://?*|https://?*) ;; *) fail 'URL must start with http:// or https://' ;; esac
# Restrict template input: no credentials, query, fragments, shell metacharacters or control characters.
case "$url" in *[!a-zA-Z0-9:/._%~-]*) fail 'URL must be a plain host/path URL without credentials, query or fragment' ;; esac
authority=${url#*://}; authority=${authority%%/*}
[ -n "$authority" ] || fail 'URL host is missing'
command -v curl >/dev/null 2>&1 || fail 'curl is required'
if command -v sha256sum >/dev/null 2>&1; then
  hash_file() { sha256sum "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  hash_file() { shasum -a 256 "$1"; }
else
  fail 'sha256sum or shasum is required'
fi
repo=https://github.com/v1xingyue/phpcheck-hids
download() {
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --retry 3 --connect-timeout 10 --max-time 120 "$@"
}
if [ -z "$version" ]; then
  release_url=$(download --output /dev/null --write-out '%{url_effective}' "$repo/releases/latest")
  case "$release_url" in "$repo"/releases/tag/v*) version=${release_url##*/} ;; *) fail 'cannot resolve latest release' ;; esac
fi
printf '%s\n' "$version" | LC_ALL=C grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+$' || fail 'version must be vMAJOR.MINOR.PATCH'

umask 022
mkdir -p "$static_dir/releases"
static_dir=$(cd "$static_dir" && pwd -P)
lock_dir=$static_dir/.prepare-private.lock
mkdir "$lock_dir" 2>/dev/null || fail 'another publisher is active (or a stale .prepare-private.lock needs removal)'
stage=
root_tmp=
cleanup() {
  [ -z "$stage" ] || rm -rf "$stage"
  [ -z "$root_tmp" ] || rm -f "$root_tmp"
  rmdir "$lock_dir" 2>/dev/null || :
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' TERM
release_dir=$static_dir/releases/$version
[ ! -e "$release_dir" ] && [ ! -L "$release_dir" ] || fail "release directory already exists: $release_dir"
[ ! -d "$static_dir/checking.sh" ] || fail 'checking.sh must not be a directory'
stage=$(mktemp -d "$static_dir/releases/.stage.XXXXXX")
base=$repo/releases/download/$version
assets='phpcheck-linux-386 phpcheck-linux-amd64 phpcheck-linux-arm64 phpcheck-darwin-amd64 phpcheck-darwin-arm64 checking.sh'
download --output "$stage/UPSTREAM_SHA256SUMS" "$base/SHA256SUMS"
for asset in $assets; do
  download --output "$stage/$asset" "$base/$asset"
  expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$stage/UPSTREAM_SHA256SUMS")
  [ "${#expected}" -eq 64 ] || fail "missing or duplicated checksum: $asset"
  case "$expected" in *[!a-fA-F0-9]*) fail "invalid checksum: $asset" ;; esac
  actual=$(hash_file "$stage/$asset"); actual=${actual%% *}
  [ "$actual" = "$expected" ] || fail "SHA-256 mismatch: $asset"
done
grep -qx "download_base=''" "$stage/checking.sh" && grep -qx "release_version=''" "$stage/checking.sh" || fail 'unsupported checking.sh template'
sed -e "s|^download_base=''.*|download_base='$url/releases/$version'|" \
    -e "s|^release_version=''.*|release_version='$version'|" "$stage/checking.sh" > "$stage/checking.sh.new"
mv "$stage/checking.sh.new" "$stage/checking.sh"
sh -n "$stage/checking.sh"
# The private script has changed: generate a fresh manifest after rewriting it.
(cd "$stage"; for asset in $assets; do hash_file "$asset"; done) > "$stage/SHA256SUMS"
rm "$stage/UPSTREAM_SHA256SUMS"
chmod 755 "$stage"
chmod 644 "$stage/"*
mv "$stage" "$release_dir"
stage=
# Publish the entry script last; existing clients keep using their pinned release.
root_tmp=$(mktemp "$static_dir/.checking.XXXXXX")
cp "$release_dir/checking.sh" "$root_tmp"
chmod 644 "$root_tmp"
mv -f "$root_tmp" "$static_dir/checking.sh"
root_tmp=
printf 'Prepared %s in %s\nRun: curl -fsSL %s/checking.sh | sh\n' "$version" "$static_dir" "$url"
