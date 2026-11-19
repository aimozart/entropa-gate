#!/bin/sh
# Entropa Gate installer. No network, no root needed, never touches keys or ledgers. It VERIFIES BEFORE IT COPIES anything.
#   sh ./install.sh --minisign-pubkey KEY [--prefix DIR] [--allow-root]     (preferred: an independent verifier)
#   sh ./install.sh --pubkey HEX        [--prefix DIR] [--allow-root]     (weaker: the verifier shipped in this tarball)
# The public key must come from a SECOND channel (the release page you reached separately), never from this tarball.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
prefix="${HOME:-}/.local"; allow_root=0; ms_key=""; ml_key=""
die() { echo "install refused: $*" >&2; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) [ $# -ge 2 ] || die "--prefix needs a directory"; prefix=$2; shift 2 ;;
    --minisign-pubkey) [ $# -ge 2 ] || die "--minisign-pubkey needs a key"; ms_key=$2; shift 2 ;;
    --pubkey) [ $# -ge 2 ] || die "--pubkey needs a key"; ml_key=$2; shift 2 ;;
    --allow-root) allow_root=1; shift ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[ "$(id -u)" != 0 ] || [ "$allow_root" = 1 ] || die "this is running as root; use an ordinary user account, or pass --allow-root if you really mean it"
case "$prefix" in /*) ;; *) die "the prefix must be an absolute path (HOME is not set?)" ;; esac
[ -n "$ms_key$ml_key" ] || die "no trust anchor: pass --minisign-pubkey KEY (preferred) or --pubkey HEX, taken from a second channel and not from this tarball"
cd "$here"
for f in entropa-gate entropa-release install.sh uninstall.sh VERSION MANIFEST.json SHA256SUMS; do [ -f "$f" ] || die "the package is incomplete: $f is missing"; done

# 1. verify, with the strongest verifier available. Nothing has been written yet.
mode=""
if [ -n "$ms_key" ]; then
  command -v minisign >/dev/null 2>&1 || { [ -n "$ml_key" ] || die "minisign is not installed (install it, or pass --pubkey for the weaker mode)"; }
fi
if [ -n "$ms_key" ] && command -v minisign >/dev/null 2>&1; then
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is not installed"
  [ -f SHA256SUMS.minisig ] || die "SHA256SUMS.minisig is missing"
  minisign -V -P "$ms_key" -x SHA256SUMS.minisig -m SHA256SUMS >/dev/null 2>&1 || die "the signature of SHA256SUMS does not verify under the given minisign key"
  sha256sum -c SHA256SUMS --quiet >/dev/null 2>&1 || die "a file does not match SHA256SUMS"
  listed=$(sed 's/^[0-9a-f]*  //' SHA256SUMS | LC_ALL=C sort)
  present=$(find . -type f | sed 's|^\./||' | grep -v -x -e SHA256SUMS -e SHA256SUMS.minisig -e MANIFEST.json | LC_ALL=C sort)
  [ "$listed" = "$present" ] || die "the set of files differs from SHA256SUMS (a file is missing or an extra file is present)"
  mode="minisign"
else
  [ -n "$ml_key" ] || die "no usable verifier"
  ./entropa-release verify --dir . --manifest MANIFEST.json --pubkey "$ml_key" >/dev/null 2>&1 || die "the manifest does not verify under the given ML-DSA key"
  mode="ml-dsa"
fi
version=$(head -1 VERSION | tr -cd '0-9A-Za-z._+-' | cut -c1-40)
[ -n "$version" ] || die "the VERSION file is empty"
if [ "$mode" = minisign ]; then
  echo "verification mode: minisign (an independent verifier; SHA256SUMS signed under the key you gave)"
else
  echo "verification mode: ML-DSA manifest checked by the verifier shipped in this same tarball"
  echo "WARNING: an attacker who replaced this tarball could have replaced that verifier too. This mode catches accidents, not a hostile download. For that, use minisign, or build entropa-release from source."
fi
if command -v sha256sum >/dev/null 2>&1; then fp=$(printf '%s' "${ms_key:-$ml_key}" | sha256sum | cut -c1-16); echo "key fingerprint (first 16 hex of the sha256 of the key text you gave): $fp"; fi
echo "not checked: that the code is safe or reviewed; that the build reproduces on your machine; that the public key you gave is the genuine one (compare it with the key published on a second channel)."

# 2. install, only under the prefix; a failure removes what this run created
created=""
cleanup() { rc=$?; if [ $rc -ne 0 ]; then for p in $created; do rm -f "$p"; done; echo "install failed; files created by this run were removed" >&2; fi; exit $rc; }
trap cleanup EXIT
share="$prefix/share/entropa-gate"; record="$share/install-record"
old_dirs=""
[ -f "$record" ] && old_dirs=$(sed -n 's/^dir //p' "$record")
new_dirs=""
for d in "$prefix" "$prefix/bin" "$prefix/share" "$share"; do
  if [ ! -d "$d" ]; then mkdir "$d"; new_dirs="$new_dirs
$d"; fi
done
put() { # $1 source, $2 destination, $3 mode
  [ -e "$2" ] || created="$created $2.new.$$"
  cp "$1" "$2.new.$$"; chmod "$3" "$2.new.$$"; mv -f "$2.new.$$" "$2"
}
put entropa-gate "$prefix/bin/entropa-gate" 755
put entropa-release "$prefix/bin/entropa-release" 755
put uninstall.sh "$share/uninstall.sh" 755
{
  echo "entropa-gate install record v1"
  echo "prefix $prefix"
  echo "version $version"
  echo "mode $mode"
  echo "file $prefix/bin/entropa-gate"
  echo "file $prefix/bin/entropa-release"
  echo "file $share/uninstall.sh"
  { printf '%s\n' "$old_dirs"; printf '%s\n' "$new_dirs"; } | sed '/^$/d' | LC_ALL=C sort -u | sed 's/^/dir /'
} > "$record.new.$$"
mv -f "$record.new.$$" "$record"
trap - EXIT
echo "installed entropa-gate $version into $prefix/bin (verified: $mode)"
case ":${PATH:-}:" in *":$prefix/bin:"*) ;; *) echo "$prefix/bin is not on your PATH. Add this line to your shell profile (this installer never edits it):"; echo "  export PATH=\"$prefix/bin:\$PATH\"" ;; esac
echo "uninstall: sh $share/uninstall.sh   (the installed copy; it removes only what this installer installed, never your keys or ledgers)"
echo "next: entropa-gate init --dir DIR   (the keys are created there, by you, not by this installer)"
