#!/usr/bin/env bash
# PKG1 P9: each named loosening of the installer must make scripts/tests/pkg1-install.sh FAIL. Re-uses a finished build (PKG1_OUT) by repacking the installer
# into a COPY of the tarball; the real packaging/pkg1 files are never changed. Usage: scripts/tests/pkg1-bite.sh PKG1_OUT
set -u
cd "$(dirname "$0")/../.."
OUT=${1:?usage: pkg1-bite.sh PKG1_OUT}
# scratch goes to ONE per-stage directory on tmpfs (volatile, cleared at reboot; nothing here deletes anything)
free_gb=$(df -BG --output=avail / | tail -1 | tr -dc 0-9); [ "$free_gb" -ge 25 ] || { echo "refusing to start: only ${free_gb} GB free on / (rule: at least 25 GB)" >&2; exit 1; }
W="/tmp/tmp-pkg1/bite-$(date +%Y%m%dT%H%M%S)"; mkdir -p "$W"
TAR=$(ls "$OUT"/entropa-gate-*-linux-x86_64.tar.gz | head -1)
mutate() { # $1 name, $2 file in package (install.sh|uninstall.sh), $3 python expression on s
  d="$W/$(echo "$1" | tr -c "A-Za-z0-9\n" _ | cut -c1-30)"; mkdir -p "$d/pkg"; tar -xzf "$TAR" -C "$d/pkg"; p=$(ls -d "$d/pkg"/entropa-gate-*/)
  python3 - "$p/$2" "$3" <<'PY'
import sys
p,e=sys.argv[1],sys.argv[2]; s=open(p).read(); o=s; exec(e); assert s!=o, "mutation did not change the file"; open(p,'w').write(s)
PY
  # a mutated installer no longer matches SHA256SUMS: re-sign the sums and the manifest with the TEST keys so ONLY the behaviour differs
  (cd "$p" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | grep -v -x -e SHA256SUMS -e SHA256SUMS.minisig -e MANIFEST.json | xargs sha256sum > "$d/sums" && mv "$d/sums" SHA256SUMS)
  minisign -S -s "$OUT/testkeys/minisign.key" -t "bite" -x "$p/SHA256SUMS.minisig" -m "$p/SHA256SUMS" >/dev/null 2>&1
  mv "$p/MANIFEST.json" "$d/old-manifest"
  "$p/entropa-release" sign --dir "$p" --product entropa-gate --version bite --sbom "$p/SBOM.cdx.json" --key "$OUT/testkeys/mldsa.seed" --out "$p/MANIFEST.json" >/dev/null 2>&1
  mkdir -p "$d/out"; (cd "$d/pkg" && tar --sort=name --mtime=@1700000000 --owner=0 --group=0 --numeric-owner -cf - "$(basename "$p")" | gzip -n > "$d/out/entropa-gate-0.2.0-linux-x86_64.tar.gz")
  cp -r "$OUT/testkeys" "$d/out/testkeys"; cp -r "$OUT/pubkeys" "$d/out/pubkeys"; cp "$OUT/report.txt" "$d/out/report.txt"
  # the report hash must match the repacked tarball for the test to proceed to the install checks
  h=$(sha256sum "$d/out/entropa-gate-0.2.0-linux-x86_64.tar.gz" | cut -d' ' -f1)
  sed -i "s/^tarball sha256: .*/tarball sha256: $h/; s/^second tarball sha256: .*/second tarball sha256: $h/" "$d/out/report.txt"
  res=$(PKG1_REUSE=1 PKG1_OUT="$d/out" PKG1_WORK="$d/work" scripts/tests/pkg1-install.sh 2>&1 | grep -E "^FAIL" | sed 's/^FAIL //' | cut -c1-60 | head -4 | tr '\n' ';')
  echo "BITE $1: ${res:-NONE FAILED (survived)}"
}
mutate "verification skipped (minisign mode always passes)" install.sh 's=s.replace(chr(34)+"$listed"+chr(34)+" = "+chr(34)+"$present"+chr(34), chr(34)+"x"+chr(34)+" = "+chr(34)+"x"+chr(34))
s=s.replace("sha256sum -c SHA256SUMS --quiet >/dev/null 2>&1 ||","true ||")'
mutate "extra files accepted" install.sh 's=s.replace("[ \"$listed\" = \"$present\" ] ||","true ||")'
mutate "root allowed without the flag" install.sh 's=s.replace("[ \"$(id -u)\" != 0 ] || [ \"$allow_root\" = 1 ] ||","true ||")'
mutate "uninstall removes the whole prefix" uninstall.sh 's=s.replace("rm -f \"$record\"","rm -rf \"$prefix\"")'
mutate "install writes before verifying (copy first)" install.sh 's=s.replace("cd \"$here\"\nfor f in","mkdir -p \"$prefix/bin\"; cp \"$here/entropa-gate\" \"$prefix/bin/leak\"\ncd \"$here\"\nfor f in")'
