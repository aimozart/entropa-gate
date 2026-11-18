#!/usr/bin/env bash
# Package entropa-witnessd (built with --features aws) as a Lambda zip: one executable named 'bootstrap'.
#   scripts/package-witness-lambda.sh  ->  target/witness-lambda.zip   (prints its sha256)
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=${BIN:-target/release/entropa-witnessd}
[ -x "$BIN" ] || { echo "build first: cargo build --release -p entropa-witnessd --features aws"; exit 1; }
need=$(objdump -T "$BIN" | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -1); echo "needs $need (Lambda provided.al2023 has glibc 2.34)"
python3 - "$BIN" <<'PY'
import sys, zipfile
z = zipfile.ZipFile('target/witness-lambda.zip', 'w', zipfile.ZIP_DEFLATED)
i = zipfile.ZipInfo('bootstrap'); i.external_attr = 0o755 << 16; i.compress_type = zipfile.ZIP_DEFLATED
z.writestr(i, open(sys.argv[1], 'rb').read()); z.close()
PY
ls -l target/witness-lambda.zip | awk '{print $5" bytes"}'; sha256sum target/witness-lambda.zip
