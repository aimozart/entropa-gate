#!/usr/bin/env bash
# CI-FIX (the first CI run on a 4-CPU runner died with "range of CPUs is from 0.01 to 4.00"): the container limits are capped at what the host really has. The host is simulated with
# ENTROPA_DEV_HOST_CPUS and ENTROPA_DEV_HOST_MEM_MIB so the test behaves the same on a big PC and on a small runner. Expected values are written by hand. Nothing is run in a container (dry run only).
set -uo pipefail
cd "$(dirname "$0")/../.."
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }
# run in_dev in a new shell with the given environment; prints stdout+stderr of the dry run
dry() { env "$@" bash -c 'source scripts/lib-docker.sh; ENTROPA_DEV_DRY_RUN=1 in_dev true' 2>&1; }
has()  { case "$1" in *"$2"*) ok "$3";; *) bad "$3 (wanted: $2) got: ${1:0:300}";; esac; }
lacks(){ case "$1" in *"$2"*) bad "$3 (found: $2)";; *) ok "$3";; esac; }

out="$(dry ENTROPA_DEV_HOST_CPUS=4 ENTROPA_DEV_HOST_MEM_MIB=16000)"
has   "$out" "--cpus=4 "                "c1 a 4-CPU host: the default request of 12 becomes 4"
lacks "$out" "--cpus=12"                "c1 and 12 is gone"
has   "$out" "using 4"                  "c1 the cap is said out loud"
# (64000 MiB of memory here, so that the memory cap stays quiet and "nothing is said" is about the CPUs only)
out="$(dry ENTROPA_DEV_HOST_CPUS=4 ENTROPA_DEV_HOST_MEM_MIB=64000 ENTROPA_DEV_CPUS=2)"
has   "$out" "--cpus=2 "                "c2 a request below the host is never raised"
lacks "$out" "using"                    "c2 and nothing is said"
out="$(dry ENTROPA_DEV_HOST_CPUS=20 ENTROPA_DEV_HOST_MEM_MIB=64000)"
has   "$out" "--cpus=12 "               "c3 a big host keeps the default of 12"
out="$(dry ENTROPA_DEV_HOST_CPUS=4 ENTROPA_DEV_HOST_MEM_MIB=16000 ENTROPA_DEV_CPUS=0.5)"
has   "$out" "--cpus=0.5 "              "c4 a fractional request below the host stays"
out="$(dry ENTROPA_DEV_HOST_CPUS=4 ENTROPA_DEV_HOST_MEM_MIB=16000 ENTROPA_DEV_CPUS=4.5)"
has   "$out" "--cpus=4 "                "c5 a fractional request above the host becomes the host's"
out="$(dry ENTROPA_DEV_HOST_CPUS=4 ENTROPA_DEV_HOST_MEM_MIB=7000)"
has   "$out" "--memory=7000m "          "m1 a 7000 MiB host: the default 24g becomes 7000m"
has   "$out" "--memory-swap=7000m "     "m1 and the swap limit equals it"
has   "$out" "using 7000m"              "m1 the cap is said out loud"
out="$(dry ENTROPA_DEV_HOST_CPUS=20 ENTROPA_DEV_HOST_MEM_MIB=64000)"
has   "$out" "--memory=24g "            "m2 a big host keeps 24g"
out="$(dry ENTROPA_DEV_HOST_CPUS=4 ENTROPA_DEV_HOST_MEM_MIB=7000 ENTROPA_DEV_MEMORY=512m)"
has   "$out" "--memory=512m "           "m3 a request below the host stays"
out="$(dry ENTROPA_DEV_HOST_CPUS=4 ENTROPA_DEV_HOST_MEM_MIB=7000 ENTROPA_DEV_MEMORY=100000g)"
has   "$out" "--memory=7000m "          "m4 a huge request is capped"
out="$(dry ENTROPA_DEV_HOST_CPUS=4 ENTROPA_DEV_HOST_MEM_MIB=7000 ENTROPA_DEV_MEMORY=6g)"
has   "$out" "--memory=6g "             "m5 6g on a 7000 MiB host stays (6144 MiB is below 7000)"
out="$(dry ENTROPA_DEV_HOST_CPUS=4 ENTROPA_DEV_HOST_MEM_MIB=7000 ENTROPA_DEV_MEMORY=7g)"
has   "$out" "--memory=7000m "          "m6 7g (7168 MiB) on a 7000 MiB host is capped"
# an unreadable host value never caps (we do not know)
out="$(dry ENTROPA_DEV_HOST_CPUS=0 ENTROPA_DEV_HOST_MEM_MIB=0)"
has   "$out" "--cpus=12 "               "u1 unknown host CPUs: no cap"
has   "$out" "--memory=24g "            "u1 unknown host memory: no cap"
out="$(dry ENTROPA_DEV_HOST_CPUS=abc ENTROPA_DEV_HOST_MEM_MIB=xyz)"
has   "$out" "--cpus=12 "               "u2 garbage host values: no cap"
# the limits line (printed by the build scripts) shows the capped values
out="$(env ENTROPA_DEV_HOST_CPUS=4 ENTROPA_DEV_HOST_MEM_MIB=7000 bash -c 'source scripts/lib-docker.sh; dev_limits' 2>&1)"
has   "$out" "cpus=4 "                  "l1 the limits line shows the capped CPUs"
has   "$out" "memory=7000m"             "l1 and the capped memory"
exit $fail
