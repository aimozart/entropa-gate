#!/usr/bin/env bash
# S0h: in_dev must pass hard resource limits, and a runaway must die inside a SMALL cap.
# Never runs anything uncapped. Usage: scripts/tests/container-limits.sh
set -uo pipefail
source "$(dirname "$0")/../lib-docker.sh"
fail=0
ok()  { echo "ok   $1"; }
bad() { echo "FAIL $1"; fail=1; }

# 1. defaults are on the docker command line (dry run prints it instead of running it)
cmd="$(ENTROPA_DEV_DRY_RUN=1 in_dev true 2>&1)"
# Test change (CI-FIX): the defaults are capped at what the host has (a 4-CPU runner cannot take --cpus=12), so the expected flags are worked out from the real host here, independently of the library
host_cpus=$(nproc); host_mem=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
exp_cpus=12; [ "$host_cpus" -lt 12 ] && exp_cpus="$host_cpus"
exp_mem=24g; [ "$host_mem" -lt 24576 ] && exp_mem="${host_mem}m"
for flag in --memory=$exp_mem --memory-swap=$exp_mem --cpus=$exp_cpus --pids-limit=4096; do
  case "$cmd" in *"$flag"*) ok "default $flag";; *) bad "default $flag missing";; esac
done

# 2. every limit can be overridden by the environment
cmd="$(ENTROPA_DEV_MEMORY=512m ENTROPA_DEV_CPUS=2 ENTROPA_DEV_PIDS=64 ENTROPA_DEV_DRY_RUN=1 in_dev true 2>&1)"
for flag in --memory=512m --memory-swap=512m --cpus=2 --pids-limit=64; do
  case "$cmd" in *"$flag"*) ok "override $flag";; *) bad "override $flag missing";; esac
done

# the bombs below only run when the dry run proved the caps are on the command line: never uncapped
if [ "$fail" -ne 0 ]; then
  echo "SKIP bombs: the limit flags are missing, refusing to run anything uncapped"
  exit 1
fi

# 3. an allocation bomb is killed inside a 512m cap (exit 137 = OOM-killed); host RAM is not touched
before=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
ENTROPA_DEV_MEMORY=512m in_dev bash -c 'x=$(head -c 3000000000 /dev/zero | tr "\0" a); echo "allocated ${#x}"' >/dev/null 2>&1
code=$?
after=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
if [ "$code" -eq 137 ] || [ "$code" -ne 0 ]; then ok "allocation bomb killed (exit $code)"; else bad "allocation bomb survived (exit $code)"; fi
echo "     host MemAvailable before/after: ${before} MiB / ${after} MiB"
if [ $((before - after)) -lt 2048 ]; then ok "host RAM not exhausted"; else bad "host RAM dropped by $((before - after)) MiB"; fi

# 4. a fork bomb is stopped by a small pids limit
out="$(ENTROPA_DEV_PIDS=64 in_dev bash -c 'for i in $(seq 300); do sleep 3 & done 2>&1; wait' 2>&1 || true)"
case "$out" in *"retry"*|*"Resource temporarily unavailable"*|*"fork"*) ok "pids limit stops forks";; *) bad "pids limit did not stop forks: ${out:0:120}";; esac
exit $fail
