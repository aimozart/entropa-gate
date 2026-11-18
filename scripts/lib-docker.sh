#!/usr/bin/env bash
# Shared helper: run a command inside the entropa-dev image (built on first use). Source this file.
IMAGE="${ENTROPA_DEV_IMAGE:-entropa-dev:1}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "building $IMAGE (first use, takes a while)..." >&2
  docker build -q -t "$IMAGE" -f "$ROOT/tools/Dockerfile.dev" "$ROOT/tools" >&2
fi
# Persistent caches live under ~/.cache (never in the repo, never committed): the cargo registry and the
# git db. They hold only downloaded crate sources and nothing from the environment, so no secrets.
# ENTROPA_TARGET_CACHE=<dir> (optional) puts the build output in a shared host dir, e.g. for several
# worktrees; by default the build output stays in ./target of this checkout.
mkdir -p "$HOME/.cache/entropa-cargo" "$HOME/.cache/entropa-dev/git"
chmod 700 "$HOME/.cache/entropa-dev" 2>/dev/null || true
# Hard resource limits for every container (overridable by environment). They stop a runaway (an
# unbounded allocation, a fork bomb) without getting in the way of normal builds and tests on this PC.
# A per-process `ulimit -v` is not used: Rust and the fuzz sanitizers reserve far more address space
# than they touch, so the cgroup limit is the reliable one. ENTROPA_DEV_ULIMIT_V=<kB> adds one anyway.
ENTROPA_DEV_MEMORY="${ENTROPA_DEV_MEMORY:-24g}"
ENTROPA_DEV_CPUS="${ENTROPA_DEV_CPUS:-12}"
ENTROPA_DEV_PIDS="${ENTROPA_DEV_PIDS:-4096}"
dev_limits() { echo "limits: memory=$ENTROPA_DEV_MEMORY swap=$ENTROPA_DEV_MEMORY cpus=$ENTROPA_DEV_CPUS pids=$ENTROPA_DEV_PIDS${ENTROPA_DEV_ULIMIT_V:+ ulimit-v=${ENTROPA_DEV_ULIMIT_V}kB}"; }
# IN_DEV_PASS_ENV="NAME1 NAME2" passes those variables into the container by name (values never
# appear on the command line). ENTROPA_DEV_DRY_RUN=1 prints the docker command instead of running it.
in_dev() {
  local pass=(); for n in ${IN_DEV_PASS_ENV:-}; do pass+=(-e "$n"); done
  local limits=(--memory="$ENTROPA_DEV_MEMORY" --memory-swap="$ENTROPA_DEV_MEMORY" --cpus="$ENTROPA_DEV_CPUS" --pids-limit="$ENTROPA_DEV_PIDS")
  # docker has no address-space ulimit type, so the optional limit is set by a wrapper inside the container
  local wrap=(); [ -z "${ENTROPA_DEV_ULIMIT_V:-}" ] || wrap=(bash -c 'ulimit -v "$0"; exec "$@"' "$ENTROPA_DEV_ULIMIT_V")
  local target=(); [ -z "${ENTROPA_TARGET_CACHE:-}" ] || { mkdir -p "$ENTROPA_TARGET_CACHE"; target=(-v "$ENTROPA_TARGET_CACHE":/work/target); }
  local cmd=(docker run --rm "${limits[@]}" "${pass[@]}" --user "$(id -u):$(id -g)" -e HOME=/tmp -e CARGO_HOME=/cargo
    -e CARGO_TARGET_DIR=/work/target -e "PATH=/cargo/bin:/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    -v "$HOME/.cache/entropa-cargo":/cargo/registry -v "$HOME/.cache/entropa-dev/git":/cargo/git -v "$ROOT":/work "${target[@]}" -w /work "$IMAGE" "${wrap[@]}" "$@")
  if [ -n "${ENTROPA_DEV_DRY_RUN:-}" ]; then echo "${cmd[*]}"; return 0; fi
  "${cmd[@]}"
}
