#!/usr/bin/env bash
# True test counts, per crate and in total, for the default build and for --all-features.
# Most tests live in #[cfg(test)] modules next to the code (see TESTING.md), which tools that only
# count files under tests/ miss; this script counts what `cargo test` actually runs.
# Usage: scripts/count-tests.sh            (runs both builds, needs Docker only)
set -euo pipefail
source "$(dirname "$0")/lib-docker.sh"
[ -d "$ROOT/admin-ui/dist" ] || "$ROOT/scripts/build-admin-ui.sh" >/dev/null

count() { # $1 = label, rest = cargo test flags
  local label="$1"; shift
  local out; out="$(in_dev cargo test --workspace --locked "$@" 2>&1)" || { echo "$out" | tail -n 30; echo "cargo test FAILED"; exit 1; }
  echo "== $label"
  echo "$out" | awk '
    /Running .*\(target\/debug\/deps\// { m=$0; sub(/.*deps\//,"",m); sub(/-[0-9a-f]+\)$/,"",m); crate=m; kind="unit/integration" }
    /Doc-tests / { crate=$2; kind="doc" }
    /^test result:/ {
      for (i=1;i<=NF;i++) { if ($i=="passed;") p=$(i-1); if ($i=="failed;") f=$(i-1); if ($i=="ignored;") g=$(i-1) }
      P[crate]+=p; F[crate]+=f; G[crate]+=g; tp+=p; tf+=f; tg+=g
    }
    END {
      printf "%-34s %7s %7s %8s\n","crate (target group)","passed","failed","ignored"
      n=asorted(P); 
      for (c in P) printf "%-34s %7d %7d %8d\n", c, P[c], F[c], G[c] | "sort"
      close("sort")
      printf "%-34s %7d %7d %8d\n","TOTAL",tp,tf,tg
    }
    function asorted(a,  k,c){c=0;for(k in a)c++;return c}'
}
count "default features"
count "all features (--all-features)" --all-features
