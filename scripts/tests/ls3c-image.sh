#!/usr/bin/env bash
# LS3c test: the claims about the container image of entropa-try-http, checked on the artifacts that scripts/ls3c-package.sh builds (a stage record (not published)). LS3C_REUSE=1 reuses the last build.
# Checks: static binary, reproducible in a network-less build container, FROM scratch Dockerfile with a numeric non-root user and no RUN, the image holds ONE file and no secret-looking environment,
# it refuses to start without its settings, it starts read-only with no capabilities and no network, it answers over a loopback-only published port as a non-root process, and its log holds nothing from a request.
# Every docker run is time-boxed (timeout 20 for the foreground refusal check, 120 for the detached runs); a foreground container that does not exit is stopped by the timeout and the check FAILS. Containers are named and stopped, never removed (the project's no-delete rule); images built for the bite checks are tagged ls3c-bite-*.
set -u
cd "$(dirname "$0")/../.."
OUT="${LS3C_OUT:-$HOME/.cache/build/ls3c-package}"
fail=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
CAN="CANARY-LS3C-$(printf '%s' 91c4)"
ORIGIN=https://try.example.test

[ -x scripts/ls3c-package.sh ] || { bad "scripts/ls3c-package.sh is missing or not executable"; exit 1; }
if [ "${LS3C_REUSE:-0}" != 1 ]; then
  mkdir -p "$OUT"
  timeout 5400 scripts/ls3c-package.sh > "$OUT.build.log" 2>&1 || bad "scripts/ls3c-package.sh failed (see $OUT.build.log)"
fi
BIN="$OUT/entropa-try-http"; REPORT="$OUT/report.txt"
[ -x "$BIN" ] && ok "binary exists" || { bad "no binary at $BIN"; exit 1; }
[ -f "$REPORT" ] && ok "report exists" || { bad "no report at $REPORT"; exit 1; }

# the binary
desc=$(file -b "$BIN")
case "$desc" in *"statically linked"*|*"static-pie linked"*) ok "static: $desc" ;; *) bad "not static: $desc" ;; esac
[ "$(readelf -d "$BIN" 2>/dev/null | grep -c '(NEEDED)' || true)" = 0 ] && ok "no shared library is needed" || bad "shared libraries are needed"
sha=$(sha256sum "$BIN" | cut -d' ' -f1)
grep -q "binary sha256: $sha" "$REPORT" && ok "report sha256 matches the file" || bad "report sha256 does not match $sha"
grep -q "^second build sha256: " "$REPORT" && ok "report states a second build" || bad "no second build in the report"
grep -q "^reproducible: yes" "$REPORT" && ok "two builds are identical" || bad "the report does not say the two builds are identical"
grep -q "^build: container .* --network none" "$REPORT" && ok "built in a container with no network" || bad "the report does not say the build ran in a container with --network none"
grep -q "^base image: scratch" "$REPORT" && ok "report records the base image: scratch" || bad "base image not recorded"
grep -Eq "^image bytes: [0-9]+" "$REPORT" && ok "report records the image size" || bad "image size not recorded"

# the build file
DF=packaging/try-http/Dockerfile
if [ -f "$DF" ]; then
  grep -q '^FROM scratch' "$DF" && ok "FROM scratch" || bad "the image is not FROM scratch"
  grep -Eq '^USER [1-9][0-9]*:[1-9][0-9]*' "$DF" && ok "numeric non-root USER" || bad "no numeric non-root USER"
  grep -Eq '^(RUN|SHELL|ADD http|HEALTHCHECK|VOLUME)' "$DF" && bad "a RUN, SHELL, remote ADD, HEALTHCHECK or VOLUME is present (nothing to run, nothing to store)" || ok "no RUN, SHELL, remote ADD, HEALTHCHECK or VOLUME"
  grep -Eq '^ENTRYPOINT \["/entropa-try-http"\]$' "$DF" && ok "exec-form entrypoint, no shell" || bad "the entrypoint is not the binary in exec form"
  grep -Eiq '^ENV .*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)' "$DF" && bad "a secret-looking ENV is set" || ok "no secret-looking ENV"
else
  bad "$DF is missing"
fi

# the image
IMG=$(sed -n 's/^image tag: //p' "$REPORT" | head -1)
if [ -n "$IMG" ] && docker image inspect "$IMG" >/dev/null 2>&1; then
  ok "image $IMG exists"
  user=$(docker image inspect --format '{{.Config.User}}' "$IMG")
  case "$user" in 0|root|"") bad "the image user is '$user'" ;; *) ok "image user $user" ;; esac
  env=$(docker image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$IMG")
  echo "$env" | grep -Eiq '(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)=' && bad "the image environment holds a secret-looking name" || ok "no secret-looking environment in the image"
  cmd=$(docker image inspect --format '{{json .Config.Cmd}}' "$IMG")
  [ "$cmd" = "null" ] && ok "no default command: the settings must be given" || bad "the image has a default command: $cmd"
  # the file list: the binary only (plus the mount points Docker adds to every container)
  cid="ls3c-test-$$-$RANDOM"
  docker create --name "$cid-files" "$IMG" >/dev/null 2>&1
  files=$(docker export "$cid-files" | tar -t | grep -Ev '^(\.dockerenv|dev/|dev/console|dev/pts/|dev/shm/|etc/|etc/hostname|etc/hosts|etc/mtab|etc/resolv\.conf|proc/|sys/)$' | grep -v '/$')
  [ "$files" = "entropa-try-http" ] && ok "the image holds one file: the binary" || bad "unexpected files in the image: $files"
  # refuses to start without its settings
  out=$(timeout 20 docker run --name "$cid-nosettings" --read-only --network none --cap-drop ALL "$IMG" 2>&1); code=$?
  docker stop "$cid-nosettings" >/dev/null 2>&1
  [ "$code" = 2 ] && echo "$out" | grep -q 'trusted-hops' && ok "refuses to start without --trusted-hops (exit 2)" || bad "no refusal without settings (exit $code): $out"
  # starts hardened, with no network at all
  timeout 120 docker run -d --name "$cid-nonet" --read-only --network none --cap-drop ALL --security-opt no-new-privileges --memory 128m --pids-limit 64 "$IMG" --trusted-hops 1 --allow-origin "$ORIGIN" --stats-secs 1 >/dev/null 2>&1
  sleep 2
  docker logs "$cid-nonet" 2>&1 | grep -q '^entropa-try-http listening 0.0.0.0:8080 trusted_hops=1$' && ok "starts read-only, with no capabilities and no network" || bad "no start line with --network none: $(docker logs "$cid-nonet" 2>&1 | head -3)"
  [ "$(docker inspect --format '{{.State.Running}}' "$cid-nonet")" = true ] && ok "still running" || bad "not running"
  docker stop "$cid-nonet" >/dev/null 2>&1
  # answers over a published loopback port, as a non-root process
  timeout 120 docker run -d --name "$cid-http" --read-only --cap-drop ALL --security-opt no-new-privileges --memory 128m --pids-limit 64 -p 127.0.0.1::8080 "$IMG" --trusted-hops 0 --allow-origin "$ORIGIN" --stats-secs 1 --global-per-min 100000 >/dev/null 2>&1
  sleep 2
  port=$(docker port "$cid-http" 8080/tcp | head -1 | sed 's/.*://')
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/healthz")" = 200 ] && ok "GET /healthz 200" || bad "healthz"
  r=$(curl -s -H 'content-type: application/json' -d '{"text":"Please summarise the retention clause.","tier":"T1"}' "http://127.0.0.1:$port/try")
  echo "$r" | grep -q '"label":"mock data, real signed records"' && ok "POST /try answers with a signed record" || bad "POST /try: $r"
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/nope")" = 404 ] && ok "unknown path 404" || bad "404"
  [ "$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS -H "Origin: $ORIGIN" -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type' "http://127.0.0.1:$port/try")" = 204 ] && ok "preflight for the one origin 204" || bad "preflight"
  [ "$(curl -s -o /dev/null -w '%{http_code}' -X OPTIONS -H 'Origin: https://evil.example.test' -H 'Access-Control-Request-Method: POST' "http://127.0.0.1:$port/try")" = 403 ] && ok "preflight for another origin 403" || bad "preflight wrong origin"
  curl -s -H 'content-type: application/json' -H "X-Canary: $CAN" -d "{\"text\":\"$CAN\",\"tier\":\"T1\"}" "http://127.0.0.1:$port/try" >/dev/null
  curl -s -H 'content-type: text/plain' -d "$CAN" "http://127.0.0.1:$port/try" >/dev/null
  sleep 2
  uid=$(docker top "$cid-http" -eo user,pid 2>/dev/null | awk 'NR==2{print $1}')
  case "$uid" in 0|root|"") bad "the process runs as '$uid'" ;; *) ok "the process runs as $uid (not root)" ;; esac
  logs=$(docker logs "$cid-http" 2>&1)
  echo "$logs" | grep -q "$CAN" && bad "the log holds the canary" || ok "the log holds no canary"
  echo "$logs" | grep -Evq '^(entropa-try-http listening |stats )' && bad "the log holds a line that is not the start line or a status count: $(echo "$logs" | grep -Ev '^(entropa-try-http listening |stats )' | head -2)" || ok "the log holds only the start line and status counts"
  docker stop "$cid-http" >/dev/null 2>&1
else
  bad "no image $IMG"
fi
[ "$fail" = 0 ] && echo "ALL OK" || echo "FAILED"
exit $fail
