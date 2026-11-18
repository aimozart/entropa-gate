# Operations

This repo's real, running checks — every one of these is a script that actually executes, not
a description of intent. Run `scripts/ci.sh` before every push; it runs all of the code-level
checks below in one command.

## CI / code-level checks (`scripts/ci.sh`)

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `gitleaks detect --source . --verbose --redact` (via `scripts/security/secret-scan.sh`)
- `cargo audit` (via `scripts/security/dependency-audit.sh`)

Runs locally, not via GitHub Actions — `entropa-chain` is Gitea-hosted and private; the proprietary
`entropa-agents` crate never touches any third-party CI runner (see `SECURITY.md`). The public
open-core mirror, `entropa-public`, runs the equivalent checks via `.github/workflows/ci.yml` on every
push and pull request.

## Live production checks (`scripts/verify-entropa-persistence.sh`, aliased as `scripts/smoke.sh`)

Read-only GET requests against the live deployed service — never touches consensus/persistence code,
never resets the soak clock:

- `curl https://scryon.entropa.space/api/health` (also reachable at `/healthz`)
- height comparison across a 10s wait, confirming block production is live, not stalled
- `curl https://scryon.entropa.space/api/head`
- full paginated `curl .../api/chain` fetch, piped into `cargo run --example verify_backup -p
  entropa-core` — the real Rust `Chain::verify()` logic, checking every block's hash link and
  ML-DSA signature against the actual live data

## Observability

- `/api/health` / `/healthz` — network + consensus + signature scheme + height, checked by the smoke
  script above and by hand during soak monitoring.
- `monitoring/` — versioned exports of the 5 live Cloud Monitoring alert policies (5xx errors,
  heartbeat missed, AI decision failures, chain rollback detected, memory utilization high), so the
  current alerting setup is reproducible from the repo, not only imperative `gcloud` history.
- `a project record (not published)` — every architecture/safety/product decision, with the command that
  proves the outcome, not just the plan.

## Live-testing evidence practice (standing rule, the project rules — not optional)

Any deliberate action against the live service (a resilience/chaos test, a forced restart, a
corruption test, anything beyond a read-only check) must capture the app's own runtime output
throughout the action, not just check status before/after:

- **Log filter that actually works** — `run.googleapis.com%2Frequests` is HTTP access logs only
  (method/status/latency); it will *not* show this app's own `println!`/`eprintln!` output (e.g.
  `CHAIN_ROLLBACK`, `leader lease acquired`). Filter on `run.googleapis.com%2Fstdout` and
  `run.googleapis.com%2Fstderr` instead:
  ```
  gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="entropa-scryon" \
    AND (logName="projects/entropa-testnet/logs/run.googleapis.com%2Fstdout" OR logName="projects/entropa-testnet/logs/run.googleapis.com%2Fstderr")' \
    --project=entropa-testnet --format="value(timestamp,textPayload)" --order=asc --freshness=<window>
  ```
- True push-streaming (`gcloud alpha logging tail`) needs `grpcio` + `CLOUDSDK_PYTHON_SITEPACKAGES=1`,
  not installed in this environment as of 2026-08-18 — fall back to polling `gcloud logging read` on
  a short interval (~4s) into a file, deduped by `insertId`, for the duration of the action.
- **Every test/action gets its own `a project record (not published)` entry**, filled in as it happens, not
  reconstructed afterward: Expected proof (what log lines/behavior should appear) → Observed outcome
  (what the captured log/command output actually showed) → Evidence (the real excerpts). This is the
  same expectation/observed/evidence discipline Paxel's reports ask for — treat it as a standing
  requirement for this repo, not a reaction to any one report.
