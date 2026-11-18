# Monitoring config (exported, versioned)

Read-only exports of the live Cloud Monitoring alert policies on `entropa-testnet`, via
`gcloud alpha monitoring policies describe <id> --format=json`. Committed so the current alerting
setup is reproducible from the repo, not only tribal knowledge in the project history/the project notes
prose — if the GCP project ever had to be rebuilt, these are what to recreate.

**Not applied automatically** — these are snapshots for reference and disaster-recovery, not
infrastructure-as-code that gets `apply`'d. Re-export after any change to an alert policy:

```
gcloud alpha monitoring policies describe <policy-id> --format=json > monitoring/<name>.json
```

| File | Alert | Created |
|---|---|---|
| `Entropa__AI_Probe_decision_failures.json` | Brain decide() failures ≥ 3 in 15m | 2026-08-12T12:20:03Z |
| `Entropa__Cloud_Run_5xx_errors.json` | 5xx request count > 0 | 2026-08-12T12:20:16Z |
| `Entropa__heartbeat_check_failed.json` | AI Probe heartbeat missed | 2026-08-12T21:49:07Z |
| `Entropa__chain_rollback_detected.json` | `CHAIN_ROLLBACK` log line seen | 2026-08-14T04:36:40Z (recreated after the service rebuild incident, see the project history) |
| `Entropa__Cloud_Run_memory_utilization_high.json` | Memory > 80% of Cloud Run limit | 2026-08-15T23:52:42Z |

All route to the same notification channel (`projects/entropa-testnet/notificationChannels/1430532887923694351`).
