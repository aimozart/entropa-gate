#!/usr/bin/env python3
"""Realistic-traffic generator for the pre-production soak window.

The owner's explicit call, 2026-08-26: this is not a synthetic demo -- it runs
against the exact real production architecture and code path (real signup,
real Stripe subscription, real bearer-key auth via entropa-ingest, real
per-customer private Merkle tree) with only the company/customer identity
being mock. The account (Pinnacle Financial) went through the genuine public
/signup flow -- a real Stripe Checkout, a real webhook-provisioned partner
record, a real API key -- exactly what a brand-new paying customer gets.

Simulates a mid-to-large financial services company's AI-agent decision
volume: fraud detection, KYC/AML screening, loan underwriting, trade
surveillance, portfolio rebalancing, wire-transfer approval, collections.
Run standalone or via `entropa-soak-traffic.timer`
(see scripts/soak/README.md). Reads ENTROPA_SOAK_API_KEY/ENTROPA_SOAK_PARTNER
from the environment (systemd EnvironmentFile=~/.config/entropa-deploy/
soak-traffic.env, gitignored/outside the repo -- never hardcoded here).
"""
import hashlib
import os
import random
import sys
import time

import requests

# Real production endpoints -- the same ones documented in the integration
# guide, not an internal/direct shortcut.
INGEST_API = "https://entropa-ingest-loqc3sut7a-uc.a.run.app"
TRANSPARENCY_API = "https://entropa-transparency-1032137727494.us-central1.run.app"

API_KEY = os.environ.get("ENTROPA_SOAK_API_KEY", "")
PARTNER = os.environ.get("ENTROPA_SOAK_PARTNER", "")

# A large financial-services company's real AI-agent surface area.
AGENTS = [
    "fraud-detection-agent", "kyc-verification-agent", "aml-screening-agent",
    "loan-underwriting-agent", "credit-risk-model", "trade-surveillance-agent",
    "portfolio-rebalancer", "robo-advisor", "wire-transfer-approval",
    "collections-agent", "aml-transaction-monitor", "identity-verification-agent",
]
ACTIONS = ["approved", "denied", "flagged", "escalated", "auto-resolved", "queued", "verified", "rejected"]

# Realistic sustained volume for a large financial company: ~500-2,000
# attestations/hour, weighted toward business hours (UTC-naive -- this is a
# simulation, not modeling a real timezone). The systemd timer fires this
# script roughly every 2 minutes; each run submits a batch sized to hit that
# target rate over the run interval.
RUN_INTERVAL_SECS = 120
TARGET_PER_HOUR_PEAK = 2000
TARGET_PER_HOUR_OFFPEAK = 500


def is_peak_hour():
    # Simple business-hours model: 8am-6pm "peak", rest of day "off-peak".
    hour = time.gmtime().tm_hour
    return 8 <= hour < 18


def batch_size_for_this_run():
    target_per_hour = TARGET_PER_HOUR_PEAK if is_peak_hour() else TARGET_PER_HOUR_OFFPEAK
    expected = target_per_hour * (RUN_INTERVAL_SECS / 3600)
    # Poisson-ish jitter around the expected count so volume looks organic,
    # not a suspiciously exact constant every run.
    return max(1, int(random.gauss(expected, expected * 0.25)))


def make_payload():
    # This is the honest reality of what a real customer submits: a pure hash,
    # nothing else. The agent/action context below exists only so *this
    # simulation* generates varied, realistic-looking source material to hash
    # -- it is never sent to Entropa. A real customer's system keeps its own
    # record of "what actually happened" locally and maps it to this hash on
    # their own side; Entropa only ever proves the hash existed at a given
    # time, immutably, without ever seeing what it represents.
    agent = random.choice(AGENTS)
    action = random.choice(ACTIONS)
    local_only_context = f"{agent}:{action}:{time.time_ns()}:{random.random()}"
    return hashlib.sha256(local_only_context.encode()).hexdigest()


def submit_one():
    payload = make_payload()
    r = requests.post(
        f"{INGEST_API}/api/tx",
        headers={"Authorization": f"Bearer {API_KEY}"},
        json={"payload": payload},
        timeout=15,
    )
    r.raise_for_status()
    return r.json().get("tracking_id")


def read_a_receipt(index):
    r = requests.get(f"{TRANSPARENCY_API}/api/receipt/{PARTNER}/{index}", timeout=15)
    return r.status_code


def main():
    if not API_KEY or not PARTNER:
        print("ERROR: ENTROPA_SOAK_API_KEY / ENTROPA_SOAK_PARTNER not set", file=sys.stderr)
        sys.exit(1)

    n = batch_size_for_this_run()
    submitted = 0
    for _ in range(n):
        time.sleep(random.uniform(0.1, 1.5))
        try:
            submit_one()
            submitted += 1
        except requests.RequestException as e:
            print(f"submit failed: {e}", file=sys.stderr)

    print(f"run complete: {submitted}/{n} submission(s) ({'peak' if is_peak_hour() else 'off-peak'} rate)")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
