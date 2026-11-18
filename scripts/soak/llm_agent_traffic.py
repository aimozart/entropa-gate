#!/usr/bin/env python3
"""Local-LLM-driven multi-agent traffic generator for the pre-production
soak. Runs as a persistent daemon (loads the model once, not per-invocation)
simulating several distinct AI agents across several distinct simulated
companies, each generating its own short decision descriptor via a local LLM
running on the RTX 3060 -- the descriptor becomes the submission's optional
`label` field; `payload` stays a plain hash, exactly matching real customer
behavior (Entropa never sees the underlying decision content).

Multiple companies round-robin through ONE loaded model rather than each
running its own process -- the GPU has 12GB VRAM and a single instance of
this model already uses ~7GB, so N separate processes would not fit. This
also happens to be a real test of the elastic write-scaling shipped
2026-08-27: several distinct customer trees getting genuinely concurrent
traffic is exactly the scenario per-customer Pub/Sub ordering keys exist for.

Run: /home/sbaker/llm_course/llm_course_workspace/.venv/bin/python
     scripts/soak/llm_agent_traffic.py
Reads one API key env var per company (see COMPANIES below), never
hardcoded here.
"""
import hashlib
import itertools
import os
import random
import time

import requests
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

INGEST_API = "https://entropa-ingest-loqc3sut7a-uc.a.run.app"
MODEL_NAME = "Qwen/Qwen2.5-3B-Instruct"

# One entry per simulated company -- distinct industry, distinct agent
# personas, its own API key (env var, never hardcoded). Add a new company by
# adding an entry here and setting its env var; nothing else changes.
COMPANIES = [
    {
        "name": "pinnacle-financial",
        "api_key_env": "ENTROPA_SOAK_API_KEY",
        "agents": {
            "fraud-detection-agent": "You are a fraud-detection AI at a large bank. Describe ONE realistic fraud-review decision you just made.",
            "kyc-verification-agent": "You are a KYC/identity-verification AI at a large bank. Describe ONE realistic customer-verification decision you just made.",
            "aml-screening-agent": "You are an AML transaction-screening AI at a large bank. Describe ONE realistic anti-money-laundering screening decision you just made.",
            "loan-underwriting-agent": "You are a loan-underwriting AI at a large bank. Describe ONE realistic loan decision you just made.",
            "trade-surveillance-agent": "You are a trade-surveillance AI at an investment firm. Describe ONE realistic trading-compliance decision you just made.",
            "portfolio-rebalancer": "You are a robo-advisor portfolio-rebalancing AI. Describe ONE realistic portfolio adjustment you just made for a client.",
            "wire-transfer-approval": "You are a wire-transfer-approval AI at a bank. Describe ONE realistic wire-transfer decision you just made.",
            "collections-agent": "You are a debt-collections AI at a financial company. Describe ONE realistic collections decision you just made.",
        },
    },
    {
        "name": "duff-beer",
        "api_key_env": "ENTROPA_SOAK_API_KEY_DUFF",
        "agents": {
            "quality-control-agent": "You are a brewery quality-control AI. Describe ONE realistic batch quality-check decision you just made.",
            "supply-chain-agent": "You are a raw-materials supply-chain AI for a brewery. Describe ONE realistic sourcing decision you just made.",
            "distribution-routing-agent": "You are a beverage-distribution routing AI. Describe ONE realistic delivery-routing decision you just made.",
            "inventory-forecasting-agent": "You are an inventory-demand-forecasting AI for a brewery. Describe ONE realistic stocking decision you just made.",
            "marketing-campaign-agent": "You are a marketing-campaign-targeting AI for a beverage brand. Describe ONE realistic campaign decision you just made.",
        },
    },
    {
        "name": "the-dude-co",
        "api_key_env": "ENTROPA_SOAK_API_KEY_DUDE",
        "agents": {
            "order-fulfillment-agent": "You are an order-fulfillment AI for a lifestyle-goods retailer. Describe ONE realistic fulfillment decision you just made.",
            "customer-support-agent": "You are a customer-support triage AI. Describe ONE realistic support-ticket decision you just made.",
            "content-moderation-agent": "You are a content-moderation AI for a community platform. Describe ONE realistic moderation decision you just made.",
            "loyalty-rewards-agent": "You are a loyalty-program rewards AI. Describe ONE realistic rewards decision you just made.",
            "review-authenticity-agent": "You are a review-authenticity-detection AI. Describe ONE realistic flagged-review decision you just made.",
        },
    },
    {
        "name": "phx-games",
        "api_key_env": "ENTROPA_SOAK_API_KEY_PHXGAMES",
        "agents": {
            "matchmaking-agent": "You are a multiplayer-matchmaking AI for an online game. Describe ONE realistic matchmaking decision you just made.",
            "anti-cheat-agent": "You are an anti-cheat-detection AI for an online game. Describe ONE realistic flagged-player decision you just made.",
            "in-game-economy-agent": "You are an in-game-economy balancing AI. Describe ONE realistic economy-adjustment decision you just made.",
            "content-moderation-agent": "You are a chat-moderation AI for an online game. Describe ONE realistic moderation decision you just made.",
            "player-support-agent": "You are a player-support triage AI for a game studio. Describe ONE realistic support decision you just made.",
        },
    },
    {
        "name": "acme-corp",
        "api_key_env": "ENTROPA_SOAK_API_KEY_ACME",
        "agents": {
            "access-provisioning-agent": "You are an employee-access-provisioning AI for a SaaS company. Describe ONE realistic access-grant decision you just made.",
            "incident-triage-agent": "You are a production-incident-triage AI. Describe ONE realistic incident-severity decision you just made.",
            "vendor-risk-agent": "You are a third-party-vendor-risk-assessment AI. Describe ONE realistic vendor-approval decision you just made.",
            "deployment-gate-agent": "You are a CI/CD deployment-gating AI. Describe ONE realistic deploy-approval decision you just made.",
            "expense-approval-agent": "You are an employee-expense-approval AI. Describe ONE realistic expense decision you just made.",
        },
    },
]

FORMAT_INSTRUCTION = (
    "Reply with ONLY a single line, 6-14 words, in the exact format "
    "'action:brief-reason' (e.g. 'approved:income-verified-debt-ratio-28pct'). "
    "No other text."
)

BATCH_SIZE = 6
SLEEP_BETWEEN_BATCHES_SECS = 20


def active_companies():
    """Only companies whose API key env var is actually set -- lets new
    companies be added to COMPANIES above ahead of their real signup
    completing, without the daemon erroring out at startup."""
    active = [c for c in COMPANIES if os.environ.get(c["api_key_env"], "")]
    if not active:
        raise SystemExit(
            "No company API keys set -- need at least ENTROPA_SOAK_API_KEY"
        )
    return active


def load_model():
    print(f"Loading {MODEL_NAME}...", flush=True)
    tok = AutoTokenizer.from_pretrained(MODEL_NAME)
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_NAME, torch_dtype=torch.float16, device_map="cuda:0"
    )
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    print("Model loaded.", flush=True)
    return tok, model


def generate_batch(tok, model, agents, agent_names):
    prompts = []
    for agent in agent_names:
        messages = [
            {"role": "system", "content": agents[agent]},
            {"role": "user", "content": FORMAT_INSTRUCTION},
        ]
        prompts.append(tok.apply_chat_template(messages, tokenize=False, add_generation_prompt=True))

    tok.padding_side = "left"
    inputs = tok(prompts, return_tensors="pt", padding=True).to("cuda:0")
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=24,
            do_sample=True,
            temperature=0.9,
            pad_token_id=tok.pad_token_id,
        )
    results = []
    for i in range(len(agent_names)):
        generated = out[i][inputs["input_ids"].shape[1]:]
        text = tok.decode(generated, skip_special_tokens=True).strip()
        # Keep only the first line, guard against a model ignoring the
        # single-line instruction.
        text = text.splitlines()[0][:120] if text else "queued:pending-review"
        results.append(text)
    return results


def submit(api_key, partner, agent, descriptor):
    label = f"{agent}:{descriptor}"
    seed = f"{partner}:{label}:{time.time_ns()}:{random.random()}"
    payload = hashlib.sha256(seed.encode()).hexdigest()
    r = requests.post(
        f"{INGEST_API}/api/tx",
        headers={"Authorization": f"Bearer {api_key}"},
        json={"payload": payload, "label": label},
        timeout=15,
    )
    r.raise_for_status()
    return label


def main():
    companies = active_companies()
    print(
        f"Running {len(companies)} compan{'y' if len(companies) == 1 else 'ies'}: "
        + ", ".join(c["name"] for c in companies),
        flush=True,
    )

    tok, model = load_model()

    # True round-robin, not random.choice -- keeps growth even across every
    # company instead of leaving it to chance (random selection produced a
    # real, visibly lopsided distribution: 36+ batches for one company vs 6
    # for another, over the same run).
    for company in itertools.cycle(companies):
        api_key = os.environ[company["api_key_env"]]
        agent_names = list(company["agents"].keys())
        batch_agents = [random.choice(agent_names) for _ in range(BATCH_SIZE)]

        t0 = time.time()
        try:
            descriptors = generate_batch(tok, model, company["agents"], batch_agents)
        except Exception as e:
            print(f"[{company['name']}] generation failed: {e}", flush=True)
            time.sleep(5)
            continue
        gen_time = time.time() - t0

        submitted = 0
        for agent, descriptor in zip(batch_agents, descriptors):
            try:
                label = submit(api_key, company["name"], agent, descriptor)
                submitted += 1
                print(f"[{company['name']}] submitted: {label}", flush=True)
            except requests.RequestException as e:
                print(f"[{company['name']}] submit failed: {e}", flush=True)

        print(
            f"[{company['name']}] batch complete: {submitted}/{len(batch_agents)} "
            f"submitted, generation took {gen_time:.1f}s",
            flush=True,
        )
        time.sleep(SLEEP_BETWEEN_BATCHES_SECS)


if __name__ == "__main__":
    main()
