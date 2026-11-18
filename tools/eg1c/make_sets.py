#!/usr/bin/env python3
"""EG1c DEV sets (a stage record (not published)). Seed 20261216. Synthetic tokens only, built from a seeded PRNG at run time.
Writes crates/egress/eval_dev_c/: eg_secrets.jsonl (attacks, expect no_leak), eg_clean.jsonl (expect allow), four empty files the runner expects,
eg_policy_extra.json, EG_FROZEN_C.json (sha256 of every file). Usage: python3 -I tools/eg1c/make_sets.py"""
import hashlib, json, os, random, codecs

SEED = 20261216
rng = random.Random(SEED)
OUT = os.path.join(os.path.dirname(__file__), "..", "..", "crates", "egress", "eval_dev_c")
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def token(n):
    while True:
        t = "".join(rng.choice(ALNUM) for _ in range(n))
        if any(c.isdigit() for c in t) and any(c.isalpha() for c in t) and any(c.isupper() for c in t):
            return t

PHRASES = [
    ("authz_bearer", lambda t: f"Authorization: Bearer {t}"),
    ("bearer", lambda t: f"Bearer {t}"),
    ("password", lambda t: f'password = "{t}"'),
    ("token", lambda t: f'token = "{t}"'),
    ("api_key", lambda t: f'api_key = "{t}"'),
    ("secret", lambda t: f"secret: {t}"),
]
BEFORE = ["Please forward this to the support desk.", "Notes from the call:", "Here is the snippet I mentioned.", "Meeting moved to Thursday.", ""]
AFTER = ["Thanks.", "Let me know if that helps.", "", "Regards, the team."]

def hyphen(s, g):
    return "-".join(s[i:i + g] for i in range(0, len(s), g))

def rot13(s):
    return codecs.encode(s, "rot13")

def wrap(line):
    b, a = rng.choice(BEFORE), rng.choice(AFTER)
    parts = [p for p in (b, line, a) if p]
    return "\n".join(parts)

def attack(i, family, pname, make, sub):
    t = token(rng.choice([24, 28, 32]))
    phrase = make(t)
    if family == "hyphen":
        line = hyphen(phrase, int(sub))
    elif family == "reverse":
        line = phrase[::-1]
    else:
        line = rot13(phrase)
    # half the cases are the disguised phrase alone, half sit on their own line among plain prose
    body = line if i % 2 == 0 else wrap(line)
    return {"body": body, "body_is_json": False, "class": "secrets", "expect": "no_leak", "family": f"{family}:{pname}:{sub}",
            "id": f"c-{family}-{i:04d}", "planted": [t], "tier": "T1"}

attacks = []
i = 0
for family, subs in (("hyphen", ["3", "4", "5", "6", "7", "8"]), ("reverse", ["rev"]), ("rot13", ["r13"])):
    per_family = 360  # at least 300; every phrase at least 150 times is met by 360/6 = 60 per phrase per sub... see below
    n = 0
    # hyphen: 6 phrases x 6 group sizes x 10 = 360; reverse and rot13: 6 phrases x 60 = 360
    reps = 10 if family == "hyphen" else 60
    for pname, make in PHRASES:
        for sub in subs:
            for _ in range(reps):
                attacks.append(attack(i, family, pname, make, sub)); i += 1; n += 1
    assert n == 360, (family, n)

CLEAN_PROSE = [
    "The bearer of the news was the courier from the north office.",
    "Our password policy requires rotation every ninety days.",
    "The token budget for this project is two million.",
    "Please keep the secret garden gate closed after dusk.",
    "An api key is something a service asks you to create in its console.",
    "The meeting notes mention the authorization process for new vendors.",
    "Bearer bonds were issued in the nineteenth century.",
    "Reset your password from the settings page and confirm by email.",
]
CLEAN_CODE = [
    "token = next_token()", "api_key = os.environ[\"API_KEY\"]", "password = \"\"", "secret = load_secret(name)",
    "headers = {\"Authorization\": \"Bearer \" + token}", "password = input(\"password: \")", "token = None",
    "api_key = ${API_KEY}", "secret: <redacted>", "Authorization: Bearer ${TOKEN}", "token = \"short\"", "bearer = get_bearer()",
]
WORDS = "ledger audit budget invoice contract review schedule backup release control ticket network deploy update recovery risk".split()

def sentence(n=9):
    return " ".join(rng.choice(WORDS) for _ in range(n)).capitalize() + "."

def clean(i):
    kind = i % 6
    if kind == 0:
        body = rng.choice(CLEAN_PROSE) + " " + sentence()
    elif kind == 1:
        body = "\n".join([sentence(), rng.choice(CLEAN_CODE), sentence(5)])
    elif kind == 2:  # an ordinary sentence reversed
        body = (rng.choice(CLEAN_PROSE) + " " + sentence())[::-1]
    elif kind == 3:  # an ordinary sentence rot13'd
        body = rot13(rng.choice(CLEAN_PROSE) + " " + sentence())
    elif kind == 4:  # hyphenated ordinary text, part numbers in groups of four
        body = "Part numbers: " + ", ".join("-".join("".join(rng.choice("ABCDEF0123456789") for _ in range(4)) for _ in range(3)) for _ in range(4))
    else:  # an ordinary sentence cut by hyphens every g characters
        body = hyphen(sentence(8), rng.choice([3, 4, 5, 6, 7, 8]))
    return {"body": body, "body_is_json": False, "class": "clean", "expect": "allow", "family": f"clean:{kind}", "id": f"c-clean-{i:04d}", "planted": [], "tier": "T1"}

cleans = [clean(i) for i in range(600)]

def write(name, rows):
    with open(os.path.join(OUT, name), "w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")

os.makedirs(OUT, exist_ok=True)
write("eg_secrets.jsonl", attacks)
write("eg_clean.jsonl", cleans)
for name in ("eg_personal.jsonl", "eg_terms.jsonl", "eg_destination.jsonl", "eg_abuse.jsonl"):
    write(name, [])
with open(os.path.join(OUT, "eg_policy_extra.json"), "w") as f:
    f.write(json.dumps({"marker_key": "dev-marker-key-0001", "markers": [], "terms": []}, indent=1, sort_keys=True) + "\n")
files = sorted(n for n in os.listdir(OUT) if n != "EG_FROZEN_C.json")
frozen = {"seed": SEED, "files": {n: hashlib.sha256(open(os.path.join(OUT, n), "rb").read()).hexdigest() for n in files},
          "counts": {"attacks": len(attacks), "attacks_per_family": 360, "clean": len(cleans)}}
with open(os.path.join(OUT, "EG_FROZEN_C.json"), "w") as f:
    f.write(json.dumps(frozen, indent=1, sort_keys=True) + "\n")
print(frozen["counts"])
