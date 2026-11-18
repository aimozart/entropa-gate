#!/usr/bin/env python3
"""EG1d DEV sets (a stage record (not published)). Seed 20261217. Synthetic values only, built from a seeded PRNG at run time. Writes crates/egress/eval_dev_d/ in the runner's layout:
eg_secrets.jsonl (attacks, expect no_leak), eg_clean.jsonl (expect allow), four empty files, eg_policy_extra.json, EG_FROZEN_D.json. Families are in the `family` field.
Usage: python3 -I tools/eg1d/make_sets.py"""
import codecs, hashlib, json, os, random

SEED = 20261217
R = random.Random(SEED)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "crates", "egress", "eval_dev_d")
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
KEYS = ["password", "passwd", "pwd", "secret", "api_key", "apikey", "token", "client_secret", "access_key", "db_password", "auth_token", "github_token", "API_KEY", "SECRET", "TOKEN", "apiKey", "dbPassword", "access_token"]

def tok(n=None):
    n = n or R.choice([16, 20, 24, 28, 32])
    while True:
        t = "".join(R.choice(ALNUM) for _ in range(n))
        if any(c.isdigit() for c in t) and any(c.isupper() for c in t) and any(c.islower() for c in t):
            return t

def rot13(s): return codecs.encode(s, "rot13")
def hyphen(s, g): return "-".join(s[i:i + g] for i in range(0, len(s), g))
def irregular(s):
    out, i = [], 0
    while i < len(s):
        g = R.randint(2, 10); out.append(s[i:i + g]); i += g
    return "-".join(out)

PROSE = ["Please forward this to the support desk.", "Notes from the call:", "Here is the snippet I mentioned.", "Meeting moved to Thursday.", "See below.", "As discussed yesterday,", "For the record:", "Can you check this config?"]
TAIL = ["Thanks.", "Let me know if that helps.", "", "Regards, the team.", "That is all."]
def ctx(line):
    return "\n".join(p for p in (R.choice(PROSE), line, R.choice(TAIL)) if p)

# ---------------------------------------------------------------- assign_clean
REFS = {
 "python": ['os.environ["{E}"]', 'os.getenv("{E}")', 'os.environ.get("{E}", "")', "getpass.getpass()", "get_{k}()", "self.refresh_{k}()", 'config.get("auth", "{k}")', "load_secret(name)", 'secrets_client.get_secret_value(SecretId=sid)["SecretString"]', "vault.read(path)", "settings.{E}", "args.{k}", 'request.headers.get("Authorization")', 'input("Enter value: ")', 'keyring.get_password("svc", user)', "None", '""'],
 "js": ["process.env.{E};", 'process.env["{E}"];', "await get_{k}();", "config.{k};", 'localStorage.getItem("{k}");', "req.body.{k};", "useAuth().{k};", "window.__CFG__.{k};"],
 "go": ['os.Getenv("{E}")', 'viper.GetString("{k}")', "cfg.{K}", 'flag.String("{k}", "", "set via flag")', "secretStore.Fetch(ctx, id)"],
 "java": ['System.getenv("{E}");', 'env.getProperty("app.{k}");', "secretsManager.getSecret(id);", "request.getParameter(name);", "this.{k};"],
 "rust": ['std::env::var("{E}")?;', "config.{k}.clone();", 'std::env::var("{E}").unwrap_or_default();', "load_from_keyring()?;", "args.{k}.take();"],
 "shell": ["$(cat /run/secrets/{k})", '"${{{E}}}"', "$(pass show db)", "$({k}_helper --read)", "${{{E}:?missing}}", "`vault read -field=value secret/app`"],
 "yaml": ["${{{E}}}", '"{{{{ vault_{k} }}}}"', "!secret {k}", "<redacted>", '""', "null", "{{ lookup('env', '{E}') }}", "ref+vault://secret/app#{k}"],
 "terraform": ["var.{k}", "data.vault_generic_secret.s.data[\"{k}\"]", "aws_secretsmanager_secret.main.id", "random_password.main.result", "module.auth.{k}"],
 "docker": ["${{{E}}}", "$({k})"],
}
def clean_assign(i):
    lang = R.choice(list(REFS))
    key = R.choice(KEYS)
    k = key.lower().replace("-", "_")
    E = key.upper()
    rhs = R.choice(REFS[lang]).format(E=E, k=k, K=k.title().replace("_", ""))
    line = {
     "python": f"{key} = {rhs}", "js": f"const {key} = {rhs}", "go": f"{key} := {rhs}", "java": f"String {key} = {rhs}",
     "rust": f"let {key} = {rhs}", "shell": f"{key.upper()}={rhs}", "yaml": f"{key}: {rhs}", "terraform": f"{key} = {rhs}",
     "docker": f"ENV {key.upper()}={rhs}",
    }[lang]
    if R.random() < 0.15:
        line = "export " + line if lang == "shell" else line
    body = ctx(line) if R.random() < 0.6 else line
    return {"body": body, "body_is_json": False, "class": "clean", "expect": "allow", "family": f"assign_clean:{lang}", "id": f"d-aclean-{i:04d}", "planted": [], "tier": "T1"}
PROSE_CLEAN = ["Store the password in the vault and never in code.", "Rotate the api key every ninety days.", "The token budget is reviewed monthly.", "A secret manager keeps the client secret out of the repository.", "Use a service account instead of a shared password.", "The bearer of this note is authorised to collect the parcel."]

# ---------------------------------------------------------------- assign_literal
def literal_line(t, i):
    key = R.choice(KEYS); form = i % 13
    return [
     f'{key} = "{t}"', f"{key} = '{t}'", f"{key} = {t}", f'{{"{key}": "{t}"}}', f"{key}: {t}", f"export {key.upper()}={t}",
     f"https://svc.example.invalid/v1/items?{key}={t}&limit=5", f'const {key} = "{t}";', f'String {key} = "{t}";', f'let {key} = "{t}";',
     f"{key} := \"{t}\"", f"ENV {key.upper()}={t}", f'get_credentials("{t}")  # {key}',
    ][form], form
def attack_literal(i, disguise=None):
    t = tok(); line, form = literal_line(t, i)
    fam = "plain"
    if disguise == "hyphen": line = hyphen(line, R.randint(3, 8)); fam = "hyphen"
    elif disguise == "reverse": line = line[::-1]; fam = "reverse"
    elif disguise == "rot13": line = rot13(line); fam = "rot13"
    body = line if R.random() < 0.5 else ctx(line)
    return {"body": body, "body_is_json": False, "class": "secrets", "expect": "no_leak", "family": f"assign_literal:{fam}:{form}", "id": f"d-alit-{i:04d}", "planted": [t], "tier": "T1"}

# ---------------------------------------------------------------- hyphen_mid
PHRASES = [lambda t: f"Authorization: Bearer {t}", lambda t: f"Bearer {t}", lambda t: f'password = "{t}"', lambda t: f'token = "{t}"', lambda t: f'api_key = "{t}"', lambda t: f"secret: {t}"]
LEAD = ["see this:", "here it is", "the line is", "I pasted", "copy from the ticket and use", "ok so", "config follows:"]
def mid_attack(i, kind):
    t = tok(R.choice([24, 28, 32])); p = R.choice(PHRASES)(t)
    lead = R.choice(LEAD)
    if kind == "regular_mid":
        line = f"{lead} {hyphen(p, R.randint(2, 10))}"
    elif kind == "irregular":
        line = f"{lead} {irregular(p)}" if i % 3 else irregular(p)
    elif kind == "compound":
        c = i % 4
        line = [rot13(p[::-1]), hyphen(p[::-1], R.randint(3, 8)), hyphen(rot13(p), R.randint(3, 8)), rot13(hyphen(p, R.randint(3, 8)))][c]
    else:  # split keyword
        word = R.choice(["Bearer", "password", "api_key", "token", "secret", "Authorization"])
        mid = R.randint(1, len(word) - 1); sep = R.choice([" ", "​", "‍", "­"])
        line = p.replace(word, word[:mid] + sep + word[mid:], 1)
    return {"body": line, "body_is_json": False, "class": "secrets", "expect": "no_leak", "family": f"hyphen_mid:{kind}", "id": f"d-mid-{kind}-{i:04d}", "planted": [t], "tier": "T1"}

# ---------------------------------------------------------------- clean_hyphen
def hex_(n): return "".join(R.choice("0123456789abcdef") for _ in range(n))
def clean_hy(i):
    k = i % 9
    if k == 0: s = "Part numbers: " + ", ".join("-".join("".join(R.choice("ABCDEF0123456789") for _ in range(R.randint(2, 6))) for _ in range(3)) for _ in range(4))
    elif k == 1: s = f"Call the desk on 555-01{R.randint(0, 99):02d} or 555-01{R.randint(0, 99):02d}."
    elif k == 2: s = f"Dates: 2026-{R.randint(1, 12):02d}-{R.randint(1, 28):02d} to 2026-{R.randint(1, 12):02d}-{R.randint(1, 28):02d}."
    elif k == 3: s = "A well-known, state-of-the-art, end-to-end, long-term, open-source, read-only, multi-step plan."
    elif k == 4: s = f"id {hex_(8)}-{hex_(4)}-{hex_(4)}-{hex_(4)}-{hex_(12)} was created"
    elif k == 5: g = R.randint(2, 10); s = "Product code " + "-".join("".join(R.choice("ABCDEFGHJK23456789") for _ in range(g)) for _ in range(R.randint(3, 6)))
    elif k == 6: s = f"See pages {R.randint(1, 90)}-{R.randint(91, 400)} and figures {R.randint(1, 9)}-{R.randint(10, 30)}."
    elif k == 7: s = "SKU " + "-".join(R.choice(["AB", "CD", "EF", "GH"]) + str(R.randint(100, 999)) for _ in range(R.randint(3, 6))) + " ships Monday."
    else: s = hyphen(" ".join(R.choice("ledger audit budget invoice contract review schedule backup".split()) for _ in range(5)), R.choice([2, 3, 4, 7, 9, 10]))
    return {"body": s if i % 2 else ctx(s), "body_is_json": False, "class": "clean", "expect": "allow", "family": f"clean_hyphen:{k}", "id": f"d-chy-{i:04d}", "planted": [], "tier": "T1"}

# ---------------------------------------------------------------- card
def luhn_ok(d):
    s = 0
    for i, c in enumerate(reversed(d)):
        n = int(c)
        if i % 2 == 1:
            n *= 2
            if n > 9: n -= 9
        s += n
    return s % 10 == 0
def card_valid():
    prefix = R.choice(["400000", "555555", "510510", "601111"])
    body = prefix + "".join(R.choice("0123456789") for _ in range(9))
    for c in "0123456789":
        if luhn_ok(body + c): return body + c
def number_bad():
    while True:
        d = "".join(R.choice("0123456789") for _ in range(16))
        if not luhn_ok(d): return d
LAYOUTS = [
 lambda d: d, lambda d: " ".join(d[i:i+4] for i in range(0, 16, 4)), lambda d: "-".join(d[i:i+4] for i in range(0, 16, 4)),
 lambda d: f"Invoice no. {d} was paid.", lambda d: f"Order #{d}", lambda d: f"| ref | {d} | open |", lambda d: f"INV{d}", lambda d: f"id={d};status=ok",
 lambda d: f"{d[:8]} {d[8:]}", lambda d: f"Please quote {d} in your reply.", lambda d: f"{d},{R.randint(10, 99)},OK", lambda d: f"ticket {d[:4]}-{d[4:8]}-{d[8:12]}-{d[12:]} closed",
]
def card_neg(i):
    body = LAYOUTS[i % 12](number_bad())
    return {"body": body, "body_is_json": False, "class": "clean", "expect": "allow", "family": f"card_neg:{i % 12}", "id": f"d-cneg-{i:04d}", "planted": [], "tier": "T1"}
def card_pos(i):
    d = card_valid(); lay = i % 12
    body = LAYOUTS[lay](d)
    if i % 5 == 4: body = body[::-1]
    return {"body": body, "body_is_json": False, "class": "secrets", "expect": "no_leak", "family": f"card_pos:{lay}", "id": f"d-cpos-{i:04d}", "planted": [d], "tier": "T1"}

attacks, cleans = [], []
for i in range(900): attacks.append(attack_literal(i))
for i in range(900, 1050): attacks.append(attack_literal(i, ["hyphen", "reverse", "rot13"][i % 3]))
for kind in ("regular_mid", "irregular", "compound", "split_keyword"):
    for i in range(320): attacks.append(mid_attack(i, kind))
for i in range(300): attacks.append(card_pos(i))
for i in range(1300): cleans.append(clean_assign(i))
for i in range(60): cleans.append({"body": R.choice(PROSE_CLEAN), "body_is_json": False, "class": "clean", "expect": "allow", "family": "assign_clean:prose", "id": f"d-aprose-{i:03d}", "planted": [], "tier": "T1"})
for i in range(600): cleans.append(clean_hy(i))
for i in range(300): cleans.append(card_neg(i))

def write(name, rows):
    with open(os.path.join(OUT, name), "w") as f:
        for r in rows: f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
os.makedirs(OUT, exist_ok=True)
write("eg_secrets.jsonl", attacks); write("eg_clean.jsonl", cleans)
for n in ("eg_personal.jsonl", "eg_terms.jsonl", "eg_destination.jsonl", "eg_abuse.jsonl"): write(n, [])
with open(os.path.join(OUT, "eg_policy_extra.json"), "w") as f:
    f.write(json.dumps({"marker_key": "dev-marker-key-0001", "markers": [], "terms": []}, indent=1, sort_keys=True) + "\n")
files = sorted(n for n in os.listdir(OUT) if n != "EG_FROZEN_D.json")
fam = {}
for r in attacks + cleans: fam[r["family"].split(":")[0]] = fam.get(r["family"].split(":")[0], 0) + 1
frozen = {"seed": SEED, "files": {n: hashlib.sha256(open(os.path.join(OUT, n), "rb").read()).hexdigest() for n in files}, "counts": {"attacks": len(attacks), "clean": len(cleans), "families": fam}}
with open(os.path.join(OUT, "EG_FROZEN_D.json"), "w") as f: f.write(json.dumps(frozen, indent=1, sort_keys=True) + "\n")
print(frozen["counts"])
