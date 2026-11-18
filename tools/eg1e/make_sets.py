#!/usr/bin/env python3
"""EG1e DEV sets (a stage record (not published)). Seed 20261218. Synthetic values only, built from a seeded PRNG at run time. Writes crates/egress/eval_dev_e/ in the runner's layout (eg_secrets.jsonl, eg_clean.jsonl,
four empty files, eg_policy_extra.json, EG_FROZEN_E.json). Families are in the `family` field. Usage: python3 -I tools/eg1e/make_sets.py"""
import hashlib, json, os, random

SEED = 20261218
R = random.Random(SEED)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "crates", "egress", "eval_dev_e")
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
KEYS = ["password", "passwd", "secret", "api_key", "apikey", "token", "client_secret", "access_key", "db_password", "auth_token", "github_token", "API_KEY", "SECRET", "TOKEN", "apiKey", "dbPassword"]
SYNW = "river stone lantern harbor copper willow meadow falcon ember quartz maple cedar anchor beacon canyon delta glacier harvest island juniper".split()

def tok(n=None, alpha=ALNUM):
    n = n or R.choice([24, 28, 32, 36, 40])
    while True:
        t = "".join(R.choice(alpha) for _ in range(n))
        if any(c.isdigit() for c in t) and any(c.isupper() for c in t) and any(c.islower() for c in t):
            return t

SYMS = "#!^*$&@%+=~?/."
def symtok(n=None):
    """A value with symbols at the start, middle or end (round 4: the leaking values started with a symbol or held # ! ^ * $ & -)."""
    n = n or R.randint(12, 48)
    while True:
        chars = [R.choice(ALNUM + "-_" + SYMS * 2) for _ in range(n)]
        pos = R.choice(["start", "middle", "end", "any"])
        if pos == "start": chars[0] = R.choice(SYMS)
        elif pos == "end": chars[-1] = R.choice(SYMS)
        elif pos == "middle": chars[n // 2] = R.choice(SYMS)
        t = "".join(chars)
        if any(c.isdigit() for c in t) and any(c.isupper() for c in t) and any(c.islower() for c in t) and any(c in SYMS for c in t):
            return t

def phrase_value(style):
    w = [R.choice(SYNW) for _ in range(R.randint(3, 5))]
    return {"snake": "_".join(w), "dotted": ".".join(w), "kebab": "-".join(w), "camel": w[0] + "".join(x.title() for x in w[1:]), "words": " ".join(w)}[style]

def row(cls, family, i, body, planted, expect):
    return {"body": body, "body_is_json": False, "class": cls, "expect": expect, "family": family, "id": f"e-{family.split(':')[0]}-{i:04d}", "planted": planted, "tier": "T1"}

PROSE_B = ["Please forward this to the support desk", "Notes from the call", "Here is the snippet I mentioned", "Meeting moved to Thursday", "See below", "As discussed yesterday", "For the record", "Can you check this config"]
PROSE_A = ["Thanks.", "Let me know if that helps.", "Regards, the team.", "That is all."]
def ctx(line): return "\n".join([R.choice(PROSE_B), line, R.choice(PROSE_A)])

# ---------------------------------------------------------------- 1. phrase literals by syntax
def phrase_literal(i):
    style = R.choice(["snake", "dotted", "kebab", "camel"])
    v = phrase_value(style); key = R.choice(KEYS)
    form = i % 10
    quoted_code = [f'{key} = "{v}"', f"{key} = '{v}'", f'const {key} = "{v}";', f'{key} := "{v}"', f'String {key} = "{v}";', f'let {key} = "{v}";', f'$ENV{{{key}}} = "{v}"'][form % 7] if form < 7 else None
    if form < 7:
        fam, body = "phrase_quoted", quoted_code
    elif form == 7:
        fam, body = "phrase_yaml", f"{key}: {v}"
    elif form == 8:
        fam, body = "phrase_json", f'{{"{key}": "{v}"}}'
    else:
        fam, body = "phrase_export", f"export {key.upper()}={v}"
    return row("secrets", fam, i, body if R.random() < 0.5 else ctx(body), [v], "no_leak")

def ini_limit(i):
    v = phrase_value(R.choice(["snake", "dotted"])); key = R.choice(KEYS)
    return row("secrets", "ini_limit", i, f"[auth]\n{key} = {v}", [v], "no_leak")

# ---------------------------------------------------------------- 2. harmless variable assignments (the false-positive side)
VARS = ["db_password", "auth_token", "api_key_value", "secret_from_vault", "tokenValue", "passwordHash", "client_secret_name", "settings.API_KEY", "config.token", "self.secret", "os.environ", "creds.password", "authToken", "dbPasswordRef"]
def harmless(i):
    key = R.choice(KEYS); v = R.choice(VARS)
    forms = [f"{key} = {v}", f"const {key} = {v};", f"let {key} = {v};", f"{key} := {v}", f"{key} = {v}  # from the vault", f"this.{key} = {v};", f"{key} = ({v} or default_{key})", f"{key} = ({v})", f"{key} = ({v}.strip())", f"self.{key} = {v}"]
    body = R.choice(forms)
    return row("clean", "harmless_assign", i, body if R.random() < 0.5 else ctx(body), [], "allow")

# ---------------------------------------------------------------- 3. placeholders and parentheses
PLACE_OK = ["changeme", "changeme-here", "placeholder", "your_password_here", "example", "dummy", "sample", "xxx", "todo", "redacted", "changeme-placeholder", "your_api_key", "xxxxxxxx", "dummy-example", "sample_placeholder", "your_token_xxx"]
def placeholder_ok(i):
    v = R.choice(PLACE_OK); key = R.choice(KEYS)
    return row("clean", "placeholder_ok", i, f'{key} = "{v}"', [], "allow")
def placeholder_literal(i):
    w = R.choice(["changeme", "example", "dummy", "your_token", "sample", "todo"]); k = tok(R.choice([8, 10, 12, 16]))
    v = R.choice([f"{w}-{k}", f"{k}-{w}", f"{w}_{k}", f"{w}{k}"]); key = R.choice(KEYS)
    return row("secrets", "placeholder_literal", i, f'{key} = "{v}"', [k], "no_leak")
REFS = ["x or default", "f()", "cfg.token", "os.getenv('TOKEN') or ''", "a.b.c", "get_token()", "settings.API_KEY", "value", "load_secret(name)", "env['X']"]
def paren_ref(i):
    key = R.choice(KEYS); v = R.choice(REFS)
    return row("clean", "paren_ref", i, R.choice([f"{key} = ({v})", f"{key} = (({v}))", f"{key} = ({v}) if enabled else None", f"{key}: ({v})"]), [], "allow")
def paren_literal(i):
    t = tok(); key = R.choice(KEYS)
    return row("secrets", "paren_literal", i, R.choice([f'{key} = ("{t}")', f'{key} = ("{t}" or "")', f"{key} = ('{t}')"]), [t], "no_leak")

# ---------------------------------------------------------------- 4. hyphen mix, hyphen midline, curl
SEPS = ["-", "-_", "- ", "-.", "_-", ".-", "--"]
SEPS_X = ["-/", "-:", "/-", ":-"]  # separators OUTSIDE the reviewer's shape: reported as their own family (a probe of the limit)
def phrase_forms(t):
    return [f"Authorization: Bearer {t}", f'password={t}!#', f"api_key={t}", f"client_secret={t}-_x", f"token={t}", f"secret: {t}", f'password = "{t}"']
def chop(s, lo, hi, seps):
    out, i = [], 0
    while i < len(s):
        n = R.randint(lo, hi); out.append(s[i:i + n]); i += n
    res = out[0]
    for p in out[1:]: res += R.choice(seps) + p
    return res
def hyphen_mix(i):
    t = tok(R.choice([20, 24, 28]), ALNUM) if i % 2 else symtok(R.choice([18, 22])); p = R.choice(phrase_forms(t))
    body = f"{R.choice(PROSE_B)}: {chop(p, 3, 6, SEPS[:5])}. {R.choice(PROSE_A)}"
    return row("secrets", "hyphen_mix", i, body if i % 3 else chop(p, 3, 6, SEPS[:5]), [t], "no_leak")
def hyphen_mix_x(i):
    t = tok(R.choice([20, 24, 28]), ALNUM); p = R.choice(phrase_forms(t))
    return row("secrets", "hyphen_mix_x", i, ctx(chop(p, 3, 6, SEPS_X + ["-"])), [t], "no_leak")
def hyphen_mix_wide(i):
    t = tok(R.choice([20, 24, 28]), ALNUM) if i % 2 else symtok(R.choice([18, 22])); p = R.choice(phrase_forms(t))
    body = ctx(chop(p, 2, 8, SEPS))
    return row("secrets", "hyphen_mix_wide", i, body, [t], "no_leak")
def hyphen_mid(i):
    t = tok(R.choice([20, 24, 28]), ALNUM); p = R.choice(phrase_forms(t))
    before = " ".join(R.choice(SYNW) for _ in range(R.randint(4, 12))); after = " ".join(R.choice(SYNW) for _ in range(R.randint(2, 6)))
    if i % 2 == 0:
        run = "-".join(p[j:j + g] for g in [R.randint(3, 8)] for j in range(0, len(p), g))
    else:
        run = chop(p, 2, 9, ["-", "_-", "-_", "--"]).replace("_", "-" if R.random() < 0.5 else "_")
    return row("secrets", "hyphen_midline", i, f"{before} {run} {after}", [t], "no_leak")
def curl(i):
    t = tok(R.randint(28, 44), ALNUM + "-_")
    forms = [f'curl -H "Authorization: Bearer {t}" https://x.example/api', f"curl -H 'Authorization: Bearer {t}' https://x.example/api", f'curl https://x.example/api -H "Authorization: Bearer {t}"',
             f'curl --header "Authorization: Bearer {t}" https://x.example/api', f'curl -H"Authorization: Bearer {t}" https://x.example/api', f'wget --header="Authorization: Bearer {t}" https://x.example/api',
             f'curl -s -X POST -H "Content-Type: application/json" -H "Authorization: Bearer {t}" -d \'{{"q":1}}\' https://x.example/api', f'curl -H "authorization: bearer {t}" https://x.example/api',
             f'curl -H "Authorization: Bearer {t}" \\\n  https://x.example/api', f'http GET https://x.example/api "Authorization: Bearer {t}"']
    return row("secrets", "curl", i, forms[i % len(forms)], [t], "no_leak")

def curl_sym(i):
    t = symtok(R.randint(12, 48))
    line = [f'curl -H "Authorization: Bearer {t}" https://x.example:8443/v1/items', f"curl -H 'Authorization: Bearer {t}' https://x.example/api", f'curl https://x.example/api -H "Authorization: Bearer {t}"',
            f'curl --header "Authorization: Bearer {t}" https://x.example/api', f'wget --header="Authorization: Bearer {t}" https://x.example/api', f'Authorization: Bearer {t}', f'curl -u user:{t} https://x.example/api'][i % 7]
    wrap = i % 4
    if wrap == 0: body = f"Found this in the repo:\n```\n{line}\n```\nThanks."
    elif wrap == 1: body = f"Found this in the repo:\n```\n{line}\n```\n"
    elif wrap == 2: body = f"Why does this fail? {line} Let me know what you think."
    else: body = line
    return row("secrets", "curl_sym", i, body, [t], "no_leak")

# ---------------------------------------------------------------- 5. clean controls
def clean_ctl(i):
    k = i % 8
    if k == 0: s = f"Order {R.randint(1000, 9999)}-{R.randint(10, 99)}-{R.randint(100, 999)} ships on 2026-0{R.randint(1, 9)}-1{R.randint(0, 9)}."
    elif k == 1: s = "The well-known long-term plan is end-to-end and state-of-the-art, see https://x.example/a-b-c/d_e_f?x=1-2-3."
    elif k == 2: s = f"Meeting notes: {R.choice(SYNW)}_{R.choice(SYNW)}_{R.choice(SYNW)} and {R.choice(SYNW)}.{R.choice(SYNW)}.{R.choice(SYNW)} are variable names in the script."
    elif k == 3: s = "ids: " + ", ".join("-".join("".join(R.choice("0123456789abcdef") for _ in range(n)) for n in (8, 4, 4, 4, 12)) for _ in range(2))
    elif k == 4: s = "Run: curl -s https://x.example/health and then wget https://x.example/file.tgz; no header needed."
    elif k == 5: s = f"Use the bearer of the note as a witness, the token budget is {R.randint(1, 9)} million, the secret garden opens at nine."
    elif k == 6: s = "Please set password policy to 12 characters and rotate the api key every ninety days; see the runbook."
    else: s = f"The values are {R.randint(1, 9)}-{R.randint(10, 99)}-{R.randint(100, 999)}-{R.randint(1000, 9999)} and a-b-c-d-e-f-g-h."
    return row("clean", "clean_ctl", i, s, [], "allow")

attacks, cleans = [], []
for i in range(900): attacks.append(phrase_literal(i))
for i in range(120): attacks.append(ini_limit(i))
for i in range(300): attacks.append(placeholder_literal(i))
for i in range(300): attacks.append(paren_literal(i))
for i in range(700): attacks.append(hyphen_mix(i))
for i in range(700): attacks.append(hyphen_mix_wide(i))
for i in range(300): attacks.append(hyphen_mix_x(i))
for i in range(800): attacks.append(hyphen_mid(i))
for i in range(300): attacks.append(curl(i))
for i in range(700): attacks.append(curl_sym(i))
for i in range(1600): cleans.append(harmless(i))
for i in range(300): cleans.append(placeholder_ok(i))
for i in range(300): cleans.append(paren_ref(i))
for i in range(800): cleans.append(clean_ctl(i))

def write(name, rows):
    with open(os.path.join(OUT, name), "w") as f:
        for r in rows: f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
os.makedirs(OUT, exist_ok=True)
write("eg_secrets.jsonl", attacks); write("eg_clean.jsonl", cleans)
for n in ("eg_personal.jsonl", "eg_terms.jsonl", "eg_destination.jsonl", "eg_abuse.jsonl"): write(n, [])
with open(os.path.join(OUT, "eg_policy_extra.json"), "w") as f:
    f.write(json.dumps({"marker_key": "dev-marker-key-0001", "markers": [], "terms": []}, indent=1, sort_keys=True) + "\n")
files = sorted(n for n in os.listdir(OUT) if n != "EG_FROZEN_E.json")
fam = {}
for r in attacks + cleans: fam[r["family"].split(":")[0]] = fam.get(r["family"].split(":")[0], 0) + 1
frozen = {"seed": SEED, "files": {n: hashlib.sha256(open(os.path.join(OUT, n), "rb").read()).hexdigest() for n in files}, "counts": {"attacks": len(attacks), "clean": len(cleans), "families": fam}}
with open(os.path.join(OUT, "EG_FROZEN_E.json"), "w") as f: f.write(json.dumps(frozen, indent=1, sort_keys=True) + "\n")
print(frozen["counts"])
