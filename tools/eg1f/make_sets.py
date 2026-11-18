#!/usr/bin/env python3
"""EG1f DEV sets (a stage record (not published)). Seed 20261226. Synthetic values only, built from a seeded PRNG at run time; digit runs are capped at 6 so no value can look like a card number or an
identifier (P0). Families come from the round-5 failure families (languages and syntaxes, value shapes, separator chops, harmless assignments). Writes crates/egress/eval_dev_f/
(eg_secrets.jsonl, eg_clean.jsonl, eg_policy_extra.json, EG_FROZEN_F.json). Usage: python3 -I tools/eg1f/make_sets.py"""
import hashlib, json, os, random, re

SEED = 20261226
R = random.Random(SEED)
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "crates", "egress", "eval_dev_f")
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
SYM = "#!^*$&@%+=~?"
WORDS = "river stone lantern harbor copper willow meadow falcon ember quartz maple cedar anchor beacon canyon delta glacier harvest island juniper".split()
KEYS = ["password", "passwd", "secret", "api_key", "apikey", "token", "client_secret", "secret_key", "access_key", "auth_token", "db_password", "private_key"]

def capped(t):
    return not re.search(r"\d{7,}", t)

def shape(kind):
    while True:
        w = [R.choice(WORDS) for _ in range(R.randint(3, 4))]
        if kind == "alnum": v = "".join(R.choice(ALNUM) for _ in range(R.choice([20, 24, 28, 32])))
        elif kind == "camel": v = w[0] + "".join(x.title() for x in w[1:]) + str(R.randint(10, 99))
        elif kind == "dash": v = "-".join(w) + "-" + str(R.randint(10, 999))
        elif kind == "dot": v = ".".join(w) + "." + str(R.randint(10, 999))
        elif kind == "snake": v = "_".join(w) + "_" + str(R.randint(10, 999))
        elif kind == "mixed": v = "".join(R.choice(ALNUM + "-_") for _ in range(R.randint(14, 30)))
        elif kind == "rand": v = "".join(R.choice(ALNUM + SYM) for _ in range(R.randint(14, 30)))
        elif kind == "spaced": v = " ".join(w) + " " + R.choice(SYM) + str(R.randint(10, 99))
        else: raise ValueError(kind)
        if capped(v) and (kind in ("camel", "dash", "dot", "snake", "spaced") or (any(c.isdigit() for c in v) and any(c.isalpha() for c in v))):
            return v

SHAPES = ["alnum", "camel", "dash", "dot", "mixed", "rand", "snake", "spaced"]

def qs(v):  # a value that is safe inside a double-quoted string template (no double quote or backslash)
    return v.replace('"', "").replace("\\", "")

# language/syntax templates: (family, template using {k} lower key, {K} upper key, {v} value); the value shape decides quoting problems
LANGS = [
    ("bash", "export {K}='{v}'"), ("cli_flag", "mytool --{k} {v}"), ("cli_flag2", 'mytool --{k} "{v}"'), ("csharp", 'string {k} = "{v}";'),
    ("curl_hdr", 'curl -H "X-Api-Key: {v}" https://api.example.test/v1'), ("curl_hdr_sq", "curl -H 'Authorization: Token {v}' https://api.example.test/v1"),
    ("docker_e", "docker run -e {K}={v} image:1"), ("hdr_auth_tok", "Authorization: Token {v}"), ("hdr_key", "X-API-Key: {v}"),
    ("json", '{{"{k}": "{v}"}}'), ("kotlin", 'val {k} = "{v}"'), ("lua", 'local {k} = "{v}"'), ("php", '${k} = "{v}";'), ("php_arr", "'{k}' => '{v}',"),
    ("props", "db.{k}={v}"), ("ps", '${k} = "{v}"'), ("ps_secure", '$p = ConvertTo-SecureString "{v}" -AsPlainText -Force'), ("ruby", '{k} = "{v}"'),
    ("ruby_env", "ENV['{K}'] = \"{v}\""), ("sql_ident", "CREATE USER app_user IDENTIFIED BY '{v}';"), ("sql_pw", "ALTER USER app_user PASSWORD '{v}';"),
    ("swift", 'let {k} = "{v}"'), ("tf", 'variable "{k}" {{ default = "{v}" }}'), ("toml", '{k} = "{v}"'), ("wget", "wget --password={v} https://files.example.test/a"),
    ("xml", "<{k}>{v}</{k}>"), ("yaml", '{k}: "{v}"'), ("go", '{k} := "{v}"'), ("java", 'String {k} = "{v}";'), ("rust", 'let {k} = "{v}";'), ("env_file", "{K}={v}"),
]
PROSE_B = ["Please forward this to the support desk", "Notes from the call", "Here is the snippet I mentioned", "Meeting moved to Thursday", "See below", "Can you check this config"]
PROSE_A = ["Thanks.", "Let me know if that helps.", "Regards, the team.", "That is all."]
def ctx(line): return "\n".join([R.choice(PROSE_B), line, R.choice(PROSE_A)])

def row(cls, family, i, body, planted, expect):
    return {"body": body, "body_is_json": False, "class": cls, "expect": expect, "family": family, "id": f"f-{family.split(':')[0]}-{i:04d}", "planted": planted, "tier": "T1"}

secrets, clean = [], []
n = 0
# 1. language literals x value shapes (3 each)
for lang, tpl in LANGS:
    for sh in SHAPES:
        for rep in range(3):
            key = R.choice(KEYS); v = shape(sh)
            if lang in ("cli_flag", "docker_e", "props", "wget", "env_file", "bash") and sh in ("spaced",):
                v = v.replace(" ", "_") if lang in ("docker_e", "props", "wget", "env_file") else v
            vv = qs(v)
            line = tpl.format(k=key, K=key.upper(), v=vv)
            body = line if R.random() < 0.5 else ctx(line)
            secrets.append(row("secrets", f"lit:{lang}:{sh}", n, body, [vv], "no_leak")); n += 1
# 2. keyword chopped by separators, with value (mid-line and mixed with prose)
SEPS = {"plain": ["-"], "old": ["-", "_"], "dotdash": [".-", "-."], "slash": ["/", "/-", "-/"], "space": ["- ", " -", " "], "colon": [":", "-:", ":-"]}
CHOP_KEYS = ["password", "api_key", "client_secret", "secret_key", "token", "Bearer"]
def chop(word, seps):
    out, i = "", 0
    while i < len(word):
        step = R.randint(2, 4); out += word[i:i + step]; i += step
        if i < len(word): out += R.choice(seps)
    return out
for sepname, seps in SEPS.items():
    for pos in ("hmid", "hmix"):
        for key in CHOP_KEYS:
            for rep in range(3):
                v = shape(R.choice(["alnum", "mixed", "rand"]))
                v = qs(v)
                kw = chop(key, seps)
                line = f"{kw}={v}" if key != "Bearer" else f"Authorization: {chop('Bearer', seps)} {v}"
                body = ctx(line) if pos == "hmid" else f"{R.choice(PROSE_B)} {line} {R.choice(PROSE_A)}"
                secrets.append(row("secrets", f"{pos}:{sepname}", n, body, [v], "no_leak")); n += 1
# 3. slash and colon separated KEY NAMES (path-like or namespaced keys)
for i in range(120):
    key = R.choice(KEYS); v = qs(shape(R.choice(SHAPES)))
    ns = R.choice(["db", "app", "service/auth", "prod:db", "cfg", "vault/kv"])
    sep = R.choice(["/", ":", "."])
    fmt = R.choice(["{ns}{sep}{k}: {v}", "{ns}{sep}{k}={v}", '{ns}{sep}{k} = "{v}"', "{ns}{sep}{K}: '{v}'"])
    line = fmt.format(ns=ns, sep=sep, k=key, K=key.upper(), v=v)
    secrets.append(row("secrets", "nskey", n, line if R.random() < 0.5 else ctx(line), [v], "no_leak")); n += 1

# clean (must be allowed): harmless assignments, placeholders, prose with the words
m = 0
def cl(fam, body):
    global m
    clean.append(row("clean", fam, m, body, [], "allow")); m += 1
PS_REFS = ["Read-Host -AsSecureString", "$env:DB_PASSWORD", "Get-Secret -Name ProdDb -AsPlainText", "$config.ApiKey", "(Get-Credential).Password", "$args[0]", "Read-Host 'Enter password' -AsSecureString", "$Secret:Prod"]
PHP_REFS = ["getenv('DB_PASSWORD')", "$_ENV['TOKEN']", "config('app.secret')", "$request->input('password')", "env('API_KEY')", "$this->secret", "getenv('X') ?: ''", "$_POST['password']"]
for i in range(110):
    k = R.choice(["password", "token", "apiKey", "secret", "clientSecret", "dbPassword"])
    cl("ps_assign", f"${k} = {R.choice(PS_REFS)}")
for i in range(110):
    k = R.choice(["password", "token", "api_key", "secret", "client_secret", "db_password"])
    cl("php_assign", f"${k} = {R.choice(PHP_REFS)};")
PH = ["changeme", "your-password-here", "<your-api-key>", "xxxxxxxx", "********", "${SECRET}", "{{ token }}", "REPLACE_ME", "TODO", "null", "None", "undefined", "<password>", "[REDACTED]", ""]
for i in range(130):
    k = R.choice(KEYS); ph = R.choice(PH)
    cl("placeholder", R.choice([f'{k} = "{ph}"', f"{k}: {ph}", f"{k.upper()}={ph}", f"'{k}' => '{ph}',", f"<{k}>{ph}</{k}>"]))
for i in range(80):
    k = R.choice(["db.password", "secret.key", "api.token", "auth.secret"])
    cl("props", R.choice([f"{k}=", f"{k}=${{DB_PASS}}", f"{k}=%(secret)s", f"{k}=${{env:SECRET_{i}}}", f"# {k}=set in the vault"]))
PROSE = ["The password policy requires at least twelve characters.", "API key rotation happens every ninety days.", "Token expired, please log in again.", "Keep the secret key out of the repository.",
         "Never share your password with anyone.", "The access token lifetime is one hour.", "Use a password manager for your credentials.", "A client secret is shown only once at creation.",
         "Bearer tokens must be sent over HTTPS.", "Reset your password from the account page.", "Where is the private key stored?", "The secret santa list is ready."]
for i in range(140):
    cl("prose", ctx(R.choice(PROSE)) if R.random() < 0.5 else R.choice(PROSE))
for i in range(60):
    cl("ids", R.choice(["order 4f3a9c1e-2b7d-4e8a-9c01-5d6e7f8a9b0c shipped", "commit " + "".join(R.choice("0123456789abcdef") for _ in range(40)), "request id req_" + "".join(R.choice(ALNUM) for _ in range(20)), "sku TS-" + str(R.randint(1000, 9999)) + "-B"]))

os.makedirs(OUT, exist_ok=True)
def write(name, rows):
    p = os.path.join(OUT, name)
    with open(p, "w", encoding="utf-8") as f:
        for r in rows: f.write(json.dumps(r, sort_keys=True, ensure_ascii=False) + "\n")
    return hashlib.sha256(open(p, "rb").read()).hexdigest()
h = {"eg_secrets.jsonl": write("eg_secrets.jsonl", secrets), "eg_clean.jsonl": write("eg_clean.jsonl", clean)}
extra = {"marker_key": "dev-marker-key-0001", "markers": [], "terms": []}
with open(os.path.join(OUT, "eg_policy_extra.json"), "w") as f: json.dump(extra, f, indent=1, sort_keys=True); f.write("\n")
h["eg_policy_extra.json"] = hashlib.sha256(open(os.path.join(OUT, "eg_policy_extra.json"), "rb").read()).hexdigest()
for name in ("eg_abuse", "eg_destination", "eg_personal", "eg_terms"):
    open(os.path.join(OUT, name + ".jsonl"), "w").close()
    h[name + ".jsonl"] = hashlib.sha256(b"").hexdigest()
with open(os.path.join(OUT, "EG_FROZEN_F.json"), "w") as f:
    json.dump({"seed": SEED, "files": h, "counts": {"secrets": len(secrets), "clean": len(clean)}, "note": "frozen before any engine code; digit runs capped at 6"}, f, indent=1, sort_keys=True); f.write("\n")
fam = {}
for r in secrets + clean: fam[r["family"].split(":")[0]] = fam.get(r["family"].split(":")[0], 0) + 1
print(len(secrets), "secrets;", len(clean), "clean;", fam)
