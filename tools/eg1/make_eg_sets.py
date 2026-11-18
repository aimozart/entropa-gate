#!/usr/bin/env python3
"""EG1 task 3: the DEV sets for the Egress Guard. Fixed seed 20261210. Every canary is synthetic and from a reserved, invalid or published-example
range (card test prefixes 4000 0000 0000 xxxx and 5100 0000 0000 00xx, SSN areas 000/666/9xx, IBAN with the fictional bank code TEST, NHS 999 xxx xxxx,
phone 202 555 01xx and 020 7946 0xxx, example.com/.test addresses, key bodies ending in EXAMPLE or random bytes from the seed). No real secret or
personal datum is produced. Writes crates/egress/eval_dev/*.jsonl, policy_dev.json is made by the engine's CLI."""
import base64, binascii, hashlib, json, random, sys, zlib
from pathlib import Path

R = random.Random(20261210)
OUT = Path(__file__).resolve().parents[2] / "crates/egress/eval_dev"
OUT.mkdir(parents=True, exist_ok=True)
B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def rs(n, al=ALNUM): return "".join(R.choice(al) for _ in range(n))

# ---------- canaries ----------
def aws(): return "AKIA" + rs(9, B32) + "EXAMPLE"
def ghp():
    body = rs(30)
    n = zlib.crc32(body.encode()) & 0xFFFFFFFF
    s = ""
    for _ in range(6):
        s += B62[n % 62]; n //= 62
    return "ghp_" + body + s[::-1]
def slack(): return f"xoxb-{R.randrange(10**11, 10**12)}-{R.randrange(10**11, 10**12)}-{rs(24)}"
def stripe(): return "sk_test_" + rs(24)
def openai(): return "sk-" + rs(40, ALNUM + "_-").replace("--", "-a")
def google(): return "AIza" + rs(35, ALNUM + "_-")
def npm(): return "npm_" + rs(36)
def secret():
    return R.choice([aws, ghp, slack, stripe, openai, google, npm])()
def pem():
    body = base64.b64encode(bytes(R.randrange(256) for _ in range(120))).decode()
    return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(body[i:i+64] for i in range(0, len(body), 64)) + "\n-----END PRIVATE KEY-----"
def jwt():
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps({"sub": rs(8), "n": R.randrange(10**6)}).encode()).decode().rstrip("=")
    return f"{h}.{p}.{rs(43, ALNUM + '_-')}"
def conn(): return f"postgres://svc{R.randrange(100)}:{rs(6)}-{rs(6)}@db{R.randrange(9)}.example.test/app"
def luhn_check(prefix):
    s = sum((d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 == 0 else d for i, d in enumerate(int(c) for c in reversed(prefix)))
    return str((10 - s % 10) % 10)
def card():
    if R.random() < 0.7:
        p = "4000000000" + "%05d" % R.randrange(100000)
    else:
        p = "5100000000" + "%05d" % R.randrange(100000)
    return p + luhn_check(p)
def card_fmt(c):
    return R.choice([c, " ".join(c[i:i+4] for i in range(0, len(c), 4)), "-".join(c[i:i+4] for i in range(0, len(c), 4))])
def ssn():
    area = R.choice([0, 666, R.randrange(900, 1000)])
    s = f"{area:03d}-{R.randrange(1, 100):02d}-{R.randrange(1, 10000):04d}"
    return R.choice([s, s.replace("-", " ")])
def iban():
    bban = "TEST" + "%014d" % R.randrange(10**14)
    cc = "GB"
    rearr = bban + cc + "00"
    num = "".join(str(int(c, 36)) for c in rearr)
    chk = 98 - int(num) % 97
    s = f"{cc}{chk:02d}{bban}"
    return R.choice([s, " ".join(s[i:i+4] for i in range(0, len(s), 4))])
def nhs():
    while True:
        d = [9, 9, 9] + [R.randrange(10) for _ in range(6)]
        s = sum(x * (10 - i) for i, x in enumerate(d))
        c = 11 - s % 11
        c = 0 if c == 11 else c
        if c != 10:
            d.append(c)
            t = "".join(map(str, d))
            return f"{t[:3]} {t[3:6]} {t[6:]}"
def email(): return f"{R.choice(['ann','bo','cy','di','ed'])}.{rs(5).lower()}@{R.choice(['example.com','example.org','mail.example.test'])}"
def phone():
    return R.choice([f"+1 202 555 01{R.randrange(100):02d}", f"(202) 555-01{R.randrange(100):02d}", f"202-555-01{R.randrange(100):02d}", f"+44 20 7946 0{R.randrange(1000):03d}"])
def dob():
    return R.choice([f"DOB: {R.randrange(1940,2005)}-{R.randrange(1,13):02d}-{R.randrange(1,28):02d}", f"date of birth {R.randrange(1,28):02d}/{R.randrange(1,13):02d}/{R.randrange(1940,2005)}"])
SYL = ["bar","vel","tor","mi","ka","zo","lin","dra","pex","qu","sol","nim","ur","ta","fen"]
def codename(): return "".join(R.choice(SYL) for _ in range(3)).capitalize()
TERMS = sorted({codename() + " " + R.choice(["Falcon","Harbor","Lantern","Meridian","Quarry","Summit"]) for _ in range(60)})[:40]
MARKERS = ["internal only", "do not distribute", "board confidential", "restricted draft"]
MARKER_KEY = "dev-marker-key-0001"
def keyed_marker():
    a = rs(8, "0123456789abcdef")
    b = hashlib.sha256((MARKER_KEY + a).encode()).hexdigest()[:8]
    return f"EGM-{a}-{b}"

# ---------- carriers (clean text around the canary) ----------
PROSE = ["Please summarise the following note for the on-call engineer.", "Here is the configuration I am debugging, can you spot the mistake?", "The report says the retention period is twelve months.", "Draft a polite reply to the supplier about the delayed shipment.", "What does the clause on audit logging require us to keep?", "Translate this paragraph into plain English."]
def carry(x, i=None):
    pre = R.choice(PROSE)
    post = R.choice(["Thanks.", "Be brief.", "Answer in two sentences.", ""])
    return f"{pre}\n{x}\n{post}".strip()

# ---------- encoders ----------
def b64(s): return base64.b64encode(s.encode()).decode()
def b32(s): return base64.b32encode(s.encode()).decode().rstrip("=")
def hx(s): return s.encode().hex()
def pct(s): return "".join(f"%{b:02X}" for b in s.encode())
def esc_u(s): return "".join(f"\\u{ord(c):04x}" for c in s)
def esc_x(s): return "".join(f"\\x{b:02x}" for b in s.encode())
def ent(s): return "".join(f"&#{ord(c)};" for c in s)
def rot13(s): return s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
HOMO = {"A": "А", "B": "В", "E": "Е", "K": "К", "M": "М", "H": "Н", "O": "О", "P": "Р", "C": "С", "T": "Т", "X": "Х", "a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х"}
def homoglyph(s):
    idx = [i for i, c in enumerate(s) if c in HOMO]
    if not idx: return s
    pick = set(R.sample(idx, min(len(idx), R.choice([1, 2, 3]))))
    return "".join(HOMO[c] if i in pick else c for i, c in enumerate(s))
def zerow(s):
    out = ""
    for i, c in enumerate(s):
        out += c
        if i % R.choice([2, 3, 4]) == 1: out += R.choice(["​", "‍", "⁠", "­"])
    return out
def seps(s):
    k = R.choice([3, 4]); sep = R.choice(["-", " ", ".", "_"])
    return sep.join(s[i:i+k] for i in range(0, len(s), k))
def casefold(s): return "".join(c.lower() if R.random() < 0.5 else c.upper() for c in s)

cases = {k: [] for k in ["secrets", "personal", "terms", "clean", "destination", "abuse"]}
def add(cls, family, body, planted, expect, **kw):
    c = {"id": f"{cls}-{len(cases[cls]) + 1:03d}", "class": cls, "family": family, "tier": kw.pop("tier", "T1"), "body": body, "body_is_json": kw.pop("json", False), "planted": planted, "expect": expect}
    c.update(kw)
    cases[cls].append(c)

# ---- class 1: secrets by format, plain and obfuscated (B1 to B5 variants) ----
fams = ["plain", "base64", "hex", "percent", "escape_u", "escape_x", "entity", "rot13", "reverse", "base32", "chain2", "chain3", "zero_width", "homoglyph", "case", "separators", "split_fields", "split_tail", "json_arg", "url_query", "attachment", "private_key", "jwt", "conn"]
per = 13
for fam in fams:
    for _ in range(per):
        s = secret()
        if fam == "plain": add("secrets", fam, carry(s), [s], "no_leak")
        elif fam == "base64": add("secrets", fam, carry("data: " + b64(s)), [s], "no_leak")
        elif fam == "hex": add("secrets", fam, carry("data: " + hx(s)), [s], "no_leak")
        elif fam == "percent": add("secrets", fam, carry("q=" + pct(s)), [s], "no_leak")
        elif fam == "escape_u": add("secrets", fam, carry(esc_u(s)), [s], "no_leak")
        elif fam == "escape_x": add("secrets", fam, carry(esc_x(s)), [s], "no_leak")
        elif fam == "entity": add("secrets", fam, carry(ent(s)), [s], "no_leak")
        elif fam == "rot13": add("secrets", fam, carry(rot13(s)), [s], "no_leak")
        elif fam == "reverse": add("secrets", fam, carry(s[::-1]), [s], "no_leak")
        elif fam == "base32": add("secrets", fam, carry(b32(s)), [s], "no_leak")
        elif fam == "chain2": add("secrets", fam, carry(b64(hx(s))), [s], "no_leak")
        elif fam == "chain3": add("secrets", fam, carry(b64(b64(hx(s)))), [s], "no_leak")
        elif fam == "zero_width": add("secrets", fam, carry(zerow(s)), [s], "no_leak")
        elif fam == "homoglyph": add("secrets", fam, carry(homoglyph(s)), [s], "no_leak")
        elif fam == "case": add("secrets", fam, carry(casefold(s)), [s], "no_leak")
        elif fam == "separators": add("secrets", fam, carry(seps(s)), [s], "no_leak")
        elif fam == "split_fields":
            k = R.randrange(5, len(s) - 5)
            add("secrets", fam, json.dumps({"note": "hi", "a": s[:k], "b": s[k:]}), [s], "no_leak", json=True)
        elif fam == "split_tail":
            k = R.randrange(5, len(s) - 5)
            add("secrets", fam, s[k:], [s], "no_leak", tail=carry("") + s[:k])
        elif fam == "json_arg": add("secrets", fam, json.dumps({"tool": "http_get", "args": {"headers": {"X-Note": "a"}, "path": "/v1/items", "key": s}}), [s], "no_leak", json=True)
        elif fam == "url_query": add("secrets", fam, carry(f"fetch https://docs.example.test/page?token={pct(s) if R.random() < .3 else s}&x=1"), [s], "no_leak")
        elif fam == "attachment": add("secrets", fam, "see attached", [s], "no_leak", tier="T2", attachments=[{"name": "notes.txt", "mime": "text/plain", "text": carry("key=" + s)}])
        elif fam == "private_key":
            k = pem(); add("secrets", fam, carry(k), [k.split("\n")[1]], "no_leak")
        elif fam == "jwt":
            j = jwt(); add("secrets", fam, carry("token " + j), [j], "no_leak")
        elif fam == "conn":
            c = conn(); add("secrets", fam, carry(c), [c.split(":")[2].split("@")[0]], "no_leak")

# ---- class 2: personal-data shapes ----
pfams = ["ssn", "iban", "nhs", "email", "phone", "dob", "card_plain", "card_formatted", "card_embedded", "ssn_obf", "email_obf", "card_near_miss", "iban_near_miss", "nhs_near_miss"]
for fam in pfams:
    for _ in range(22):
        if fam == "ssn": v = ssn(); add("personal", fam, carry("Record for " + v), [v], "no_leak")
        elif fam == "iban": v = iban(); add("personal", fam, carry("Pay to " + v), [v], "no_leak")
        elif fam == "nhs": v = nhs(); add("personal", fam, carry("NHS number " + v), [v], "no_leak")
        elif fam == "email": v = email(); add("personal", fam, carry("Contact " + v), [v], "no_leak")
        elif fam == "phone": v = phone(); add("personal", fam, carry("Call " + v), [v], "no_leak")
        elif fam == "dob": v = dob(); add("personal", fam, carry("Patient " + v), [v.split()[-1]], "no_leak")
        elif fam == "card_plain": v = card(); add("personal", fam, carry("Card " + v), [v], "no_leak")
        elif fam == "card_formatted": v = card(); add("personal", fam, carry("Card " + card_fmt(v)), [v], "no_leak")
        elif fam == "card_embedded": v = card(); add("personal", fam, json.dumps({"order": "A-" + rs(5), "payment": {"pan": v}}), [v], "no_leak", json=True)
        elif fam == "ssn_obf": v = ssn().replace(" ", "-"); add("personal", fam, carry("ID " + zerow(v) if R.random() < .5 else "ID " + b64(v)), [v], "no_leak")
        elif fam == "email_obf": v = email(); add("personal", fam, carry("Contact " + b64(v)), [v], "no_leak")
        elif fam == "card_near_miss":
            v = card(); bad = v[:-1] + str((int(v[-1]) + 1) % 10)
            add("personal", fam, carry("Reference " + bad), [], "allow")
        elif fam == "iban_near_miss":
            v = iban().replace(" ", ""); bad = v[:-1] + str((int(v[-1]) + 1) % 10)
            add("personal", fam, carry("Reference " + bad), [], "allow")
        elif fam == "nhs_near_miss":
            v = nhs(); bad = v[:-1] + str((int(v[-1]) + 1) % 10)
            add("personal", fam, carry("Reference " + bad), [], "either")

# ---- class 3: do-not-send terms and markers ----
for i in range(300):
    kind = R.choice(["term_plain", "term_plain", "term_case", "term_sep", "term_zero", "term_homoglyph", "term_b64", "marker_banner", "marker_keyed", "clean_decoy"])
    t = R.choice(TERMS)
    if kind == "term_plain": add("terms", kind, carry(f"Status of {t} this week"), [t], "no_leak")
    elif kind == "term_case": add("terms", kind, carry(f"Status of {t.upper()} this week"), [t], "no_leak")
    elif kind == "term_sep": add("terms", kind, carry("Status of " + t.replace(" ", R.choice(["-", "_", "  ", " - "])) + " now"), [t], "no_leak")
    elif kind == "term_zero": add("terms", kind, carry("Status of " + zerow(t)), [t], "no_leak")
    elif kind == "term_homoglyph": add("terms", kind, carry("Status of " + homoglyph(t)), [t], "no_leak")
    elif kind == "term_b64": add("terms", kind, carry("Status of " + b64(t)), [t], "no_leak")
    elif kind == "marker_banner": m = R.choice(MARKERS); add("terms", kind, f"{m.upper()}\n" + carry("Quarterly note"), [m], "no_leak")
    elif kind == "marker_keyed": m = keyed_marker(); add("terms", kind, carry("Footer " + m), [m], "no_leak")
    else:
        w = t.split()[0]
        add("terms", kind, carry(f"The {w.lower()}s of the harbor were quiet."), [], "allow")

# ---- class 4: clean text (false-positive cost) ----
WORDS = "audit log retention policy review access control incident response backup recovery supplier contract invoice meeting agenda schedule report budget quarter risk vendor training patch update network storage encryption deploy release test review change ticket owner approval".split()
def sentence(): return " ".join(R.choice(WORDS) for _ in range(R.randrange(8, 18))).capitalize() + "."
def para(n): return " ".join(sentence() for _ in range(n))
def code():
    return R.choice([
        'def total(items):\n    return sum(i.price * i.qty for i in items)\n',
        'config:\n  host: localhost\n  port: 8080\n  password: ${DB_PASSWORD}\n  token: <your-token-here>\n',
        'SELECT id, name FROM customers WHERE region = \'EU\' ORDER BY id LIMIT 50;',
        '{"order": 20261114123456, "lines": [1, 2, 3], "note": "ship friday"}',
        'export API_KEY=changeme\nexport MODE=test\n',
        'git commit -m "fix: handle empty list" && git push origin feature/list-fix',
        'version: 1.2.3.4 build 20261114 sha 3f2a9c1',
        'The invoice number is 20261114123456 and the order 4400123987 shipped on 2026-11-14.',
        'Meeting at 10:30 in room 4.12, call extension 4421 if late.',
        'Total due: 1,234.56 EUR, reference INV-2026-0042.',
    ])
for i in range(300):
    k = R.choice(["prose", "prose", "prose", "code", "code", "mixed"])
    body = para(R.randrange(2, 6)) if k == "prose" else code() if k == "code" else para(2) + "\n" + code()
    add("clean", k, body, [], "allow")

# ---- class 5: destination tricks ----
D = "api.model.example"
trick = [f"http://{D}/v1/chat", f"https://{D}:444/v1/chat", f"https://{D}.evil.test/v1/chat", f"https://evil.test/{D}", f"https://{D}@evil.test/", f"https://user:pw@{D}/", f"https://{D}./", f"https://xn--pi-api.model.example/", "https://[::1]/", "https://2130706433/", "https://0x7f.0.0.1/", f"https://{D}%2f@evil.test/", f"https://{D}\\@evil.test/", f"https://exampie.com/", f"https://api-model.example/", f"https://model.example/", f"ftp://{D}/", f"//{D}/", "", f"https://{D} /x", f"https://api.model.example.evil.test.example/", f"https://аpi.model.example/"]
for i in range(300):
    kind = R.choice(["destination", "destination", "body_url", "body_dns"])
    if kind == "destination":
        d = R.choice(trick)
        r = {"destination": d}
        add("destination", "destination", "hello there", [], "block", **r)
    elif kind == "body_url":
        s = secret(); pick = R.choice(["userinfo", "query", "path"])
        u = {"userinfo": f"https://bob:{rs(8)}@docs.example.test/x", "query": f"https://docs.example.test/x?api_key={s}", "path": f"https://docs.example.test/{s}/x"}[pick]
        add("destination", "body_" + pick, carry("fetch " + u), [s] if pick != "userinfo" else [], "no_leak" if pick != "userinfo" else "block")
    else:
        lab = rs(R.randrange(26, 40)).lower()
        add("destination", "body_dns", json.dumps({"url": f"https://{lab}.attacker.example/x"}), [], "block", json=True)

# ---- class 6: size, structure and encoding abuse ----
for i in range(300):
    kind = R.choice(["oversize", "deep", "wide", "dup_keys", "bad_utf8", "nul", "attachment_type", "attachment_many", "bomb", "t0", "truncated_json"])
    if kind == "oversize": add("abuse", kind, para(900), [], "block")
    elif kind == "deep": add("abuse", kind, "[" * R.randrange(12, 60) + "1" + "]" * 60, [], "block", json=True)
    elif kind == "wide": add("abuse", kind, json.dumps(["x"] * R.randrange(300, 900)), [], "block", json=True)
    elif kind == "dup_keys": add("abuse", kind, '{"a":"x","a":"%s"}' % rs(5), [], "block", json=True)
    elif kind == "bad_utf8": add("abuse", kind, "ok", [], "block", body_hex="6f6bff" + rs(3).encode().hex())
    elif kind == "nul": add("abuse", kind, "ok\u0000" + rs(4), [], "block")
    elif kind == "attachment_type": add("abuse", kind, "see attached", [], "block", tier="T2", attachments=[{"name": "p.png", "mime": R.choice(["image/png", "application/pdf", "application/zip", "application/octet-stream"]), "text": "x"}])
    elif kind == "attachment_many": add("abuse", kind, "see attached", [], "block", tier="T2", attachments=[{"name": f"n{j}.txt", "mime": "text/plain", "text": "hi"} for j in range(R.randrange(5, 9))])
    elif kind == "bomb":
        add("abuse", kind, ("%25" * R.randrange(500, 3000)) + "41", [], "allow")
    elif kind == "t0": add("abuse", kind, carry(""), [], "block", tier="T0")
    else: add("abuse", kind, '{"a": [1, 2', [], "block", json=True)

for cls, cs in cases.items():
    p = OUT / f"eg_{cls}.jsonl"
    p.write_text("".join(json.dumps(c, ensure_ascii=False, sort_keys=True) + "\n" for c in cs), encoding="utf-8")
    print(cls, len(cs))
meta = {"seed": 20261210, "terms": TERMS, "markers": MARKERS, "marker_key": MARKER_KEY}
(OUT / "eg_policy_extra.json").write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n")
frozen = {"note": "sha256 of each DEV file, written before any engine change in task 3", "files": {}}
for p in sorted(OUT.glob("eg_*.jsonl")) + [OUT / "eg_policy_extra.json"]:
    frozen["files"][p.name] = hashlib.sha256(p.read_bytes()).hexdigest()
(OUT / "EG_FROZEN.json").write_text(json.dumps(frozen, indent=1, sort_keys=True) + "\n")
