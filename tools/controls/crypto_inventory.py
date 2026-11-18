"""Crypto-inventory collector (E1 task 2): read-only, OUR OWN assets only, one TLS handshake per host and nothing else.

For each target in compliance/crypto-targets.json it runs `openssl s_client` (a handshake with a timeout), parses the text, and records: TLS
version, negotiated key-exchange group (a hybrid ML-KEM group is recognised by name), cipher suite, the server's handshake signature type,
the certificate chain (subject, issuer, public key, signature algorithm, validity), the SANs and whether they name the host, and days to
expiry. A host that does not answer is recorded as not answering, with a reason; nothing is invented. A third-party host is refused before any
connection, whatever the targets file says (is_own_asset). Standard library plus the system `openssl`.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

OWN_DOMAINS = ("entropa.space", "bigironbank.online", "hippagrchealthcare.site")
OWN_EXACT_HOSTS = ("localhost", "127.0.0.1", "entropa-platinum-loqc3sut7a-uc.a.run.app", "entropa-ingest-loqc3sut7a-uc.a.run.app",
                   "entropa-transparency-1032137727494.us-central1.run.app")
LOCAL_HOSTS = ("localhost", "127.0.0.1")
TARGET_KEYS = ("name", "host", "port", "reason")
PORTS = (443,)


class TargetError(ValueError):
    pass


@dataclass(frozen=True)
class Target:
    name: str
    host: str
    port: int
    reason: str


def is_own_asset(host) -> bool:
    if not isinstance(host, str) or not host:
        return False
    h = host.lower()
    return h in OWN_EXACT_HOSTS or any(h == d or h.endswith("." + d) for d in OWN_DOMAINS)


def load_targets(path: Path) -> list[Target]:
    try:
        d = json.loads(Path(path).read_text())
        rows = d["targets"]
    except (OSError, ValueError, KeyError, TypeError):
        raise TargetError("cannot read the targets file") from None
    if not isinstance(rows, list) or not rows:
        raise TargetError("targets must be a non-empty list")
    out = []
    for r in rows:
        if not isinstance(r, dict) or set(r) != set(TARGET_KEYS):
            raise TargetError(f"each target needs exactly the keys {TARGET_KEYS}")
        if not all(isinstance(r[k], str) and r[k].strip() for k in ("name", "host", "reason")) or type(r["port"]) is not int:
            raise TargetError("bad target field types")
        if not is_own_asset(r["host"]):
            raise TargetError(f"not one of our own assets: {r['host']!r}")
        if r["port"] not in PORTS:
            raise TargetError(f"port {r['port']} is not allowed")
        out.append(Target(r["name"], r["host"], r["port"], r["reason"]))
    return out


def is_hybrid_pq(group) -> bool:
    g = re.sub(r"[-_ ]", "", str(group or "")).upper()
    return "MLKEM" in g or "KYBER" in g


def is_pq_signature(name) -> bool:
    n = re.sub(r"[-_ ]", "", str(name or "")).upper()
    return any(x in n for x in ("MLDSA", "SLHDSA", "DILITHIUM", "FALCON", "SPHINCS"))


def leaf_sha256(pem) -> str | None:
    """SHA-256 of the leaf certificate's DER bytes (the usual certificate fingerprint), or None if the PEM is missing or not base64."""
    if not isinstance(pem, str):
        return None
    body = "".join(l for l in pem.splitlines() if l and not l.startswith("-----"))
    try:
        return hashlib.sha256(base64.b64decode(body, validate=True)).hexdigest()
    except ValueError:
        return None


def _iso(s: str) -> str:
    return dt.datetime.strptime(" ".join(s.split()), "%b %d %H:%M:%S %Y GMT").strftime("%Y-%m-%dT%H:%M:%SZ")


def _error(out: str, err: str, rc: int) -> str:
    blob = (out + "\n" + err).lower()
    if rc == 124:
        return "timeout"
    if "connection refused" in blob or "errno=111" in blob or "errno 111" in blob:
        return "connection_refused"
    if "name or service not known" in blob or "getaddrinfo" in blob or "nodename nor servname" in blob:
        return "dns_failure"
    if "connected(" in blob:
        return "handshake_failure"
    return "no_tls_session"


def parse_s_client(out: str, err: str = "", rc: int = 0) -> dict:
    m = re.search(r"^New, (\S+), Cipher is (\S+)", out, re.M)
    if not m:
        return dict(answered=False, error=_error(out, err, rc))
    r: dict = dict(answered=True, tls_version=m.group(1), cipher_suite=m.group(2))
    g = re.search(r"^Negotiated TLS1\.3 group: (\S+)", out, re.M)
    t = re.search(r"^Server Temp Key: ([^,\n]+)", out, re.M)
    r["group"], r["group_source"] = (g.group(1), "negotiated_tls13_group") if g else ((t.group(1).strip(), "server_temp_key") if t else (None, None))
    r["hybrid_pq_kex"] = is_hybrid_pq(r["group"])
    for key, rx in (("peer_signature_type", r"^Peer signature type: (\S+)"), ("peer_signing_digest", r"^Peer signing digest: (\S+)")):
        x = re.search(rx, out, re.M)
        r[key] = x.group(1) if x else None
    v = re.search(r"^Verification: (.+)$", out, re.M) or re.search(r"^Verification error: (.+)$", out, re.M)
    r["verification"] = v.group(1).strip() if v else None
    c = re.search(r"^Verify return code: (\d+)", out, re.M)
    r["verify_return_code"] = int(c.group(1)) if c else None
    sec = re.split(r"\n---\n", out.split("Certificate chain", 1)[1], maxsplit=1)[0] if "Certificate chain" in out else ""
    chain = []
    for blk in re.finditer(r"^ (\d+) s:(.*)\n\s+i:(.*)\n\s+a:PKEY: (.*?); sigalg: (.*)\n\s+v:NotBefore: (.*?); NotAfter: (.*)$", sec, re.M):
        chain.append(dict(depth=int(blk.group(1)), subject=blk.group(2).strip(), issuer=blk.group(3).strip(), public_key=blk.group(4).strip(),
                          sigalg=blk.group(5).strip(), not_before=_iso(blk.group(6)), not_after=_iso(blk.group(7))))
    r["chain"] = chain
    pem = re.search(r"-----BEGIN CERTIFICATE-----\n.*?-----END CERTIFICATE-----", sec, re.S)
    r["leaf_pem"] = pem.group(0) + "\n" if pem else None
    return r


def openssl_runner(host: str, port: int, timeout: int = 15):
    """One TLS handshake, then close. Nothing is sent after the handshake and no application data, no STARTTLS, no cipher sweep."""
    cmd = ["openssl", "s_client", "-connect", f"{host}:{port}", "-showcerts", "-verify_hostname", host]
    if not re.fullmatch(r"[0-9.]+", host):
        cmd += ["-servername", host]
    try:
        p = subprocess.run(cmd, input=b"", capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "", "", 124
    return p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"), p.returncode


def openssl_san(pem: str) -> list[str]:
    try:
        p = subprocess.run(["openssl", "x509", "-noout", "-ext", "subjectAltName"], input=pem.encode(), capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return []
    names = []
    for part in p.stdout.decode("utf-8", "replace").split("\n")[1:]:
        for item in part.split(","):
            item = item.strip()
            if item.startswith("DNS:"):
                names.append(item[4:])
            elif item.startswith("IP Address:"):
                names.append(item[11:])
    return names


def san_matches(host: str, sans) -> bool:
    h = host.lower()
    for s in sans:
        s = s.lower()
        if s == h:
            return True
        if s.startswith("*.") and h.count(".") == s.count(".") and h.endswith(s[1:]) and h != s[2:]:
            return True
    return False


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def collect(targets, runner=None, x509=None, now: str | None = None, allow_test_port: bool = False) -> list[dict]:
    for t in targets:                                        # refuse BEFORE any connection
        if not is_own_asset(t.host):
            raise TargetError(f"not one of our own assets: {t.host!r}")
        if t.port not in PORTS and not (allow_test_port and t.host in LOCAL_HOSTS):
            raise TargetError(f"port {t.port} is not allowed for {t.host}")
    runner, x509 = runner or openssl_runner, x509 or openssl_san
    clock = dt.datetime.strptime(now or _now_iso(), "%Y-%m-%dT%H:%M:%SZ")
    results = []
    for t in targets:
        out, err, rc = runner(t.host, t.port)
        r = parse_s_client(out, err, rc)
        r.update(name=t.name, host=t.host, port=t.port)
        if r["answered"]:
            san = x509(r["leaf_pem"]) if r.get("leaf_pem") else []
            r["san"] = san
            r["leaf_sha256"] = leaf_sha256(r.get("leaf_pem"))
            r["hostname_in_san"] = san_matches(t.host, san)
            leaf = r["chain"][0] if r["chain"] else None
            r["leaf_pq_signature"] = is_pq_signature(leaf["sigalg"]) if leaf else None
            r["leaf_days_to_expiry"] = (dt.datetime.strptime(leaf["not_after"], "%Y-%m-%dT%H:%M:%SZ") - clock).days if leaf else None
        results.append(r)
    return results


def main(argv: list[str]) -> int:
    targets = load_targets(Path(__file__).resolve().parents[2] / "compliance" / "crypto-targets.json")
    print(json.dumps(collect(targets), indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main(sys.argv[1:]))
