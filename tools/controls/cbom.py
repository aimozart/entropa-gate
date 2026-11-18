"""CycloneDX 1.6 CBOM (cryptographic bill of materials) from the crypto-inventory results (E1 task 2).

One protocol asset (TLS) and one certificate asset per host that answered, plus the algorithms they use, deduplicated. Hosts that did not
answer are listed in the metadata properties as not covered; nothing is invented for them. The BOM records what was OBSERVED in a handshake: it
is an inventory, not an assessment, and it makes no quantum-safety claim (a hybrid ML-KEM group is recorded by name and as a flag). The
canonical bytes (sorted keys) are what the receipt hashes. validate() is a structural check of the parts of the 1.6 schema we emit, not a full
JSON Schema validation (no jsonschema module is installed).
"""
from __future__ import annotations

import hashlib
import json
import re

REF = "bom-ref"
ASSET_TYPES = ("protocol", "algorithm", "certificate")


class CbomError(ValueError):
    pass


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-").lower()


def cipher_algorithms(suite: str) -> list[str]:
    """Algorithm names named inside a TLS cipher suite string (TLS 1.3 and OpenSSL TLS 1.2 spellings)."""
    s = suite.upper()
    out = []
    for rx, fmt in ((r"ECDHE", "ECDHE"), (r"(?<![A-Z])DHE", "DHE")):
        if re.search(rx, s):
            out.append(fmt)
    if "ECDSA" in s:
        out.append("ECDSA")
    elif re.search(r"(?:^|[-_])RSA(?:[-_]|$)", s):
        out.append("RSA")
    m = re.search(r"AES[_-]?(\d+)[_-]?GCM", s)
    if m:
        out.append(f"AES-{m.group(1)}-GCM")
    if "CHACHA20" in s:
        out.append("ChaCha20-Poly1305")
    m = re.search(r"SHA(\d+)", s)
    if m:
        out.append(f"SHA-{m.group(1)}")
    return out


def _alg_props(name: str) -> dict:
    n = name.upper()
    if "MLKEM" in n.replace("-", ""):
        return dict(primitive="key-agree", parameterSetIdentifier=name, cryptoFunctions=["keygen", "encapsulate", "decapsulate"])
    if n in ("X25519", "SECP256R1", "SECP384R1", "ECDHE", "DHE") or n.startswith("FFDHE"):
        return dict(primitive="key-agree", parameterSetIdentifier=name, cryptoFunctions=["keygen"])
    if "GCM" in n or "POLY1305" in n:
        return dict(primitive="ae", parameterSetIdentifier=name, cryptoFunctions=["encrypt", "decrypt", "tag"])
    if n.startswith("SHA-"):
        return dict(primitive="hash", parameterSetIdentifier=name, cryptoFunctions=["digest"])
    return dict(primitive="signature", parameterSetIdentifier=name, cryptoFunctions=["sign", "verify"])


def _algorithm(name: str, note: str | None = None) -> dict:
    c = {"type": "cryptographic-asset", REF: f"crypto/algorithm/{_slug(name)}", "name": name,
         "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": _alg_props(name)}}
    if note:
        c["description"] = note
    return c


def build_cbom(results: list[dict], timestamp: str, serial: str) -> dict:
    answered = [r for r in results if r.get("answered")]
    if not answered:
        raise CbomError("no host answered: refusing to write an empty inventory")
    algs: dict[str, dict] = {}
    comps, deps = [], []

    def need(name, note=None):
        algs.setdefault(name, _algorithm(name, note))
        return algs[name][REF]

    for r in answered:
        host, port, leaf = r["host"], r["port"], (r["chain"][0] if r.get("chain") else None)
        pref, cref = f"crypto/protocol/{host}:{port}", f"crypto/certificate/{host}:{port}"
        refs = [need(a) for a in cipher_algorithms(r["cipher_suite"])]
        if r.get("group"):
            refs.append(need(r["group"], "hybrid key exchange: ML-KEM-768 combined with X25519" if r.get("hybrid_pq_kex") else None))
        version = r["tls_version"].replace("TLSv", "")
        comps.append({"type": "cryptographic-asset", REF: pref, "name": f"TLS {host}:{port}",
                      "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                          "type": "tls", "version": version,
                          "cipherSuites": [{"name": r["cipher_suite"], "algorithms": [x for x in refs if "algorithm" in x], "identifiers": []}]}},
                      "properties": [{"name": "entropa:group", "value": str(r.get("group"))}, {"name": "entropa:group_source", "value": str(r.get("group_source"))},
                                     {"name": "entropa:hybrid_pq_kex", "value": str(bool(r.get("hybrid_pq_kex"))).lower()},
                                     {"name": "entropa:peer_signature_type", "value": str(r.get("peer_signature_type"))},
                                     {"name": "entropa:hostname_in_san", "value": str(r.get("hostname_in_san")).lower()},
                                     {"name": "entropa:verification", "value": str(r.get("verification"))}]})
        depends = list(refs)
        if leaf:
            sig_ref = need(leaf["sigalg"])
            comps.append({"type": "cryptographic-asset", REF: cref, "name": f"Certificate for {host}:{port}",
                          "cryptoProperties": {"assetType": "certificate", "certificateProperties": {
                              "subjectName": leaf["subject"], "issuerName": leaf["issuer"], "notValidBefore": leaf["not_before"],
                              "notValidAfter": leaf["not_after"], "signatureAlgorithmRef": sig_ref, "certificateFormat": "X.509"}},
                          "properties": [{"name": "entropa:public_key", "value": leaf["public_key"]},
                                         {"name": "entropa:san", "value": ",".join(r.get("san") or [])},
                                         {"name": "entropa:days_to_expiry", "value": str(r.get("leaf_days_to_expiry"))}]
                          + ([{"name": "entropa:leaf_sha256", "value": r["leaf_sha256"]}] if r.get("leaf_sha256") else [])})
            deps.append({"ref": cref, "dependsOn": [sig_ref]})
            depends += [cref, sig_ref]
        deps.append({"ref": pref, "dependsOn": sorted(set(depends))})
    comps = list(algs.values()) + comps
    not_answered = [f"{r['host']}:{r.get('error')}" for r in results if not r.get("answered")]
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": serial, "version": 1,
           "metadata": {"timestamp": timestamp,
                        "tools": {"components": [{"type": "application", "name": "entropa-e1-crypto-inventory", "version": "1"}]},
                        "component": {"type": "application", REF: "entropa-estate", "name": "Entropa estate TLS posture"},
                        "properties": [{"name": "entropa:hosts_in_scope", "value": str(len(results))},
                                       {"name": "entropa:hosts_answered", "value": str(len(answered))},
                                       {"name": "entropa:hosts_not_answered", "value": ",".join(not_answered) if not_answered else "none"},
                                       {"name": "entropa:wording", "value": "inventory of observed TLS handshakes of our own hosts; evidence mapped to controls, not an assessment"}]},
           "components": comps, "dependencies": deps}
    validate(bom)
    return bom


def validate(b: dict) -> None:
    if not isinstance(b, dict) or b.get("bomFormat") != "CycloneDX" or b.get("specVersion") != "1.6":
        raise CbomError("not a CycloneDX 1.6 document")
    if not re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", str(b.get("serialNumber", ""))) or type(b.get("version")) is not int:
        raise CbomError("serialNumber or version missing or malformed")
    if not isinstance(b.get("metadata", {}).get("timestamp"), str):
        raise CbomError("metadata.timestamp missing")
    comps = b.get("components")
    if not isinstance(comps, list) or not comps:
        raise CbomError("no components")
    refs = []
    for c in comps:
        if c.get("type") != "cryptographic-asset" or not c.get(REF) or not c.get("name"):
            raise CbomError("every component must be a named cryptographic-asset with a bom-ref")
        if c.get("cryptoProperties", {}).get("assetType") not in ASSET_TYPES:
            raise CbomError("unknown assetType")
        refs.append(c[REF])
    if len(refs) != len(set(refs)):
        raise CbomError("duplicate bom-ref")
    known = set(refs) | {b.get("metadata", {}).get("component", {}).get(REF)}
    for d in b.get("dependencies", []):
        if d.get("ref") not in known or any(x not in known for x in d.get("dependsOn", [])):
            raise CbomError(f"dependency points at an unknown ref: {d.get('ref')}")


def to_bytes(b: dict) -> bytes:
    return (json.dumps(b, sort_keys=True, indent=1, ensure_ascii=False) + "\n").encode("utf-8")


def sha256_hex(b: dict) -> str:
    return hashlib.sha256(to_bytes(b)).hexdigest()
