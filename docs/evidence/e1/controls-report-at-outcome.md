# E1 self-assessment of our own estate

Generated 2026-11-13T22:15:11Z. **evidence mapped to the control; not an assessment of compliance, and not a claim that any standard is met.**

## Known gaps

Stated up front, before any row:

- **ledgers_share_one_key**: three ledgers share one signing key (affects: DORA-12-2-d, NIST-AU-10)
- **witness_only_ai_ledger**: only the AI ledger is witnessed (affects: DORA-12-2-d, NIST-AU-9-2)
- **gcp_service_account_keys_4**: four GCP service-account keys exist (affects: DORA-7)
- **aws_cli_key_not_retired**: the AWS CLI key has not been retired (affects: DORA-7)
- **csp_report_only**: content security policy is report-only on the public sites (affects: no register row)
- **dnssec_off**: DNSSEC is off (affects: no register row)
- **council_sessions_manual**: council sessions are run by hand (affects: no register row)
- **node_dir_two_ledgers_one_key**: one node directory holds two ledgers (ledger and evidence-ledger) signed by the single platinum.key (affects: DORA-12-2-d, NIST-AU-10)
- **crypto_agility_plan_missing**: an inventory exists, but a documented plan for changing certificate algorithms is not yet written; certificates are classical and the hybrid key exchange is supplied by the hosting platforms (affects: PCI-12-3-3, DORA-6)

## Findings

- 10 of 10 answering hosts negotiated a hybrid ML-KEM key exchange with an OpenSSL 3.5 client. It is supplied by the hosting platforms (per the operator: Firebase Hosting and the Cloud Run front ends), not implemented by Entropa, and another client may negotiate differently.
- The certificates are classical (EC, (prime256v1) x3; RSA, 2048 (bit) x7): no post-quantum signature protects the certificates.
- Crypto-agility: this inventory exists; a documented plan for changing certificate algorithms is not yet written (known gap crypto_agility_plan_missing in compliance/controls-rubric.json).
- Fact (not a gap): 4 hosts present one shared certificate: entropa.space, bigironbank.online, hippagrchealthcare.site, scryon.entropa.space.
- Fact (not a gap): 3 hosts present one shared certificate: entropa-platinum-loqc3sut7a-uc.a.run.app, entropa-ingest-loqc3sut7a-uc.a.run.app, entropa-transparency-1032137727494.us-central1.run.app.
- Certificates expire in 67 to 81 days from the inventory date.
- Log integrity: a one-byte change anywhere in the evidence ledger of a copy was detected, most by a checkpoint mismatch; a flip of the very last byte hits the trailing newline and is caught as a format error ('file ends with a partial line'), not as a cryptographic mismatch.

## Summary

- MET BY EVIDENCE: 1
- PARTIAL: 11
- GAP: 5
- Quotes verified against their source: 17/17 (14 primary; 3 rows rest on a secondary source)

## Control rows

| ID | Standard | Clause | Status | Source | Quote verified | Covered | Missing | Known gaps | Receipts |
|---|---|---|---|---|---|---|---|---|---|
| DORA-6 | DORA RTS 2024/1774 | Art. 6(1) | PARTIAL | primary | yes | crypto_inventory | crypto_policy_document | crypto_agility_plan_missing | 1 |
| DORA-7 | DORA RTS 2024/1774 | Art. 7(2) | GAP | primary | yes | - | key_lifecycle_evidence | gcp_service_account_keys_4, aws_cli_key_not_retired | - |
| DORA-12-2-d | DORA RTS 2024/1774 | Art. 12(2)(d) | PARTIAL | primary | yes | log_tamper_detection, signed_records | separate_storage | ledgers_share_one_key, witness_only_ai_ledger, node_dir_two_ledgers_one_key | 2, 3 |
| PCI-10-3-2 | PCI DSS | 10.3.2 | PARTIAL | primary | yes | log_tamper_detection | access_control_on_logs | - | 2, 3 |
| PCI-10-3-4 | PCI DSS | 10.3.4 | PARTIAL | primary | yes | log_tamper_detection | alerting_on_change | - | 2, 3 |
| PCI-10-5-1 | PCI DSS | 10.5.1 | GAP | primary | yes | - | retention_evidence | - | - |
| PCI-12-3-3 | PCI DSS | 12.3.3 | PARTIAL | primary | yes | crypto_inventory | annual_review_record | crypto_agility_plan_missing | 1 |
| NIST-AU-9 | NIST SP 800-53 | AU-9 | PARTIAL | primary | yes | log_tamper_detection | access_control_on_logs | - | 2, 3 |
| NIST-AU-9-2 | NIST SP 800-53 | AU-9(2) | GAP | primary | yes | - | separate_storage | witness_only_ai_ledger | - |
| NIST-AU-9-3 | NIST SP 800-53 | AU-9(3) | MET BY EVIDENCE | primary | yes | signed_records, log_tamper_detection | - | - | 2, 3 |
| NIST-AU-10 | NIST SP 800-53 | AU-10 | PARTIAL | primary | yes | signed_records | distinct_signing_keys | ledgers_share_one_key, node_dir_two_ledgers_one_key | 2 |
| EUAIA-12 | EU AI Act | Art. 12(1) | PARTIAL | primary | yes | signed_records | retention_evidence | - | 2 |
| EUAIA-19 | EU AI Act | Art. 19(1) | GAP | primary | yes | - | retention_evidence | - | - |
| EUAIA-26-6 | EU AI Act | Art. 26(6) | GAP | primary | yes | - | retention_evidence | - | - |
| HIPAA-164-312-b | HIPAA Security Rule | 164.312(b) | PARTIAL | secondary | yes | signed_records | audit_review_process | - | 2 |
| HIPAA-164-312-c1 | HIPAA Security Rule | 164.312(c)(1) | PARTIAL | secondary | yes | log_tamper_detection | integrity_policy_document | - | 2, 3 |
| HIPAA-164-312-c2 | HIPAA Security Rule | 164.312(c)(2) | PARTIAL | secondary | yes | log_tamper_detection | - | - | 2, 3 |

Why each row has its status:

- DORA-6: missing evidence: crypto_policy_document; known gap attached: crypto_agility_plan_missing
- DORA-7: no required evidence kind has a verifying receipt
- DORA-12-2-d: missing evidence: separate_storage; known gap attached: ledgers_share_one_key, witness_only_ai_ledger, node_dir_two_ledgers_one_key
- PCI-10-3-2: missing evidence: access_control_on_logs
- PCI-10-3-4: missing evidence: alerting_on_change
- PCI-10-5-1: no required evidence kind has a verifying receipt
- PCI-12-3-3: missing evidence: annual_review_record; known gap attached: crypto_agility_plan_missing
- NIST-AU-9: missing evidence: access_control_on_logs
- NIST-AU-9-2: no required evidence kind has a verifying receipt
- NIST-AU-9-3: every required evidence kind has a verifying receipt, no known gap, primary source verified
  - Caveat: the mechanism was demonstrated on a demo node built by the same binary; no production ledger was examined.
- NIST-AU-10: missing evidence: distinct_signing_keys; known gap attached: ledgers_share_one_key, node_dir_two_ledgers_one_key
- EUAIA-12: missing evidence: retention_evidence
- EUAIA-19: no required evidence kind has a verifying receipt
- EUAIA-26-6: no required evidence kind has a verifying receipt
- HIPAA-164-312-b: missing evidence: audit_review_process; the source text is secondary
- HIPAA-164-312-c1: missing evidence: integrity_policy_document; the source text is secondary
- HIPAA-164-312-c2: the source text is secondary

## Evidence

- **crypto_inventory**: present; the receipt verifies and the CBOM matches its hash (files: crypto-inventory-2026-11-13-r2.json, cbom-2026-11-13-r2.cdx.json; receipts: [1])
  - earlier runs kept as dated records: crypto-inventory-2026-11-13.json
- **log_tamper_detection**: present; a one-byte change to a copy fails offline verification; the original passes; both receipts verify (files: log-integrity-2026-11-13.json; receipts: [2, 3])
- **signed_records**: present; the original ledger verifies from start to end offline and the node signs with ML-DSA-65 (files: log-integrity-2026-11-13.json; receipts: [2])
- **separate_storage**: absent; recorded facts are documented or stated, not measured by the demonstration, so no receipt was emitted (the facts are in the log-integrity evidence file)
- **crypto_policy_document**: absent; not produced by E1
- **key_lifecycle_evidence**: absent; not produced by E1
- **access_control_on_logs**: absent; not produced by E1
- **alerting_on_change**: absent; not produced by E1
- **annual_review_record**: absent; not produced by E1
- **retention_evidence**: absent; not produced by E1
- **audit_review_process**: absent; not produced by E1
- **integrity_policy_document**: absent; not produced by E1
- **distinct_signing_keys**: absent; not produced by E1

## Plan versus outcome

| Forecast | Measured |
|---|---|
| every quote verified against its source | 17 of 17 verified; 14 primary, 3 secondary rows |
| most rows PARTIAL, a few MET, at least 5 GAP | 11 PARTIAL, 1 MET (NIST-AU-9-3), 5 GAP (DORA-7, PCI-10-5-1, NIST-AU-9-2, EUAIA-19, EUAIA-26-6) |
| the CBOM covers every in-scope host | 10 of 11 in-scope targets answered (localhost has no TLS service) |
| every MET row has an offline-verifying receipt | each MET row's required evidence has a receipt that was checked against the node and verified offline |

## History of commit hashes that changed

- E-LABELS-2 RED commit: 23dcdca became e54ac07 (messages reworded to add the repository's required 'Test change:' line; content identical)
- E-LABELS-2 commit: 05bf716 became 9b734fa (messages reworded to add the repository's required 'Test change:' line; content identical)

## Limits

- The three HIPAA rows rest on a public mirror (Cornell LII) of 45 CFR 164.312, not on the official eCFR text, so the fixed rubric caps them at PARTIAL.
- Receipts come from a LOCAL scratch node whose signing key is a throwaway made for E1. They verify offline on that node. No live node and no witness is involved.
- The crypto inventory is one observation from one client (OpenSSL 3.5) at one network position on one day. The hybrid key exchange it shows is supplied by the hosting platforms, not by Entropa.
- The CBOM is checked structurally against the parts of CycloneDX 1.6 we emit; it is not validated with the official JSON Schema (no validator is installed).
- The log-integrity demonstration uses a dedicated demo node. No production ledger was copied or changed. Separate storage and key sharing in production are STATED, not measured.
- Evidence kinds E1 does not produce (policy documents, retention, key lifecycle, alerting, review records, distinct signing keys) are absent, so rows that need them cannot be MET.
- Register quotes are at most 25 words; a clause must be read in full in its source to be interpreted.
