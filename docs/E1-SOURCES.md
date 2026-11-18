# E1 source texts (where the register quotes are checked)

Nothing licensed lives in this repository. The register (`compliance/controls-register.json`) holds short quotes (at most 25 words), a source file name, and that file's sha256. `python3 -m unittest discover -s tools/controls/tests -t .` finds every quote in its local source.

| Source file | Where it lives | Kind | How to get it |
|---|---|---|---|
| DORA_RTS_ICT_Risk_2024_1774.pdf (Delegated Regulation (EU) 2024/1774, OJ 25.6.2024) | a private research directory (gitignored there) | primary | Publications Office PDF |
| EU_AI_Act_2024_1689.pdf (Regulation (EU) 2024/1689, OJ 12.7.2024) | same | primary | Publications Office PDF |
| PCI-DSS-v4_0_1.pdf (PCI DSS v4.0.1) | same | primary | licensed download from the PCI SSC document library (account needed) |
| nist-800-53-rev5-catalog.json (NIST SP 800-53 Rev 5.2.0, OSCAL catalog) | `~/.cache/build/controls-e1-sources` | primary | `curl -L -o nist-800-53-rev5-catalog.json https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json` |
| hipaa-164-312-source.html (45 CFR 164.312) | same | **secondary** | `curl -L -A "Mozilla/5.0" -o hipaa-164-312-source.html https://www.law.cornell.edu/cfr/text/45/164.312` (Cornell LII is an unofficial mirror; the official eCFR request returned HTTP 406 on 2026-11-13) |

Directories can be overridden with `E1_STANDARDS_DIR` and `E1_PUBLIC_SOURCES_DIR`. If a source file is missing the test FAILS (set `E1_ALLOW_MISSING_SOURCES=1` only to run the rest). The check compares modulo whitespace, line-break hyphenation, typographic quotes and dashes; a different word, number or letter case does not match. Each quote must also sit under its clause anchor, so a phrase repeated elsewhere cannot vouch for the wrong clause.
