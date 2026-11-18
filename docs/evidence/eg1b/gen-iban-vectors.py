#!/usr/bin/env python3
"""Independent IBAN vectors for tests/survivors_iban.rs (EG1b mutation triage). Lengths are the IBAN registry lengths, written here from the registry, NOT read
from the engine's table; check digits are computed by the standard mod-97 rule with Python integers. Seeded, synthetic digits only (no real account)."""
import random
LEN = dict(AD=24, AT=20, BE=16, BG=22, CH=21, CY=28, CZ=24, DE=22, DK=18, EE=20, ES=24, FI=18, FR=27, GB=22, GR=27, HR=21, HU=28, IE=22, IS=26, IT=27,
           LI=21, LT=20, LU=20, LV=21, MC=27, MT=31, NL=18, NO=15, PL=28, PT=25, RO=24, SE=24, SI=19, SK=24, SM=27)
def check(cc, bban):
    s = bban + cc + "00"
    n = int("".join(str(int(c, 36)) for c in s))
    return "%02d" % (98 - n % 97)
random.seed(20261215)
rows = []
for cc in sorted(LEN):
    for k in range(2):
        bban = "".join(random.choice("0123456789") for _ in range(LEN[cc] - 4))
        iban = cc + check(cc, bban) + bban
        assert len(iban) == LEN[cc] and int("".join(str(int(c, 36)) for c in bban + cc + iban[2:4])) % 97 == 1
        rows.append((cc, iban))
print("pub const IBANS: &[(&str, &str)] = &[")
for cc, i in rows:
    print(f'    ("{cc}", "{i}"),')
print("];")
