import pathlib
import sys

TRACK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRACK / "starter"))

import h1_salted_hash as salted

stored = salted.make_hash("SecretPass123")

print("login ok:", salted.check("SecretPass123", stored))
print("login wrong password:", salted.check("wrong", stored))