import pathlib
import sys

TRACK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRACK / "starter"))

import h1_salted_hash as salted

tests = [
    ("malformed string", "not a hash"),
    ("other algorithm", "md5$1000$AAAA$AAAA"),
    ("zero iterations", "pbkdf2_sha256$0$AAAA$AAAA"),
]

for name, data in tests:
    try:
        salted.check("x", data)
        print(f"{name}: FAILED")
    except ValueError:
        print(f"{name}: ValueError")