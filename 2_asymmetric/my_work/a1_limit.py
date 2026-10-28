
import pathlib
import sys

TRACK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRACK / "starter"))
sys.path.insert(0, str(TRACK / "weak_code"))

import a1_rsa_oaep as tools

key = tools.generate_key()
pub = key.public_key()

for size in (190, 191):
    try:
        tools.encrypt_oaep(pub, b"x" * size)
        print(f"{size} bytes: ok")
    except ValueError:
        print(f"{size} bytes: ValueError")
