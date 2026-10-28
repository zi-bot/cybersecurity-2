
import pathlib
import sys
import os

TRACK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRACK / "starter"))
sys.path.insert(0, str(TRACK / "weak_code"))

import a3_hybrid as hybrid
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.exceptions import InvalidTag


key1 = rsa.generate_private_key(
    public_exponent=65537, key_size=2048
)
key2 = rsa.generate_private_key(
    public_exponent=65537, key_size=2048
)

pub1 = key1.public_key()
data = os.urandom(10_000)

package = hybrid.hybrid_encrypt(data, pub1)
print("round-trip 10000 bytes:",
      hybrid.hybrid_decrypt(package, key1) == data)

try:
    hybrid.hybrid_decrypt(package, key2)
except ValueError:
    print("wrong key: ValueError")

try:
    hybrid.hybrid_decrypt(package[:100], key1)
except ValueError:
    print("truncated package: ValueError")

try:
    hybrid.hybrid_decrypt(b"", key1)
except ValueError:
    print("empty package: ValueError")

tampered = package[:-1] + bytes([package[-1] ^ 1])
try:
    hybrid.hybrid_decrypt(tampered, key1)
except InvalidTag:
    print("tampered data: InvalidTag")
