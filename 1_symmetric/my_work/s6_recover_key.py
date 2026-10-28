
import base64
import json
import pathlib
import re
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TRACK = pathlib.Path(__file__).resolve().parents[1]
source = (TRACK / "weak_code" / "weak_embedded_key.py").read_text()

key = base64.b64decode(
    re.findall(r'"([A-Za-z0-9+/]{20,}={0,2})"', source)[0]
)

nonce = base64.b64decode(
    re.search(r'_IV_DEFAULT = "([^"]+)"', source).group(1)
)

ciphertext = (TRACK / "artifacts" / "order_vault.enc").read_bytes()

plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
print(plaintext.decode("utf-8"))
