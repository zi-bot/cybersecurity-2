import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

pt1 = b"DAILY REPORT: 100 UNIT"
pt2 = b"DAILY REPORT: 500 UNIT"

nonce = bytes.fromhex("61b1a51300c5ca279213eda5")
key = os.urandom(32)

ct1 = AESGCM(key).encrypt(nonce, pt1, None)[:-16]
ct2 = AESGCM(key).encrypt(nonce, pt2, None)[:-16]

ct_xor = bytes(c1 ^ c2 for c1, c2 in zip(ct1, ct2))

known_prefix = b"DAILY REPORT: "
recovered_pt2_prefix = bytes(b ^ x for b, x in zip(known_prefix, ct_xor))

print("Recovered PT2 prefix:", recovered_pt2_prefix.decode())