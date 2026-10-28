#!/usr/bin/env python3
"""
PRACTICAL EXAM — Asymmetric station. FIXED VERSION.

What was wrong in the original send_status.py:
    - It implemented "bare"/"textbook" RSA: c = m^e mod n, with NO padding.
    - Textbook RSA is deterministic: the same plaintext always produces
      the exact same ciphertext under the same public key.
    - Because the message space here is tiny (only 3 possible statuses),
      an attacker only needs the PUBLIC key (which is not secret) to
      pre-compute the ciphertext for every possible status and then
      simply look up which one matches each row in order_status.csv.
      No private key or factoring attack is even needed.

The fix:
    - Use RSA-OAEP (Optimal Asymmetric Encryption Padding) via the
      `cryptography` library's high-level `encrypt()` API.
    - OAEP mixes in random padding bytes before the RSA exponentiation,
      so encrypting the SAME plaintext twice produces a DIFFERENT
      ciphertext every time (semantic security / IND-CPA). An attacker
      can no longer build a lookup table from the public key alone.
"""

from __future__ import annotations

import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

VALID_STATUSES = (b"PROCESSING", b"PENDING", b"SHIPPED")
_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(_DIR, "public_key.pem"), "rb") as _f:
    _PUB_KEY = serialization.load_pem_public_key(_f.read())

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def encrypt_status(status: bytes) -> bytes:
    """RSA-OAEP encryption: randomized, so ciphertext differs every call."""
    return _PUB_KEY.encrypt(status, _OAEP)


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1].encode() in VALID_STATUSES:
        status = argv[1].encode()
        ct1 = encrypt_status(status)
        ct2 = encrypt_status(status)  # encrypt the same status again
        print(f"Status: {argv[1]}")
        print(f"Ciphertext #1 (hex):\n{ct1.hex()}")
        print(f"Ciphertext #2 (hex):\n{ct2.hex()}")
        print(f"\nSame plaintext, different ciphertext: {ct1 != ct2}")
        return 0
    print("Asymmetric Station — FIXED Order Status Sender (RSA-OAEP)")
    print(f"Valid statuses: {[s.decode() for s in VALID_STATUSES]}")
    print("Usage:")
    print("  python3 send_status_fixed.py <STATUS>")
    print("Example:")
    print("  python3 send_status_fixed.py PENDING")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))