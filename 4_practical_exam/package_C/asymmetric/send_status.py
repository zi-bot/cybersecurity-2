#!/usr/bin/env python3
"""
PRACTICAL EXAM — Asymmetric station. The sender of order statuses to a partner.
Provided by the instructor. An order status is always one of VALID_STATUSES.
order_status.csv holds the order number and the ciphertext (hex).
"""

from __future__ import annotations

import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

VALID_STATUSES = (b"PROCESSING", b"PENDING", b"SHIPPED")
_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(_DIR, "public_key.pem"), "rb") as f:
    _PUB = serialization.load_pem_public_key(f.read())


def encrypt_status(status: bytes) -> bytes:
    """Encrypt status using RSA-OAEP with SHA-256."""
    return _PUB.encrypt(
        status,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1].encode() in VALID_STATUSES:
        status = argv[1].encode()
        ciphertext = encrypt_status(status)

        print(f"Status: {argv[1]}")
        print(f"Ciphertext (hex):\n{ciphertext.hex()}")
        return 0

    print("Asymmetric Station — Order Status Sender (RSA-OAEP)")
    print(f"Valid statuses: {[s.decode() for s in VALID_STATUSES]}")
    print("Usage:")
    print("  python send_status.py <STATUS>")
    print("Example:")
    print("  python send_status.py PENDING")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
