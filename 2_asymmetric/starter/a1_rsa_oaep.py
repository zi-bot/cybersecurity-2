#!/usr/bin/env python3
"""
Practical 2 (BAB 2) — Step A1: RSA-OAEP (STARTER).

Fill in the TODO parts. Use the `cryptography` library; OAEP with SHA-256 (MGF1 SHA-256).
Expected output once finished:
    round-trip: True
    two encryptions identical? False
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_key():
    """Generate an RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )


def encrypt_oaep(pub, message: bytes) -> bytes:
    """Encrypt using RSA-OAEP with SHA-256."""
    return pub.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_oaep(priv, ciphertext: bytes) -> bytes:
    """Decrypt using RSA-OAEP with SHA-256."""
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def main() -> int:
    priv = generate_key()
    pub = priv.public_key()
    message = b"session key: 0123456789abcdef"
    c1, c2 = encrypt_oaep(pub, message), encrypt_oaep(pub, message)
    print("round-trip:", decrypt_oaep(priv, c1) == message)
    print("two encryptions identical?", c1 == c2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
