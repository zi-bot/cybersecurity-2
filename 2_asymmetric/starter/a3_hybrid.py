#!/usr/bin/env python3
"""
Practical 2 (BAB 2) — Step A3: hybrid encryption (STARTER).

Design: a random AES-256 key -> encrypt the data with AES-GCM (random 12-byte nonce); wrap that
AES key with RSA-OAEP. Package format:

    wrapped_key_length (2 bytes, big-endian) | wrapped_key | nonce | ct+tag

Behaviour you must handle:
  - empty / truncated package / a lying length header  -> ValueError
  - wrong private key                                  -> ValueError
  - data was modified                                  -> InvalidTag
Expected output once finished:
    10000 bytes: round-trip True
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes  # noqa: F401
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: F401
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401


def hybrid_encrypt(data: bytes, pub) -> bytes:
    """TODO A3: build the package in the format above."""
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, None)
    wrapped_key = pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return len(wrapped_key).to_bytes(2, byteorder="big") + wrapped_key + nonce + ciphertext


def hybrid_decrypt(package: bytes, priv) -> bytes:
    """TODO A3: parse the package, checking lengths BEFORE slicing."""
    if len(package) < 2:
        raise ValueError("truncated package")

    wrapped_len = int.from_bytes(package[:2], byteorder="big")
    if wrapped_len <= 0 or wrapped_len != 256:
        raise ValueError("invalid wrapped key length")

    offset = 2 + wrapped_len
    if len(package) < offset + 12 + 16:
        raise ValueError("truncated package")

    wrapped_key = package[2:offset]
    nonce = package[offset:offset + 12]
    ciphertext = package[offset + 12:]

    aes_key = priv.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


def main() -> int:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    data = os.urandom(10_000)
    package = hybrid_encrypt(data, priv.public_key())
    print(f"{len(data)} bytes: round-trip", hybrid_decrypt(package, priv) == data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
