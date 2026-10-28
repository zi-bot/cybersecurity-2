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

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa


OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def hybrid_encrypt(data: bytes, public_key) -> bytes:
    """Enkripsi data dengan AES-GCM dan bungkus kunci AES memakai RSA-OAEP."""
    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    ciphertext = AESGCM(aes_key).encrypt(nonce, data, None)
    wrapped_key = public_key.encrypt(aes_key, OAEP)

    header = len(wrapped_key).to_bytes(2, "big")
    return header + wrapped_key + nonce + ciphertext


def hybrid_decrypt(package: bytes, private_key) -> bytes:
    """Periksa paket, buka kunci AES, lalu dekripsi data."""
    if len(package) < 2:
        raise ValueError("Package too short")

    wrapped_length = int.from_bytes(package[:2], "big")

    if wrapped_length == 0:
        raise ValueError("Invalid wrapped key length")

    minimum_length = 2 + wrapped_length + 12 + 16
    if len(package) < minimum_length:
        raise ValueError("Package too short")

    start = 2
    end = start + wrapped_length

    wrapped_key = package[start:end]
    nonce = package[end:end + 12]
    ciphertext = package[end + 12:]

    try:
        aes_key = private_key.decrypt(wrapped_key, OAEP)
    except ValueError as exc:
        raise ValueError("Unable to unwrap AES key") from exc

    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


def main() -> int:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    data = os.urandom(10_000)
    package = hybrid_encrypt(data, public_key)
    decrypted = hybrid_decrypt(package, private_key)

    print(f"10000 bytes: round-trip {decrypted == data}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
