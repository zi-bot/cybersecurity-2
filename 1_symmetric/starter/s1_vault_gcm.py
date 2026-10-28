#!/usr/bin/env python3
"""
Practical 2 (BAB 2) — Steps S1–S2: an AES-GCM file vault (STARTER).

Fill in every function marked TODO (remove the `raise NotImplementedError`).
Rules: use the `cryptography` library (AESGCM). Do not design your own algorithm.
Keep the key OUTSIDE the repository and the report (e.g. ~/.lab_keys/vault.key).

Encrypted file format:  nonce (12 bytes) + ciphertext + tag (16 bytes)

When finished, run:
    python3 1_symmetric/starter/s1_vault_gcm.py
Expected output:
    round-trip: True
    tampered ciphertext rejected: InvalidTag
"""
from __future__ import annotations

import os
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
TAG_SIZE = 16


def create_key() -> bytes:
    """S1: a random AES-256 key (32 bytes)."""
    return AESGCM.generate_key(bit_length=256)


def save_key(key: bytes, path: str) -> None:
    """S1: write the key to `path` with permissions 0600."""
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        f.write(key)


def load_key(path: str) -> bytes:
    """S1: read the key; reject (ValueError) if its length is not 32 bytes."""
    with open(path, "rb") as f:
        key = f.read()
    if len(key) != 32:
        raise ValueError("Key length is not 32 bytes!")
    return key


def encrypt_data(key: bytes, data: bytes) -> bytes:
    """S1: a NEW random 12-byte nonce for every message; return nonce + ct."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    return nonce + ciphertext


def decrypt_data(key: bytes, package: bytes) -> bytes:
    """S1/S2: split nonce and ct; ValueError if the package is < 28 bytes;
    let InvalidTag surface if the data was changed or the key is wrong."""
    if len(package) < (NONCE_SIZE + TAG_SIZE):
        raise ValueError("Payload terlalu pendek!")
    
    nonce = package[:NONCE_SIZE]
    ciphertext = package[NONCE_SIZE:]
    
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)


def encrypt_file(key: bytes, src: str, dst: str) -> None:
    """S1: read `src`, write the encrypted result to `dst`."""
    with open(src, "rb") as f:
        plaintext = f.read()
    payload = encrypt_data(key, plaintext)
    with open(dst, "wb") as f:
        f.write(payload)


def decrypt_file(key: bytes, src: str, dst: str) -> None:
    """S1: write `dst` ONLY if decryption succeeds."""
    with open(src, "rb") as f:
        package = f.read()
    plaintext = decrypt_data(key, package)
    with open(dst, "wb") as f:
        f.write(plaintext)


def main() -> int:
    key = create_key()
    with tempfile.TemporaryDirectory() as d:
        orig, enc, dec = (os.path.join(d, n) for n in ("a.txt", "a.enc", "a.out"))
        with open(orig, "wb") as f:
            f.write(b"ORDER-0000001 | dummy data")
        encrypt_file(key, orig, enc)
        decrypt_file(key, enc, dec)
        with open(orig, "rb") as a, open(dec, "rb") as b:
            print("S1 round-trip:", a.read() == b.read())
        with open(enc, "rb") as f:
            broken = bytearray(f.read())
        broken[NONCE_SIZE] ^= 1  # S2: flip one bit
        with open(enc, "wb") as f:
            f.write(broken)
        try:
            decrypt_file(key, enc, dec)
            print("S2 tampered ciphertext rejected: NO  <-- something is wrong")
        except InvalidTag:
            print("S2 tampered ciphertext rejected: InvalidTag")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())