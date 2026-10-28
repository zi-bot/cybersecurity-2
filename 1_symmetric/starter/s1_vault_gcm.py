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


#!/usr/bin/env python3

from __future__ import annotations

import os
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
TAG_SIZE = 16


def create_key() -> bytes:
    """Membuat kunci AES-256 acak."""
    return AESGCM.generate_key(bit_length=256)


def save_key(key: bytes, path: str) -> None:
    """Menyimpan kunci dengan izin akses terbatas."""
    if len(key) != 32:
        raise ValueError("Kunci AES-256 harus 32 byte")

    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(key)
    except Exception:
        raise


def load_key(path: str) -> bytes:
    """Membaca kunci dan memeriksa panjangnya."""
    with open(path, "rb") as f:
        key = f.read()

    if len(key) != 32:
        raise ValueError("Panjang kunci tidak valid")

    return key


def encrypt_data(key: bytes, data: bytes) -> bytes:
    """Mengenkripsi data menggunakan AES-GCM."""
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_data(key: bytes, package: bytes) -> bytes:
    """Mendekripsi data dan memeriksa keasliannya."""
    if len(package) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Paket terenkripsi terlalu pendek")

    nonce = package[:NONCE_SIZE]
    ciphertext = package[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def encrypt_file(key: bytes, src: str, dst: str) -> None:
    """Mengenkripsi file sumber ke file tujuan."""
    with open(src, "rb") as f:
        data = f.read()

    encrypted = encrypt_data(key, data)

    with open(dst, "wb") as f:
        f.write(encrypted)


def decrypt_file(key: bytes, src: str, dst: str) -> None:
    """Menyimpan hasil dekripsi hanya jika autentikasi berhasil."""
    with open(src, "rb") as f:
        package = f.read()

    data = decrypt_data(key, package)

    with open(dst, "wb") as f:
        f.write(data)


def main() -> int:
    key = create_key()

    with tempfile.TemporaryDirectory() as d:
        orig, enc, dec = (
            os.path.join(d, n) for n in ("a.txt", "a.enc", "a.out")
        )

        with open(orig, "wb") as f:
            f.write(b"ORDER-0000001 | dummy data")

        encrypt_file(key, orig, enc)
        decrypt_file(key, enc, dec)

        with open(orig, "rb") as a, open(dec, "rb") as b:
            print("round-trip:", a.read() == b.read())

        with open(enc, "rb") as f:
            broken = bytearray(f.read())

        broken[NONCE_SIZE] ^= 1

        with open(enc, "wb") as f:
            f.write(broken)

        try:
            decrypt_file(key, enc, dec)
            print("tampered ciphertext rejected: NO  <-- something is wrong")
        except InvalidTag:
            print("tampered ciphertext rejected: InvalidTag")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

