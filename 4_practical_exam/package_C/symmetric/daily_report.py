#!/usr/bin/env python3
"""
PRACTICAL EXAM — Symmetric station. The warehouse unit's "daily report" script.
Provided by the instructor. Find its weakness, prove it, then fix it.
"""

from __future__ import annotations

import os
import secrets
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12


def _key() -> bytes:
    """Ambil kunci AES-256 dari environment variable."""
    key_hex = os.environ.get("REPORT_KEY")

    if not key_hex:
        raise ValueError("REPORT_KEY belum diatur.")

    try:
        key = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise ValueError("Format REPORT_KEY tidak valid.") from exc

    if len(key) != 32:
        raise ValueError("Kunci harus berukuran 32 byte (64 karakter hex).")

    return key


def encrypt(plaintext: bytes) -> bytes:
    """Enkripsi dengan nonce acak yang baru."""
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, None)

    # Format file: nonce (12 byte) + ciphertext + tag autentikasi.
    return nonce + ciphertext


def decrypt(data: bytes) -> bytes:
    """Baca nonce dari file lalu dekripsi."""
    if len(data) < NONCE_SIZE + 16:
        raise ValueError("Berkas terlalu pendek atau tidak valid.")

    nonce = data[:NONCE_SIZE]
    ciphertext = data[NONCE_SIZE:]

    return AESGCM(_key()).decrypt(nonce, ciphertext, None)


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "encrypt":
        with open(argv[2], "rb") as f:
            plaintext = f.read()

        try:
            encrypted = encrypt(plaintext)
        except Exception as err:
            print(f"Encryption failed: {err}")
            return 1

        with open(argv[3], "wb") as f:
            f.write(encrypted)

        print(f"Encrypted {len(plaintext)} bytes -> {argv[3]}")
        return 0

    if len(argv) == 3 and argv[1] == "decrypt":
        with open(argv[2], "rb") as f:
            data = f.read()

        try:
            plaintext = decrypt(data)
            print(plaintext.decode("utf-8", errors="replace"))
            return 0
        except Exception:
            print("Decryption failed: invalid key or modified file")
            return 1

    print("Symmetric Station — AES-GCM File Encryptor")
    print("Usage:")
    print("  python daily_report.py encrypt <input_file> <output_file>")
    print("  python daily_report.py decrypt <input_file.enc>")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))