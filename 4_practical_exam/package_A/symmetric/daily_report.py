#!/usr/bin/env python3
"""
PRACTICAL EXAM — Symmetric station. The warehouse unit's "daily report" script.
Provided by the instructor. Find its weakness, prove it, then fix it.
"""

from __future__ import annotations

import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PART_1 = bytes.fromhex("3c562effed422a2a4ee85ce43ffe86f6c69edd703ee75f1b6b8ea96a18c77f53")
_PART_2 = bytes.fromhex("0c385ea049abef08e9b96d4d28a981777588a9aed42d6cc572e973e21e18a5d2")

def _key() -> bytes:
    return bytes(a ^ b for a, b in zip(_PART_1, _PART_2))


def encrypt(plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(data: bytes) -> bytes:
    if len(data) < 28:
        raise ValueError("Data terenkripsi terlalu pendek")

    nonce = data[:12]
    ciphertext = data[12:]
    return AESGCM(_key()).decrypt(nonce, ciphertext, None)


def main(argv: list[str]) -> int:
    if len(argv) == 3 and argv[1] == "decrypt":
        with open(argv[2], "rb") as f:
            data = f.read()
        try:
            pt = decrypt(data)
            print(pt.decode("utf-8", errors="replace"))
            return 0
        except Exception as err:
            print(f"Decryption failed: {err}")
            return 1
    elif len(argv) == 3 and argv[1] == "encrypt":
        with open(argv[2], "rb") as f:
            data = f.read()
        ct = encrypt(data)
        sys.stdout.buffer.write(ct)
        return 0
    elif len(argv) == 4 and argv[1] == "encrypt":
        with open(argv[2], "rb") as f:
            data = f.read()
        ct = encrypt(data)
        with open(argv[3], "wb") as f:
            f.write(ct)
        print(f"Encrypted {len(data)} bytes -> {argv[3]}")
        return 0
    print("Symmetric Station — Warehouse Daily Report Encryptor")
    print("Usage:")
    print("  python3 daily_report.py decrypt report_monday.enc")
    print("  python3 daily_report.py decrypt report_tuesday.enc")
    print("  python3 daily_report.py encrypt <input_file> <output_file>")
    print("  python3 daily_report.py encrypt <input_file> > <output_file>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
