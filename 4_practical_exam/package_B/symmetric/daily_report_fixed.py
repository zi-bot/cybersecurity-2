#!/usr/bin/env python3
"""
PRACTICAL EXAM — Symmetric station. FIXED VERSION.

What was wrong in the original daily_report.py:
    - It used AESGCM with a hardcoded, constant _NONCE for every encryption.
    - Reusing a (key, nonce) pair in AES-GCM destroys confidentiality AND
      authenticity: the keystream repeats, so XOR-ing two ciphertexts
      cancels the keystream out and leaks XOR(plaintext1, plaintext2).
      It can also allow forging a valid authentication tag ("forbidden
      attack" on GCM).

The fix:
    - Generate a FRESH random 12-byte nonce for every single encryption
      using os.urandom (a CSPRNG), exactly as GCM's design requires.
    - The nonce is not secret, so we simply prepend it to the ciphertext
      before writing/sending it. The receiver reads the first 12 bytes
      back out as the nonce before decrypting.
    - The key itself is still fixed (same idea as before), but because
      the nonce is always different, the same key can now be reused
      safely across many messages.
"""

from __future__ import annotations

import os
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# NOTE: in a real system this key should come from a secrets manager /
# environment variable, never be hardcoded in source. We keep the same
# key derivation as the original exam file only so decrypting the old
# files still works for comparison; the important fix here is the nonce.
_PART_1 = bytes.fromhex("705077bdb3f172435b62e4fd8a2e266e8b08da1642a6568a701ffc44537dc7b7")
_PART_2 = bytes.fromhex("06d063277e930ab72bf97e76cc4d909336a69a418438ad68814b0cc10568c3d0")

NONCE_SIZE = 12  # bytes, standard for AES-GCM


def _key() -> bytes:
    return bytes(a ^ b for a, b in zip(_PART_1, _PART_2))


def encrypt(plaintext: bytes) -> bytes:
    """Encrypt with a brand-new random nonce, prefixed to the output."""
    nonce = os.urandom(NONCE_SIZE)          # <-- the actual fix
    ct = AESGCM(_key()).encrypt(nonce, plaintext, None)
    return nonce + ct                       # nonce || ciphertext || tag


def decrypt(blob: bytes) -> bytes:
    """Split the stored nonce back off, then decrypt/verify."""
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(_key()).decrypt(nonce, ct, None)


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
    elif len(argv) == 4 and argv[1] == "encrypt":
        with open(argv[2], "rb") as f:
            data = f.read()
        blob = encrypt(data)
        with open(argv[3], "wb") as f:
            f.write(blob)
        print(f"Encrypted {len(data)} bytes -> {argv[3]} (fresh random nonce used)")
        return 0
    print("Symmetric Station — FIXED Warehouse Daily Report Encryptor")
    print("Usage:")
    print("  python3 daily_report_fixed.py encrypt <input_file> <output_file>")
    print("  python3 daily_report_fixed.py decrypt <output_file>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
