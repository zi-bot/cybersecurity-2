#!/usr/bin/env python3
"""
PRACTICAL EXAM — Hash station. FIXED VERSION.

What was wrong in the original weak_pin.py:
    - PINs were hashed with plain, unsalted SHA-1: hash = SHA1(pin).
    - A 4-digit PIN only has 10,000 possible values (0000-9999). SHA-1
      is extremely fast, so an attacker can hash ALL 10,000 PINs in a
      fraction of a second and build a full lookup table ("rainbow
      table") that cracks every hash in the dump instantly.
    - Because there's no salt, two users with the SAME pin end up with
      the IDENTICAL hash (visible directly in pin_dump.csv: 'rina' and
      'tika' share one hash), leaking equality information even before
      anything is cracked.

The fix:
    - Add a random, unique SALT per user (os.urandom), so identical
      PINs no longer produce identical hashes.
    - Use a deliberately SLOW, purpose-built password hashing function
      (PBKDF2-HMAC-SHA256 with a high iteration count) instead of a
      single fast general-purpose hash. This makes brute-forcing the
      small 10,000-PIN keyspace computationally expensive instead of
      instantaneous.
    - Store salt + hash together; verify using a constant-time compare
      (hmac.compare_digest) to avoid timing side-channels.

Note: for a real cashier/login system you should also rate-limit PIN
attempts at the application layer (e.g. lock after 5 tries) because
4-digit PINs are inherently low-entropy no matter how they're hashed.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys

ITERATIONS = 200_000
SALT_SIZE = 16


def store_pin(pin: str, salt: bytes | None = None) -> str:
    """Return 'salt_hex$hash_hex' for storage."""
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    derived = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, ITERATIONS)
    return f"{salt.hex()}${derived.hex()}"


def check_pin(pin: str, stored: str) -> bool:
    """stored is 'salt_hex$hash_hex' as produced by store_pin()."""
    try:
        salt_hex, hash_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except ValueError:
        return False
    derived = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, ITERATIONS)
    return hmac.compare_digest(derived.hex(), hash_hex)


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1].isdigit():
        pin = argv[1]
        stored = store_pin(pin)
        print(f"PIN: {pin} -> stored value (salt$hash): {stored}")
        return 0
    if len(argv) == 3 and argv[1].isdigit():
        pin, expected = argv[1], argv[2]
        match = check_pin(pin, expected)
        print(f"PIN: {pin} vs stored: {expected} -> Match: {match}")
        return 0 if match else 1
    print("Hash Station — FIXED Cashier PIN Storage (Salted PBKDF2-HMAC-SHA256)")
    print("Usage:")
    print("  python3 weak_pin_fixed.py <4-digit-pin>")
    print("  python3 weak_pin_fixed.py <4-digit-pin> <stored salt$hash>")
    print("Example:")
    print("  python3 weak_pin_fixed.py 1234")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))