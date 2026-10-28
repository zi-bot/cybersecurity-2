#!/usr/bin/env python3
"""
PRACTICAL EXAM — Hash station. 4-digit PIN storage in a legacy cashier application.
Provided by the instructor. pin_dump.csv lists the users and their PIN hashes (dummy data).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sys

iterations = 100000  # Perulangan PBKDF2 untuk memperlambat brute-force

def store_pin(pin: str, salt: bytes | None = None) -> tuple[str, str]:
    """salt and hash a 4-digit PIN using PBKDF2 with SHA-256"""
    if len(pin) != 4 or not pin.isdigit():
        raise ValueError("PIN must be a 4-digit number")
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, iterations)
    return key.hex(), salt.hex()


def check_pin(pin: str, stored: str, salt: str) -> bool:
    """verify a 4-digit PIN against a stored hash and salt in constant time"""
    salt_bytes = bytes.fromhex(salt)
    computed_hash, _ = store_pin(pin, salt_bytes)
    return hmac.compare_digest(computed_hash, stored)


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1].isdigit():
        pin = argv[1]
        h, salt = store_pin(pin)
        print(f"PIN: {pin} -> PBKDF2 Hash: {h} | Salt: {salt}")
        return 0

    if len(argv) == 4 and argv[1].isdigit():
        pin, expected_hash, salt = argv[1], argv[2], argv[3]
        match = check_pin(pin, expected_hash, salt)
        print(f"PIN: {pin} vs Hash: {expected_hash[:16]}... -> Match: {match}")
        return 0 if match else 1

    print("Hash Station — Secure Cashier PIN Storage (PBKDF2 SHA-256)")
    print("Usage:")
    print("  python3 weak_pin.py <4-digit-pin>")
    print("  python3 weak_pin.py <4-digit-pin> <expected_hash> <salt>")
    print("Example:")
    print("  python3 weak_pin.py 1234")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
