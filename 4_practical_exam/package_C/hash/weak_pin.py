#!/usr/bin/env python3
"""
PRACTICAL EXAM — Hash station. 4-digit PIN storage in a legacy cashier application.
Provided by the instructor. pin_dump.csv lists the users and their PIN hashes (dummy data).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sys


def store_pin(pin: str) -> str:
    salt = secrets.token_bytes(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode(),
        salt,
        600000
    )

    return salt.hex() + "$" + hashed.hex()


def check_pin(pin: str, stored: str) -> bool:
    salt_hex, hash_hex = stored.split("$")
    salt = bytes.fromhex(salt_hex)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode(),
        salt,
        600000
    )

    return hmac.compare_digest(hashed.hex(), hash_hex)


def main(argv):
    if len(argv) == 2 and argv[1] == "--demo":
        pin = "1234"

        account_a = store_pin(pin)
        account_b = store_pin(pin)

        print("Hash akun A:", account_a)
        print("Hash akun B:", account_b)
        print("Hash berbeda:", account_a != account_b)
        print("PIN benar:", check_pin(pin, account_a))
        print("PIN salah:", check_pin("9999", account_a))
        return 0

    if (
        len(argv) == 2
        and len(argv[1]) == 4
        and argv[1].isascii()
        and argv[1].isdigit()
    ):
        print(store_pin(argv[1]))
        return 0

    print("Hash Station — PBKDF2 with Salt")
    print("Usage:")
    print("  python weak_pin.py <4-digit-pin>")
    print("  python weak_pin.py --demo")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))