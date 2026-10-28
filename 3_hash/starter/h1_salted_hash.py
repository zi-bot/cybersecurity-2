#!/usr/bin/env python3
"""
Practical 2 (BAB 2) — Step H1: salted password hashing (STARTER).

Stored format (one string):
    pbkdf2_sha256$<iterations>$<salt_base64>$<hash_base64>

Rules: hashlib.pbkdf2_hmac('sha256', ...), a random 16-byte salt per password, a default of
>= 600000 iterations, and comparison with hmac.compare_digest.
Behaviour you must handle:
  - wrong password                                       -> check() returns False
  - a corrupt stored string / another algorithm /
    iterations <= 0 or absurdly large                    -> ValueError
Expected output once finished:
    two hashes differ? True
    correct password verifies? True
    wrong password verifies? False
"""

from __future__ import annotations

import base64  # noqa: F401
import hashlib  # noqa: F401
import hmac  # noqa: F401
import os  # noqa: F401

ITERATIONS = 600_000



def make_hash(password: str, iterations: int = ITERATIONS) -> str:
    """Build a stored password hash with a fresh random salt."""
    if iterations <= 0 or iterations > 10_000_000:
        raise ValueError("Invalid iteration count")

    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    )

    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(password_hash).decode("ascii")

    return f"pbkdf2_sha256${iterations}${salt_b64}${hash_b64}"


def check(password: str, stored: str) -> bool:
    """Verify a password against its stored hash."""
    try:
        algorithm, iterations_text, salt_b64, hash_b64 = stored.split("$")

        if algorithm != "pbkdf2_sha256":
            raise ValueError("Unsupported algorithm")

        iterations = int(iterations_text)
        if iterations <= 0 or iterations > 10_000_000:
            raise ValueError("Invalid iteration count")

        salt = base64.b64decode(salt_b64, validate=True)
        expected_hash = base64.b64decode(hash_b64, validate=True)

        if len(salt) != 16 or not expected_hash:
            raise ValueError("Invalid stored hash")

    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("Corrupt stored password hash") from exc

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations
    )

    return hmac.compare_digest(actual_hash, expected_hash)

def main() -> int:
    a, b = make_hash("SecretPass123", 100_000), make_hash("SecretPass123", 100_000)
    print("two hashes differ?", a != b)
    print("correct password verifies?", check("SecretPass123", a))
    print("wrong password verifies?", check("wrong", a))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
