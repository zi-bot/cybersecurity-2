#!/usr/bin/env python3
"""
Practical 2 (BAB 2) — Step H3: measure the cost per guess (STARTER).

After fixing the password storage with h1_salted_hash.py, prove that an attacker is now far
slower. Fill in time_per_guess, then compare:
    md5 (weak_hash_no_salt.store_password)   vs   make_hash(...) from H1
Record the ratio in 3_hash/evidence_sheet.md.
"""

from __future__ import annotations

import time  # noqa: F401



def time_per_guess(hash_function, count: int = 20) -> float:
    """Return the average seconds per guess."""
    if count <= 0:
        raise ValueError("count must be greater than zero")

    start = time.perf_counter()

    for i in range(count):
        hash_function(f"guess{i}")

    elapsed = time.perf_counter() - start
    return elapsed / count



if __name__ == "__main__":
    import pathlib
    import sys

    TRACK = pathlib.Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(TRACK / "starter"))
    sys.path.insert(0, str(TRACK / "weak_code"))

    from weak_hash_no_salt import store_password
    from h1_salted_hash import make_hash

    md5_time = time_per_guess(store_password)
    kdf_time = time_per_guess(make_hash)

    print(f"MD5 average time per guess: {md5_time:.8f} seconds")
    print(f"PBKDF2 average time per guess: {kdf_time:.8f} seconds")
    print(f"PBKDF2/MD5 time ratio: {kdf_time / md5_time:.2f}x")
