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
    """TODO H3: the average seconds to call hash_function('guess<i>') `count` times
    (time.perf_counter)."""
    start = time.perf_counter()
    for i in range(count):
        hash_function(f"guess{i}")
    elapsed = time.perf_counter() - start
    return elapsed / count


if __name__ == "__main__":
    print("Fill in time_per_guess, then call it for md5 and for your KDF.")
