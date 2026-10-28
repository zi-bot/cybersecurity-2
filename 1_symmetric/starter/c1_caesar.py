#!/usr/bin/env python3
"""
Practical 2 (BAB 2) — Steps C1–C2: the Caesar cipher, build it then break it (STARTER).

WARNING: Caesar is a TOY cipher. It is used here only to be attacked; never use it to
protect data. The practical's rule still stands: in real work you use a standard library
(e.g. AES-GCM), not a cipher you invented.

C1  Fill in caesar_encrypt and caesar_decrypt:
      - only the letters A-Z and a-z are shifted; upper/lower case is preserved
      - digits, spaces, punctuation and non-ASCII letters do NOT change
      - negative shifts and shifts >= 26 are normalised (shift 27 equals shift 1)
C2  Fill in brute_force: return the 25 key guesses (1..25) as a list of
    (shift, decrypted_text). Then read artifacts/caesar_message.txt, run brute_force, and
    find the one candidate that reads as a sentence. Record: how large is Caesar's keyspace,
    and compare it with AES-256 (2**256).

Expected output once finished (python3 1_symmetric/starter/c1_caesar.py):
    round-trip: True
    keyspace: 25
    ... 25 candidate lines, one of which is a readable English sentence
"""

from __future__ import annotations

import os


def caesar_encrypt(text: str, shift: int) -> str:
    """TODO C1: shift every letter by `shift` (mod 26)."""
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        else:
            result.append(char)
    return "".join(result)


def caesar_decrypt(text: str, shift: int) -> str:
    """TODO C1: the inverse of caesar_encrypt."""
    return caesar_encrypt(text, -shift)


def brute_force(ciphertext: str) -> list[tuple[int, str]]:
    """TODO C2: [(1, decrypted_with_shift_1), ..., (25, decrypted_with_shift_25)]."""
    candidates = []
    for s in range(1, 26):
        candidates.append((s, caesar_decrypt(ciphertext, s)))
    return candidates


def main() -> int:
    sample = "Order-0000042: SHIPPED to Bekasi Warehouse!"
    print("round-trip:", caesar_decrypt(caesar_encrypt(sample, 7), 7) == sample)
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "artifacts", "caesar_message.txt")
    with open(path, encoding="utf-8") as f:
        ciphertext = f.read()
    candidates = brute_force(ciphertext)
    print("keyspace:", len(candidates))
    for shift, text in candidates:
        print(f"  shift {shift:2d}: {text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
