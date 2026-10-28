# Station Answer: <symmetric | asymmetric | hash>

## 1. Finding
- Weakness: Penggunaan fungsi hash kriptografis yang usang dan cepat (SHA-1) tanpa salt, digabungkan dengan ruang entropi PIN 4-digit yang sangat kecil (hanya 10.000 kemungkinan dari 0000–9999). Hal ini memungkinkan penyerang memulihkan teks asli PIN secara instan melalui serangan brute-force atau lookup table.
- location: weak_pin.py:13

## 2. Evidence
import hashlib

target_hash = "7091ea48a07d48d8ee45f0e9a096c4d22dd9b99f"

recovered_pin = None
for i in range(10000):
    candidate = f"{i:04d}"
    if hashlib.sha1(candidate.encode()).hexdigest() == target_hash:
        recovered_pin = candidate
        break

print("Recovered PIN:", recovered_pin)

Output:
Recovered PIN: 4821

## 3. Fix

import hashlib
import secrets
import hmac

ITERATIONS = 600_000


def store_pin(pin: str) -> str:
    salt = secrets.token_bytes(16)

    pin_hash = hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode(),
        salt,
        ITERATIONS
    )

    return f"{salt.hex()}:{pin_hash.hex()}"


def check_pin(pin: str, stored: str) -> bool:
    try:
        salt_hex, expected_hash = stored.split(":")
        salt = bytes.fromhex(salt_hex)

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            pin.encode(),
            salt,
            ITERATIONS
        )

        return hmac.compare_digest(
            actual_hash.hex(),
            expected_hash
        )
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    pin = input("Masukkan PIN 4 digit: ")

    if len(pin) != 4 or not pin.isdigit():
        print("PIN harus terdiri dari 4 digit.")
    else:
        stored = store_pin(pin)
        print("Data PIN tersimpan:", stored)
        print("Verifikasi:", check_pin(pin, stored))



Verification Proof:
Recovered PIN: None

## 4. Explanation
Penggunaan SHA-1 tanpa salt berbahaya karena hash dapat diuji dengan cepat terhadap seluruh kemungkinan PIN empat digit. Penyerang yang memperoleh database hash dapat melakukan brute force secara offline tanpa melewati pembatasan percobaan pada aplikasi. PBKDF2-HMAC-SHA256 dengan salt unik memperlambat setiap percobaan dan mencegah hash identik untuk PIN yang sama tersimpan secara langsung.