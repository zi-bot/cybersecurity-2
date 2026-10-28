1. ## 1. Finding
- Weakness: Sistem lama menyimpan PIN menggunakan SHA-1 tanpa salt. Karena PIN hanya terdiri dari empat angka, penyerang bisa mencoba semua kemungkinan PIN dari 0000 sampai 9999 untuk menemukan PIN yang cocok dengan hash.
- Location: weak_pin.py - pin_dump.csv, kolom sha1_hash.

## 2. Evidence
Pengujian dilakukan dengan mencoba semua kemungkinan PIN empat digit, kemudian membandingkan hasil hash SHA-1 dengan hash yang ada di pin_dump.csv.

Kode Python:

import csv
import hashlib

def crack_pin(target_hash):
    for number in range(10000):
        pin = f"{number:04d}"
        result = hashlib.sha1(pin.encode()).hexdigest()

        if result == target_hash:
            return pin

    return None

with open("pin_dump.csv", newline="", encoding="utf-8-sig") as f:
    for row in csv.DictReader(f):
        pin = crack_pin(row["sha1_hash"])
        print(f"User: {row['user']}, PIN ditemukan: {pin}")

Perintah untuk menjalankan pengujian:
python .\crack_pin.py

Output:
Tempelkan hasil yang muncul setelah perintah dijalankan.

Pengujian ini bertujuan mengetahui apakah PIN empat digit dapat ditemukan dengan mencoba seluruh kemungkinan PIN yang tersedia.

## 3. Fix
Perbaikan dilakukan dengan mengganti penyimpanan hash SHA-1 menjadi PBKDF2-HMAC-SHA256. Sistem menggunakan salt acak 16 byte dan 600.000 iterasi agar proses menebak PIN menjadi lebih sulit.

Kode perbaikan:

import hashlib
import hmac
import secrets

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

Verification Proof:

Jalankan perintah berikut:

python .\weak_pin.py --demo

Hasil yang diharapkan:

Hash akun A: [salt dan hash]
Hash akun B: [salt dan hash]
Hash berbeda: True
PIN benar: True
PIN salah: False

Hasil tersebut menunjukkan bahwa PIN yang benar dapat diterima, PIN yang salah ditolak, dan PIN yang sama menghasilkan hash berbeda karena menggunakan salt acak.

## 4. Explanation
Penyimpanan PIN menggunakan SHA-1 tanpa salt mudah diserang karena penyerang bisa mencoba semua kemungkinan PIN empat digit. Untuk mengatasinya, digunakan PBKDF2-HMAC-SHA256 dengan salt acak dan 600.000 iterasi agar proses menebak PIN lebih lambat. hmac.compare_digest() digunakan untuk membandingkan hash dengan lebih aman. Sistem juga perlu membatasi percobaan login dan menjaga keamanan database.