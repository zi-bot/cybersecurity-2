# Station Answer: symmetric

## 1. Finding
_NONCE ditetapkan tetap, lalu dipakai kembali oleh encrypt() pada baris 22 dengan kunci yang sama. Penggunaan ulang nonce AES-GCM membuat enkripsi rentan terhadap kebocoran hubungan antar-plaintext; jika penyerang mengetahui satu plaintext, ia dapat memulihkan plaintext lain dari ciphertext yang nonce-nya sama.

## 2. Evidence

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

pt1 = b"DAILY REPORT: 100 UNIT"
pt2 = b"DAILY REPORT: 500 UNIT"

nonce = bytes.fromhex("61b1a51300c5ca279213eda5")
key = os.urandom(32)

ct1 = AESGCM(key).encrypt(nonce, pt1, None)[:-16]
ct2 = AESGCM(key).encrypt(nonce, pt2, None)[:-16]

ct_xor = bytes(c1 ^ c2 for c1, c2 in zip(ct1, ct2))

known_prefix = b"DAILY REPORT: "
recovered_pt2_prefix = bytes(b ^ x for b, x in zip(known_prefix, ct_xor))

print("Recovered PT2 prefix:", recovered_pt2_prefix.decode())


Output:
Recovered PT2 prefix: DAILY REPORT: 

## 3. Fix

def encrypt(plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(data: bytes) -> bytes:
    if len(data) < 28:
        raise ValueError("Data terenkripsi terlalu pendek")

    nonce = data[:12]
    ciphertext = data[12:]
    return AESGCM(_key()).decrypt(nonce, ciphertext, None)


Verification Proof:
Decryption failed:

## 4. Explanation
Penggunaan nilai nonce yang sama pada enkripsi AES-GCM sangat berbahaya di lingkungan produksi karena mode operasi ini berbasis aliran enkripsi konter, sehingga melakukan operasi XOR terhadap dua ciphertext dengan nonce identik akan secara langsung mengeliminasi fungsi kunci dan menyisakan hasil XOR dari kedua teks asli. Keadaan ini memungkinkan pihak luar untuk merekonstruksi isi pesan rahasia tanpa memerlukan kunci utama, sekaligus membuka celah perhitungan subkunci otentikasi untuk melakukan pemalsuan integritas data.