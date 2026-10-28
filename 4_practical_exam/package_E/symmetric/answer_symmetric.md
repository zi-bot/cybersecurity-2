# Station Answer: symmetric

## 1. Finding
- Weakness: Hardcoded cryptographic key generated via XOR of two static byte arrays in the source code, combined with potential nonce reuse risks if static nonces are ever used or key management is static.
- Location: daily_report.py:12-18

## 2. Evidence
Untuk memulihkan teks asal (plaintext) dari `report_monday.enc` dan `report_tuesday.enc`, kita dapat mengeksekusi kunci yang diturunkan dari operasi XOR `_PART_1` dan `_PART_2` pada skrip `daily_report.py`.

Kode Python untuk memulihkan plaintext:

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PART_1 = bytes.fromhex("88a056649e277025530c54af9275592ac0feebc24d83a14891e2493bada0bde7")
_PART_2 = bytes.fromhex("23e16859eb5add0eb63eedb89187a0ca31476bcb9085f37baa92478bdadf136c")
key = bytes(a ^ b for a, b in zip(_PART_1, _PART_2))

def decrypt_file(filename):
    with open(filename, "rb") as f:
        data = f.read()
    nonce = data[:12]
    ciphertext = data[12:]
    return AESGCM(key).decrypt(nonce, ciphertext, None).decode('utf-8')

print("Monday Report:", decrypt_file("report_monday.enc"))
print("Tuesday Report:", decrypt_file("report_tuesday.enc"))