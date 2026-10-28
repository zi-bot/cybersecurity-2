# Station Answer: asymmetric

## 1. Finding
- Weakness: Usage of unpadded / deterministic "Bare" RSA encryption ($c = m^e \pmod n$), which allows ciphertext matching through dictionary/pre-computation attacks against small domain spaces.
- Location: send_status.py:21-25

## 2. Evidence
Karena status yang dikirimkan terbatas pada 3 kemungkinan (`PROCESSING`, `PENDING`, `SHIPPED`), penyerang cukup mengagregasi teks sandi kandidat dengan kunci publik yang tersedia di `public_key.pem`, lalu mencocokkan hash/ciphertext pada `order_status.csv`.

Kode Python untuk memulihkan seluruh data `order_status.csv`:

```python
import csv
from cryptography.hazmat.primitives import serialization

with open("public_key.pem", "rb") as f:
    pub = serialization.load_pem_public_key(f.read()).public_numbers()

VALID_STATUSES = (b"PROCESSING", b"PENDING", b"SHIPPED")
k = (pub.n.bit_length() + 7) // 8

lookup = {}
for status in VALID_STATUSES:
    m = int.from_bytes(status.rjust(k, b"\x00"), "big")
    c = pow(m, pub.e, pub.n).to_bytes(k, "big").hex()
    lookup[c] = status.decode()

with open("order_status.csv", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        print(f"{row['order_no']}: {lookup.get(row['encrypted_status_hex'], 'UNKNOWN')}")