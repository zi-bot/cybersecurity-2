# Station Answer: hash

## 1. Finding
- Weakness: Use of unsalted, cryptographically broken SHA-1 hash function for password/PIN storage, making credentials vulnerable to offline brute-force and precomputed rainbow table attacks.
- Location: weak_pin.py:12-13

## 2. Evidence
Karena PIN hanya terdiri dari 4 digit angka (`0000` hingga `9999`), terdapat 10.000 kombinasi yang dapat dikalkulasi secara instan melalui pencarian lokal (*offline brute-force*).

Kode Python untuk memecahkan seluruh hash pada `pin_dump.csv`:
```python
import csv
import hashlib
rainbow_table = {}
for i in range(10000):
    pin = f"{i:04d}"
    h = hashlib.sha1(pin.encode()).hexdigest()
    rainbow_table[h] = pin

with open("pin_dump.csv", newline="") as f:
    reader = csv.DictReader(f)
    for row in reader:
        user = row["user"]
        sha1_hash = row["sha1_hash"]
        recovered_pin = rainbow_table.get(sha1_hash, "NOT FOUND")
        print(f"User: {user:6s} | Hash: {sha1_hash} | Recovered PIN: {recovered_pin}")