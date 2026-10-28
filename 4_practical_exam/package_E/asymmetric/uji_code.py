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