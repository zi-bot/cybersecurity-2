import csv
from send_status import VALID_STATUSES, encrypt_status

# 1. Bikin tabel pemeta nilai hex ke status teks
lookup_table = {}
for status in VALID_STATUSES:
    hex_val = encrypt_status(status).hex()
    lookup_table[hex_val] = status.decode()

# 2. Baca order_status.csv dan terjemahkan statusnya
with open("order_status.csv", "r") as f:
    reader = csv.reader(f)
    for row in reader:
        if not row or len(row) < 2:
            continue
        order_id = row[0].strip()
        ciphertext_hex = row[1].strip()

        status_terjemahan = lookup_table.get(
            ciphertext_hex, "Status Tidak Valid"
        )
        print(f"Nomor Order: {order_id} | Status: {status_terjemahan}")
