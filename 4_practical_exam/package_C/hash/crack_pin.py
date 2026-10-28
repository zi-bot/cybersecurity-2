import csv
import hashlib

def crack_pin(target_hash):
    for number in range(10000):
        pin = f"{number:04d}"
        candidate_hash = hashlib.sha1(pin.encode()).hexdigest()

        if candidate_hash == target_hash:
            return pin

    return None

with open("pin_dump.csv", newline="", encoding="utf-8-sig") as f:
    for row in csv.DictReader(f):
        pin = crack_pin(row["sha1_hash"])
        print(f"User: {row['user']}, PIN ditemukan: {pin}")
