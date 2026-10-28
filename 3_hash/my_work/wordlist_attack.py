import pathlib
import sys
import csv

TRACK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRACK / "weak_code"))

import weak_hash_no_salt as weak

wordlist = {}

with open(TRACK / "artifacts" / "small_wordlist.txt", "r") as f:
    for word in f:
        word = word.strip()
        wordlist[weak.store_password(word)] = word

count = 0

with open(TRACK / "artifacts" / "user_dump.csv", "r") as f:
    reader = csv.DictReader(f)

    for row in reader:
        user = row["user"]
        md5 = row["md5_hash"]

        if md5 in wordlist:
            print(f"{user}: {wordlist[md5]}")
            count += 1
        else:
            print(f"{user}: not found")

print(f"cracked {count} of 12")