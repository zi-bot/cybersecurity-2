 Station Answer: Hash

## 1. Finding
- Weakness: MMenggunakan hash mentah SHA-1 yang usang tanpa salt (unsalted) dan tanpa perulangan komputasi. PIN 4-digit hanya memiliki 10.000 kemungkinan (0000–9999) sehingga sangat mudah dibongkar secara brute-force dalam hitungan milidetik. Selain itu, dua pengguna dengan PIN yang sama (tika dan vina) menghasilkan nilai hash yang identik, mempermudah peretas melihat pola kredensial.
- Location: weak_pin:12

## 2. Evidence
import hashlib
import csv


target_data = []
with open("pin_dump.csv", "r") as f:
    reader = csv.reader(f)
    next(reader, None)  
    for row in reader:
        if row:
            target_data.append((row[0].strip(), row[1].strip()))

pin_to_hash = {}
for i in range(10000):
    pin = f"{i:04d}"
    h = hashlib.sha1(pin.encode("utf-8")).hexdigest()
    pin_to_hash[h] = pin

for user, h in target_data:
    recovered_pin = pin_to_hash.get(h, "NOT FOUND")
    print(f"User: {user} | Recovered PIN: {recovered_pin}")

Output:
PS C:\Cyber Security\cybersecurity-2\4_practical_exam\package_D\hash> python weak_pin.py
User: rina | Recovered PIN: 7320
User: sapto | Recovered PIN: 5841
User: tika | Recovered PIN: 3187
User: udin | Recovered PIN: 9064
User: vina | Recovered PIN: 3187
User: wawan | Recovered PIN: 1256

## 3. Fix
def store_pin(pin: str, salt: bytes | None = None) -> tuple[str, str]:
    """salt and hash a 4-digit PIN using PBKDF2 with SHA-256"""
    if len(pin) != 4 or not pin.isdigit():
        raise ValueError("PIN must be a 4-digit number")
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), salt, iterations)
    return key.hex(), salt.hex()


def check_pin(pin: str, stored: str, salt: str) -> bool:
    """verify a 4-digit PIN against a stored hash and salt in constant time"""
    salt_bytes = bytes.fromhex(salt)
    computed_hash, _ = store_pin(pin, salt_bytes)
    return hmac.compare_digest(computed_hash, stored)

Verification Proof:
PS C:\Cyber Security\cybersecurity-2\4_practical_exam\package_D\hash> python weak_pin.py 3187
PIN: 3187 -> PBKDF2 Hash: f6fec179381672cfa8eca0e028e5ba68a2754f8f761af8c2391a2860cd37e201 | Salt: c254ac1b41106d41d7abeb0bb3db1b20
PS C:\Cyber Security\cybersecurity-2\4_practical_exam\package_D\hash> python weak_pin.py 3187
PIN: 3187 -> PBKDF2 Hash: fc275cfb66e07192453d8139915d49f53cd69ae3f940d602629ce901f1758f2b | Salt: 2e90901dddd85b5ce2ffecb2c880329e

## 4. Explanation
Menyimpan hash tanpa salt sangat berbahaya karena peretas yang mencuri basis data dapat secara instan membongkar seluruh PIN pengguna menggunakan rainbow table atau pencocokan massal. Penggunaan PBKDF2-HMAC-SHA256 dengan salt acak unik memastikan PIN yang sama (seperti milik tika dan vina) menghasilkan hash yang berbeda total, sekaligus memperlambat serangan offline brute-force melalui perulangan komputasi. Fungsi hmac.compare_digest juga mencegah serangan celah waktu (timing attack). Namun, batas keamanan utama tetap pada ruang kombinasi PIN 4-digit yang terbatas (10.000 kemungkinan), sehingga sistem wajib dilengkapi pembatasan percobaan login (rate limiting).