# Jawaban — Stasiun Hash (Penyimpanan PIN)

## 1. Finding

`weak_pin.py` menyimpan PIN kasir sebagai `SHA1(pin)` biasa — **tanpa salt**
dan memakai algoritma hash yang **sangat cepat** (SHA-1 dirancang untuk
cepat, bukan untuk menyimpan password/PIN). Karena PIN hanya 4 digit, ruang
kemungkinannya cuma **10.000** kombinasi (`0000`–`9999`). Gabungan dua
kelemahan ini (tanpa salt + hash cepat + ruang kunci kecil) membuat seluruh
isi `pin_dump.csv` bisa dibongkar instan dengan tabel pra-hitung.

## 2. Evidence

Saya menjalankan brute force langsung terhadap seluruh ruang 10.000
kemungkinan PIN dan mencocokkannya ke `pin_dump.csv`:

```python
import hashlib, csv

table = {}
for i in range(10000):
    pin = f"{i:04d}"
    table[hashlib.sha1(pin.encode()).hexdigest()] = pin

with open("pin_dump.csv") as f:
    reader = csv.reader(f)
    next(reader)  # skip header
    for user, h in reader:
        print(user, "->", table.get(h, "???"))
```

Hasil nyata (dijalankan < 1 detik untuk seluruh 10.000 hash):
```
rina     hash=1f06341021418df93e43562201909ea650bbca60 -> PIN=9035
sapto    hash=e08277878957dd2d0bbf2023a920dcf2000f2d81 -> PIN=6128
tika     hash=1f06341021418df93e43562201909ea650bbca60 -> PIN=9035
udin     hash=b17656c96367beb7e3dfa2463ec218335590db73 -> PIN=3471
vina     hash=5544a9c65fe1288084484177a840a6ac37117736 -> PIN=5509
wawan    hash=85786f17cc4bca8c0cdb82e596b7ae761b435c59 -> PIN=8264
```

**Semua 6 PIN berhasil dibongkar 100%.** Perhatikan juga: `rina` dan `tika`
punya hash yang **persis sama** (`1f0634...`). Ini membuktikan ketiadaan
salt — tanpa perlu membongkar hash-nya sekalipun, penyerang sudah tahu
kedua user itu memakai PIN yang identik hanya dengan membandingkan
hash mentahnya di database yang bocor.

## 3. Fix

File perbaikan: `weak_pin_fixed.py` (satu folder dengan file ini).

Perubahan intinya:
- Tambahkan **salt acak unik per user** (`os.urandom(16)`), sehingga PIN
  yang sama antar-user tidak lagi menghasilkan hash yang sama.
- Ganti SHA-1 polos dengan **PBKDF2-HMAC-SHA256** dengan 200.000 iterasi
  (fungsi hash password yang *sengaja dibuat lambat*), sehingga brute force
  10.000 kemungkinan PIN menjadi jauh lebih mahal secara komputasi.
- Verifikasi PIN memakai `hmac.compare_digest` (constant-time) untuk
  menghindari celah timing attack.

Potongan kode kunci:
```python
def store_pin(pin: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    derived = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, ITERATIONS)
    return f"{salt.hex()}${derived.hex()}"

def check_pin(pin: str, stored: str) -> bool:
    salt_hex, hash_hex = stored.split("$", 1)
    salt = bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, ITERATIONS)
    return hmac.compare_digest(derived.hex(), hash_hex)
```

Pengujian nyata — menyimpan PIN `9035` (milik rina/tika) dua kali:
```
PIN: 9035 -> bce786f5...$9a6b9760...
PIN: 9035 -> c208e1a4...$542355bd...
two stores of same PIN differ: True
check_pin correct: True
check_pin wrong pin: False
```
PIN yang sama kini menghasilkan nilai simpanan yang berbeda setiap kali
(karena salt-nya acak), tapi verifikasi tetap berfungsi benar.

## 4. Explanation

Hash kriptografis umum (SHA-1, SHA-256, dll.) dirancang untuk **cepat**
karena dipakai untuk hal seperti checksum/integritas data — justru sifat
inilah yang berbahaya untuk password/PIN, karena kecepatan yang sama juga
dipakai penyerang untuk menebak. Untuk PIN 4 digit yang ruang kuncinya
cuma 10.000, hash cepat apa pun — SHA-1 atau bahkan SHA-256 — akan tetap
bisa ditembus brute force dalam hitungan detik jika tidak ada salt dan
tidak ada faktor "pelambat" tambahan.

**Salt** mengatasi masalah pengulangan pola: setiap user mendapat input
tambahan yang unik dan acak sebelum di-hash, sehingga tidak mungkin lagi
membuat satu tabel pra-hitung ("rainbow table") yang berlaku untuk semua
user sekaligus — penyerang harus membangun ulang tabel 10.000 entri untuk
**setiap** salt/user, bukan sekali untuk seluruh database.

**Iterasi berulang (PBKDF2 / idealnya bcrypt, scrypt, atau Argon2)**
mengatasi masalah kecepatan: dengan memaksa fungsi hash dijalankan ratusan
ribu kali per percobaan, biaya komputasi untuk menebak satu PIN naik dari
hampir nol menjadi signifikan, sehingga brute force 10.000 kemungkinan
menjadi jauh lebih lambat dan mahal (walau untuk PIN 4-digit yang memang
berentropi sangat rendah, pertahanan terbaik tetap kombinasi: salt + hash
lambat **+ rate limiting/lockout** di level aplikasi, misalnya memblokir
akun setelah beberapa kali salah input PIN).
