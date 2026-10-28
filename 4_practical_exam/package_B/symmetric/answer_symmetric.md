# Jawaban — Stasiun Symmetric (AES-GCM)

## 1. Finding

`daily_report.py` menggunakan AES-GCM, tetapi **nonce-nya hardcode** (konstan,
`_NONCE = bytes.fromhex("d5ba4d098a93f620572bc54e")`) dan dipakai ulang untuk
setiap pemanggilan `encrypt()`. AES-GCM **wajib** memakai nonce yang unik
setiap kali enkripsi dilakukan dengan key yang sama. Begitu nonce dipakai
ulang, keamanan GCM runtuh total: kerahasiaan isi pesan bisa dibobol, dan
dalam kasus terburuk tanda tangan otentikasinya pun bisa dipalsukan
("forbidden attack" pada GCM).

Buktinya terlihat jelas: `report_monday.enc` dan `report_tuesday.enc`
dienkripsi dengan key dan nonce yang **sama persis**.

## 2. Evidence

Langkah pembuktian (dijalankan nyata, bukan teori):

1. Dekripsi kedua file memakai kode asli (key & nonce sama-sama ada di
   source code, jadi ini sudah membuktikan kuncinya bocor begitu saja):
   ```
   $ python3 daily_report.py decrypt report_monday.enc
   EXAM-SYM-B|warehouse=Medan|item=filter|quantity=0310

   $ python3 daily_report.py decrypt report_tuesday.enc
   EXAM-SYM-B|warehouse=Medan|item=cable|quantity=0042
   ```

2. Pembuktian inti seranganan "nonce reuse" (seandainya key tidak
   diketahui, tapi attacker punya **sedikit tebakan/crib** isi salah satu
   pesan): karena AES-GCM pada dasarnya adalah stream cipher (CTR mode)
   ditambah tag otentikasi, memakai nonce yang sama berarti **keystream
   yang dipakai untuk kedua pesan itu identik**. Maka:

   ```
   XOR(ciphertext_monday, ciphertext_tuesday) == XOR(plaintext_monday, plaintext_tuesday)
   ```

   Saya hitung langsung dengan Python:
   ```python
   mon = open('report_monday.enc','rb').read()
   tue = open('report_tuesday.enc','rb').read()
   mon_body, tue_body = mon[:-16], tue[:-16]   # buang 16 byte tag GCM
   xor_ct = bytes(a ^ b for a, b in zip(mon_body, tue_body))

   pt_mon = b'EXAM-SYM-B|warehouse=Medan|item=filter|quantity=0310'
   pt_tue = b'EXAM-SYM-B|warehouse=Medan|item=cable|quantity=0042'
   xor_pt = bytes(a ^ b for a, b in zip(pt_mon, pt_tue))

   print(xor_ct.hex())
   print(xor_pt.hex())
   print(xor_ct == xor_pt)
   ```

   Hasil eksekusi nyata:
   ```
   XOR ciphertext bodies : 000000000000000000000000000000000000000000000000000000000000000005080e18000e0d04140f1a1d1d0d440d000703
   XOR plaintexts        : 000000000000000000000000000000000000000000000000000000000000000005080e18000e0d04140f1a1d1d0d440d000703
   MATCH: True
   ```

   Kedua nilai XOR **identik**. Artinya: kalau attacker hanya tahu format/isi
   kira-kira satu laporan (misal tahu laporan Senin berisi template standar),
   ia bisa langsung menghitung XOR itu lalu meng-XOR-kannya lagi ke
   ciphertext laporan Selasa untuk mendapatkan isi laporan Selasa secara utuh
   — **tanpa pernah mengetahui kunci AES-nya sama sekali**.

## 3. Fix

File perbaikan: `daily_report_fixed.py` (satu folder dengan file ini).

Perubahan intinya:
- Nonce **tidak lagi hardcode**. Setiap kali `encrypt()` dipanggil, nonce
  baru 12-byte dibuat dengan `os.urandom(12)` (CSPRNG).
- Karena nonce tidak rahasia (hanya harus unik), nonce tersebut disimpan di
  depan ciphertext (`nonce || ciphertext || tag`), lalu saat dekripsi,
  12 byte pertama dibaca kembali sebagai nonce sebelum didekripsi.

Potongan kode kunci:
```python
def encrypt(plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(_key()).encrypt(nonce, plaintext, None)
    return nonce + ct

def decrypt(blob: bytes) -> bytes:
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(_key()).decrypt(nonce, ct, None)
```

Pengujian nyata menunjukkan dua pesan yang dienkripsi sekarang memiliki
nonce yang berbeda-beda setiap kali:
```
nonce 1: d91a6b26bc3a4e655b84cb26
nonce 2: a48e792414249594f8ba01d7
different nonces: True
```
dan tetap bisa didekripsi balik dengan benar oleh penerima yang sah.

## 4. Explanation

AES-GCM aman **hanya jika** pasangan (key, nonce) tidak pernah dipakai
berulang. Nonce dirancang untuk memastikan setiap pesan punya "keystream"
unik walau kuncinya sama terus; sekali nonce diulang, dua keystream yang
identik membuat dua ciphertext bisa di-XOR satu sama lain sehingga kunci
AES-nya "hilang" dari persamaan — hasil XOR-nya langsung memberi
XOR(plaintext1, plaintext2), yang kalau salah satu plaintext-nya bisa
ditebak (mis. format baku laporan), plaintext lainnya terbongkar seketika.
Lebih parah lagi, GCM memakai nonce yang sama untuk menghitung komponen
otentikasi internal (nilai "H"), sehingga nonce reuse juga membuka celah
pemalsuan tag otentikasi.

Perbaikannya sederhana tapi wajib: **selalu** gunakan nonce acak dan baru
untuk setiap enkripsi, dan sertakan nonce itu bersama ciphertext (nonce
boleh publik, asal unik). Dengan begitu, walau key sama dipakai untuk jutaan
pesan, setiap pesan tetap punya keystream yang berbeda sehingga serangan
XOR di atas tidak bisa dilakukan lagi, dan keamanan semantik AES-GCM
(IND-CPA + integritas) kembali terjaga penuh.
