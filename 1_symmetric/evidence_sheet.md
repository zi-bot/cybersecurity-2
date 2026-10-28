# Evidence sheet — Track 1 (Symmetric)

Name / Student ID: ______________________   Date: ____________

One row per step. Keep each cell short and checkable, paste real output, and **never write a key value** — write how you obtained it.

| Case | Vulnerable code (file/line) | Your payload / test step | Output evidence | Fix | Re-test result |
|---|---|---|---|---|---|
| C1–C2 Caesar (warm-up, not graded) | `c1_caesar.py` | Menjalankan `brute_force` pada `caesar_message.txt` | `round-trip: True`; `keyspace: 25`; pesan terbaca pada shift 7 | Gunakan AES-GCM untuk data rahasia | Pesan berhasil ditemukan, tetapi Caesar tidak aman untuk data rahasia |
| S1–S2 AES-GCM done right | — | Menjalankan `s1_vault_gcm.py` dan mengubah satu byte ciphertext | `round-trip: True`; `tampered ciphertext rejected: InvalidTag` | AES-GCM dengan nonce acak dan autentikasi; simpan kunci di luar repository | Perubahan ciphertext ditolak dengan `InvalidTag` |
| S3 ECB leaks patterns | `weak_ecb.py`, `compare_blocks.py`, `s3_gcm_blocks.py` | Membandingkan blok ciphertext dari dua file ECB dan dua file AES-GCM | ECB: `[0, 1, 2, 5]`; AES-GCM: `none` | Menggunakan AES-GCM dengan nonce acak | ECB memperlihatkan pola blok yang sama, sedangkan AES-GCM menghasilkan ciphertext berbeda saat plaintext yang sama dienkripsi dua kali |
| S4 ECB without authentication | `weak_ecb.py`, `s4_move_block.py` | Mengubah blok ciphertext ECB dan AES-GCM, lalu mencoba mendekripsinya | ECB: plaintext berubah tetapi tetap terbaca; AES-GCM: `InvalidTag` | Menggunakan AES-GCM untuk mendeteksi perubahan ciphertext | ECB tidak mendeteksi perubahan blok, sedangkan AES-GCM menolak ciphertext yang telah diubah |
| S5 Reused nonce | `weak_fixed_nonce.py`, `s5_nonce_reuse.py` | Memulihkan pesan kedua dengan XOR tanpa mengetahui kunci, lalu menguji dua pesan dengan nonce acak | Pesan kedua berhasil dipulihkan; `Random nonce prevents recovery: True` | Menggunakan nonce unik untuk setiap enkripsi dengan AES-GCM | Penggunaan nonce yang sama dapat membocorkan isi pesan, sedangkan nonce acak mencegah pemulihan melalui percobaan XOR tersebut |
| S6 Embedded key | `weak_embedded_key.py`, `_TEMPLATE_CACHE_B64` | Mencari string Base64 dalam kode sumber, mengambil key saat program berjalan, lalu mendekripsi `order_vault.enc` | `"unit": "B2B Order Operations"`; JSON pesanan berhasil dibaca | Simpan key di luar kode dan repository, misalnya pada file yang terlindungi atau environment variable, serta gunakan nonce acak | Desain baru mencegah serangan ini karena key tidak dapat diambil langsung dari kode sumber; akses key harus dilindungi |

## Short explanation (2–3 sentences each)

- Why are ECB and a fixed nonce dangerous?
ECB is dangerous because identical plaintext blocks produce identical ciphertext blocks, so patterns can be seen. Reusing a nonce with AES-GCM is dangerous because it can weaken encryption security and allow attackers to recover information or forge messages.
- Why does an embedded key make encryption useless?
An embedded key makes encryption useless because attackers can find the key in the source code and use it to decrypt the encrypted data. The key should be stored securely outside the source code.

_____________________________________________________________________
