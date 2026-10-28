# Evidence sheet — Track 2 (Asymmetric)

Name / Student ID: ______________________   Date: ____________

One row per step. Keep each cell short and checkable, paste real output, and **never write a key value** — write how you obtained it.

| Case | Vulnerable code (file/line) | Your payload / test step | Output evidence | Fix | Re-test result |
|---|---|---|---|---|---|
| A1 RSA-OAEP | `starter/a1_rsa_oaep.py` | Menjalankan pengujian RSA-OAEP dan mencoba mengenkripsi pesan berukuran 190 dan 191 byte melalui `a1_limit.py` | `round-trip: True`; `two encryptions identical? False`; `190 bytes: ok`; `191 bytes: ValueError` | Menggunakan RSA-OAEP dengan kunci 2048-bit dan SHA-256 | Pesan 190 byte berhasil dienkripsi, sedangkan 191 byte ditolak; OAEP menghasilkan ciphertext berbeda untuk pesan yang sama |
| A2 RSA without padding | `weak_code/weak_rsa_no_padding.py`, `encrypt_no_padding` | Mengenkripsi pesan yang sama dua kali dengan RSA tanpa padding, lalu membandingkannya dengan RSA-OAEP | Tanpa padding: `identical? True`; RSA-OAEP: `identical? False`; keduanya berhasil didekripsi | Menggunakan RSA-OAEP dengan padding acak | Enkripsi OAEP menghasilkan ciphertext berbeda untuk pesan yang sama sehingga lebih sulit dikenali melalui perbandingan ciphertext |
| A3 Hybrid encryption | `weak_code/weak_rsa_large_data.py`, `starter/a3_hybrid.py` | Mencoba mengenkripsi data 1.000 byte langsung dengan RSA-OAEP, lalu menguji hybrid encryption dengan data 10.000 byte | Batas RSA: `190 bytes`; data 1.000 byte gagal dienkripsi langsung; hybrid: `round-trip True`; kunci salah: `ValueError`; paket terpotong: `ValueError`; paket kosong: `ValueError`; data diubah: `InvalidTag` | Menggunakan AES-GCM untuk mengenkripsi data dan RSA-OAEP untuk melindungi kunci AES | Data 10.000 byte berhasil dipulihkan; paket tidak valid ditolak dan perubahan ciphertext terdeteksi |

## Short explanation (2–3 sentences each)

- Why is RSA without padding dangerous? Describe the dictionary attack.
RSA without padding is dangerous because encrypting the same message with the same key produces the same ciphertext. In a dictionary attack, an attacker encrypts common or guessed messages and compares the results with the target ciphertext to find a match.
- Why is large data encrypted with a hybrid scheme?
RSA is not suitable for encrypting large data directly because it has a size limit. A hybrid scheme uses AES to encrypt the data and RSA-OAEP to encrypt the AES key, making it more suitable for large amounts of data.
_____________________________________________________________________
