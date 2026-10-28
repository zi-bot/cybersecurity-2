# Evidence sheet — Track 3 (Hash)

Name / Student ID: ______________________   Date: ____________

One row per step. Keep each cell short and checkable, paste real output, and **never write a key value** — write how you obtained it.

| Case | Vulnerable code (file/line) | Your payload / test step | Output evidence | Fix | Re-test result |
|---|---|---|---|---|---|
| H1 Salted hash done right | `starter/h1_salted_hash.py` | Membuat dua hash dari kata sandi yang sama, lalu menguji kata sandi benar dan salah | `two hashes differ? True`; `correct password verifies? True`; `wrong password verifies? False` | Menggunakan PBKDF2-SHA256 dan salt acak 16 byte | Ketiga pengujian berhasil; default menggunakan 600.000 iterasi |
| H2 Unsalted MD5 | `weak_code/weak_hash_no_salt.py` | Belum diuji | Belum diuji | Menggunakan hash kata sandi dengan salt acak dan KDF yang lambat, seperti PBKDF2 | Belum diuji |
| H3 Cost per guess | `weak_code/weak_hash_no_salt.py`, `starter/h1_salted_hash.py`, `starter/h3_kdf.py` | Membandingkan waktu rata-rata percobaan MD5 dan PBKDF2 | MD5: `0.00006646` detik; PBKDF2: `0.52726597` detik; rasio: `7932.99x` | Menggunakan PBKDF2 dengan salt unik dan jumlah iterasi yang tinggi | PBKDF2 sekitar `7932.99x` lebih lambat daripada MD5 pada pengujian ini |

## Short explanation (2–3 sentences each)

- Two users can have the same hash if they use the same password and no salt is used. Some users survived the dictionary attack because their passwords were not found in the attacker's dictionary.
- Salt makes hashes different even when users have the same password. A higher iteration count makes password guessing slower, so it is harder for attackers to guess passwords.

_____________________________________________________________________
