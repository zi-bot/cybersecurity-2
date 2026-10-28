# Ujian Praktik Kriptografi — Praktikum 2 (75 menit, individu)

> **Bahasa:** [English Version](exam_instructions.md) | **Versi Bahasa Indonesia**

> [!IMPORTANT]
> - Kerjakan ujian ini secara mandiri hanya menggunakan berkas yang disediakan di dalam folder paket penugasan Anda.
> - **DILARANG** menuliskan kunci privat (private key) mentah ke dalam berkas laporan Anda.
> - **DILARANG** mengerjakan folder paket selain paket yang ditugaskan kepada Anda. Z
> - **DILARANG** bekerja sama dengan mahasiswa lain atau membagikan jawaban Anda.
> - **DILARANG** merancang algoritma enkripsi buatan sendiri; gunakan primitif standar yang telah diaudit dari pustaka `cryptography` atau pustaka standar Python.
> - **DILARANG** menggunakan alat kecerdasan buatan (AI) untuk menghasilkan isi berkas jawaban Anda. Anda boleh bertanya kepada AI hanya untuk klarifikasi sintaksis Python atau pustaka kriptografi, namun bukan untuk membuat luaran tugas Anda. (**Segala bentuk jawaban yang dihasilkan oleh AI dikategorikan sebagai kecurangan akademik dan berakibat nilai 0 untuk stasiun terkait serta untuk seluruh ujian praktik. Hati-hati saat mengajukan pertanyaan kepada AI.**)
> - Bekerjalah secara teliti dan hindari kesalahan ketik (*typo*); jawaban Anda harus dapat direproduksi secara persis oleh penguji.
> - **SEGALA PELANGGARAN terhadap aturan di atas akan berakibat nilai 0 untuk stasiun terkait serta untuk seluruh ujian praktik.**

Anda menerima satu folder paket penugasan (contoh: `package_A/`, `package_B/`, `package_C/`, `package_D/`, atau `package_E/`) yang berisi **tiga stasiun praktikum**.  
Total waktu pengerjaan: **75 menit** (alokasi yang disarankan: **25 menit per stasiun**).  
Anda diperbolehkan menggunakan Python, pustaka standar (standard library), pustaka `cryptography`, serta catatan praktikum Anda.

---

## Luaran & Rubrik Penilaian

Untuk **setiap** stasiun, kumpulkan satu berkas jawaban dalam format Markdown di dalam direktori paket penugasan Anda:
- `answer_symmetric.md` (untuk stasiun `symmetric/`)
- `answer_asymmetric.md` (untuk stasiun `asymmetric/`)
- `answer_hash.md` (untuk stasiun `hash/`)

> [!TIP]
> **Alur Kerja Kode (Membuat Berkas Baru vs Mengubah Berkas Lama):**
> Saat membuat kode perbaikan untuk Bagian 3, **buatlah berkas baru** (misalnya: `fixed_daily_report.py`, `fixed_send_status.py`, `fixed_pin.py`) alih-alih menimpa langsung skrip awal yang rentan. Hal ini menjaga berkas skrip asli tetap utuh sehingga bukti serangan Bagian 2 tetap dapat direproduksi dan memudahkan pembuktian verifikasi secara berdampingan.
> **Perhatian:** Baik Anda membuat berkas skrip terpisah maupun mengubah di tempat, **Anda wajib menyalin seluruh kode perbaikan dan bukti luarannya langsung ke Bagian 3 (`## 3. Fix`) pada berkas jawaban Markdown Anda**, karena penilaian penguji berbasis pada berkas Markdown tersebut.

Setiap berkas jawaban dinilai berdasarkan **Rubrik Praktikum RPS (Rubrik C2 — Praktikum Defensif)** yang mencakup empat dimensi penilaian (100 poin per stasiun):

1. **Ketepatan Hasil (35 poin)**
   - **Finding (10 poin)**: Mengidentifikasi kelemahan kriptografi dan lokasi persisnya (nama berkas dan nomor baris) secara tepat dalam 1–2 kalimat.
   - **Evidence (25 poin)**: Menyertakan perintah/kode Python yang dapat direproduksi beserta luaran eksekusinya yang membuktikan pemulihan data target atau keberhasilan eksploitasi secara 100% akurat.
2. **Metode & Pengamanan (25 poin)**
   - **Fix Implementation (25 poin)**: Menyediakan kode pengganti Python yang berfungsi dengan benar untuk memperbaiki kelemahan menggunakan primitif standar yang teruji dari pustaka `cryptography` atau pustaka standar, tanpa membocorkan rahasia atau menuliskan kunci mentah.
3. **Verifikasi & Batasan (25 poin)**
   - **Verification Proof (15 poin)**: Bukti eksekusi nyata yang membuktikan bahwa serangan atau eksploitasi sebelumnya kini gagal terhadap kode perbaikan Anda.
   - **Security Boundaries & Limitations (10 poin)**: Menjelaskan batasan operasional dan sisa keterbatasan keamanan dari solusi yang diterapkan (misalnya: batas ketahanan brute-force luring untuk rahasia entropi rendah seperti PIN 4-digit, serta perlunya mekanisme rate limiting di tingkat aplikasi).
4. **Penjelasan Individu (15 poin)**
   - **Explanation (15 poin)**: Menjelaskan secara ringkas dan lugas dengan kalimat sendiri mengapa kelemahan awal tersebut sangat berbahaya jika berada pada sistem produksi nyata.

---

## Ringkasan Stasiun Ujian

| Stasiun | Skenario dan Berkas yang Disediakan | Target Capaian |
|---|---|---|
| `symmetric/` | Pelaporan gudang harian (`daily_report.py`, `report_monday.enc`, `report_tuesday.enc`) | Pulihkan teks asal (plaintext) kedua laporan terenkripsi, tunjukkan kelemahan mendasar dalam skema enkripsi, dan terapkan perbaikan enkripsi berkas yang aman. |
| `asymmetric/` | Pengiriman status pesanan ke mitra (`send_status.py`, `order_status.csv`, `public_key.pem`) | Pulihkan status asli seluruh pesanan pada `order_status.csv` hanya dengan kunci publik, jelaskan mengapa skema saat ini rentan, dan terapkan pengiriman status yang aman. |
| `hash/` | Penyimpanan PIN kasir pada aplikasi legacy (`weak_pin.py`, `pin_dump.csv`) | Pecahkan dan pulihkan seluruh PIN 4-digit dari `pin_dump.csv`, jelaskan cacat penyimpanan, terapkan perbaikan penyimpanan kredensial yang aman, dan jelaskan sisa batas keamanannya. |

---

## Perintah Bermanfaat untuk Ujian

### Pengujian Lingkungan dan Validasi Pengumpulan
```bash
# Periksa lingkungan Python dan pustaka cryptography
python3 -c "import cryptography; print(cryptography.__version__)"

# Masuk ke direktori paket penugasan Anda
cd 4_practical_exam/package_A       # (atau package_B, package_C, package_D, package_E sesuai penugasan Anda)

# Jalankan validator kapan saja selama ujian untuk memeriksa kelengkapan berkas jawaban
python3 validate_submission.py
```

---

### Stasiun 1: `symmetric/` — Pelaporan Gudang Harian
```bash
cd symmetric

# 1. Tampilkan informasi penggunaan skrip dan opsi yang tersedia
python3 daily_report.py

# 2. Dekripsi berkas laporan gudang terenkripsi menggunakan skrip yang disediakan
python3 daily_report.py decrypt report_monday.enc
python3 daily_report.py decrypt report_tuesday.enc

# 3. Uji enkripsi data menggunakan skrip
python3 daily_report.py encrypt <berkas_input> <berkas_output>
```

---

### Stasiun 2: `asymmetric/` — Pengiriman Status Pesanan ke Mitra
```bash
cd ../asymmetric

# 1. Tampilkan informasi penggunaan skrip dan status yang valid
python3 send_status.py

# 2. Enkripsi status kandidat untuk mengamati bagaimana skrip menghasilkan teks sandi (ciphertext)
python3 send_status.py PROCESSING
python3 send_status.py PENDING
python3 send_status.py SHIPPED

# 3. Periksa catatan status pesanan yang terenkripsi
head -n 5 order_status.csv
```

---

### Stasiun 3: `hash/` — Penyimpanan PIN Kasir Legacy
```bash
cd ../hash

# 1. Tampilkan informasi penggunaan skrip
python3 weak_pin.py

# 2. Hitung nilai hash dari kandidat PIN menggunakan skrip
python3 weak_pin.py 1234
python3 weak_pin.py 0000

# 3. Periksa berkas bocoran hash kasir
head -n 5 pin_dump.csv
```

---

## Panduan Evaluasi untuk Bagian 3 (Fix & Bukti Verifikasi)

Untuk mendapatkan poin penuh pada **Bagian 3 (Fix)**, laporan Anda harus menyertakan kode pengganti Python yang berfungsi serta bukti terverifikasi bahwa eksploitasi sebelumnya tidak lagi dapat dilakukan:

### 1. Stasiun 1 (`symmetric/`) — Perbaikan Enkripsi Berkas
- **Tujuan:** Perbaiki implementasi enkripsi berkas agar kerahasiaan laporan tetap terlindungi bahkan ketika mengenkripsi banyak berkas menggunakan kunci yang sama.
- **Panduan:** Teliti bagaimana kunci kriptografi dan parameter inisialisasi dikelola pada `daily_report.py`. Pada kondisi apa enkripsi berulang membocorkan relasi antar teks asal? Bagaimana data inisialisasi seharusnya dikelola agar penerima dapat mendekripsi berkas secara mandiri tanpa merusak kerahasiaan?
- **Syarat Bukti:** Jalankan kode perbaikan Anda pada dua pesan uji coba dan tunjukkan bahwa teks sandi yang dihasilkan tidak lagi membocorkan hubungan antar teks asal maupun pola lintas pesan.

### 2. Stasiun 2 (`asymmetric/`) — Perbaikan Pengiriman Status Pesanan
- **Tujuan:** Ganti mekanisme kunci publik yang rentan dengan skema enkripsi kunci publik modern yang melindungi kerahasiaan pesan.
- **Panduan:** Selidiki mengapa implementasi kunci publik saat ini memungkinkan pihak ketiga mengetahui isi pesan tanpa memiliki kunci privat, terutama jika ruang variasi pesan berukuran kecil. Mekanisme standar apa yang menjamin bahwa enkripsi berulang dari pesan yang sama tidak dapat diidentifikasi atau dicocokkan dengan tabel pra-komputasi?
- **Syarat Bukti:** Enkripsi status kandidat yang sama berkali-kali menggunakan kunci publik dan tunjukkan bahwa teks sandi yang dihasilkan teracak sempurna dan kebal terhadap pencocokan kamus pra-komputasi.

### 3. Stasiun 3 (`hash/`) — Perbaikan Penyimpanan PIN
- **Tujuan:** Ganti penyimpanan hash mentah yang lemah dengan implementasi penyimpanan kredensial yang aman.
- **Panduan:** Selidiki mengapa menyimpan hash mentah tidak aman untuk kredensial pengguna. Bagaimana skema penyimpanan dapat memastikan bahwa dua pengguna dengan PIN yang sama tidak menghasilkan nilai simpanan yang identik? Bagaimana faktor beban komputasi dapat ditingkatkan untuk menghalau serangan tebakan luring (offline brute-force)?
- **Syarat Bukti:** Simpan PIN 4-digit yang sama untuk dua akun uji coba yang berbeda dan tunjukkan bahwa nilai simpanannya berbeda total, serta buktikan bahwa fungsi verifikasi Anda berhasil memvalidasi PIN yang benar dan menolak PIN yang salah dalam waktu konstan.

---

## Validasi Mandiri Pengumpulan Tugas

Folder paket penugasan Anda telah dilengkapi dengan skrip `validate_submission.py`. Jalankan skrip ini kapan saja dari direktori utama paket Anda:

```bash
python3 validate_submission.py
```

Validator otomatis ini memeriksa bahwa:
- Ketiga berkas jawaban (`answer_symmetric.md`, `answer_asymmetric.md`, `answer_hash.md`) telah tersedia.
- Keempat bagian wajib (`## 1. Finding`, `## 2. Evidence`, `## 3. Fix`, `## 4. Explanation`) ada di setiap berkas.
- Tidak ada teks penampung template (`<...>`) yang tertinggal.
- Tidak ada blok teks kunci privat mentah yang diunggah.

---

## Petunjuk Pengumpulan Tugas
Commit seluruh berkas jawaban Markdown(*.md) beserta kode perbaikan Python Anda ke repositori dengan menggunakan branch masing-masing (feat/<nama_nim>) bukan ke branch `main`. Pastikan commit Anda bersih, ringkas, dan jelas. Buat pull request ke branch `main` untuk penilaian. Penguji tidak akan menilai berkas yang belum di-commit atau berkas yang berada di luar folder paket penugasan Anda.

## Template Berkas Jawaban

Gunakan struktur berikut untuk setiap laporan stasiun Anda (**pertahankan nama judul bagian bahasa Inggris agar validator otomatis dapat membaca berkas Anda**):

```markdown
# Station Answer: <symmetric | asymmetric | hash>

## 1. Finding
- Weakness: <Deskripsi ringkas kelemahan keamanan yang ditemukan>
- Location: <nama_berkas>:<nomor_baris>

## 2. Evidence
<Kode Python atau perintah yang digunakan untuk memulihkan data atau mendemonstrasikan serangan>

Output:
<Luaran eksekusi yang membuktikan keberhasilan pemulihan data atau hasil eksploitasi>

## 3. Fix
<Kode implementasi perbaikan dalam Python>

Verification Proof:
<Luaran eksekusi yang membuktikan bahwa serangan sebelumnya gagal terhadap kode perbaikan>

## 4. Explanation
<Satu paragraf yang menjelaskan mengapa kelemahan ini berbahaya dalam sistem produksi nyata, diikuti dengan analisis batasan operasional atau batas keamanan solusi yang diterapkan.>
```
