## 1. Finding
- Weakness: Implementasi awal menggunakan enkripsi RSA tanpa padding yang aman (bare RSA). Karena status pesanan hanya terdiri dari beberapa pilihan yang mudah ditebak, penyerang yang memiliki kunci publik berpotensi menguji setiap kemungkinan status untuk mencocokkannya dengan ciphertext.
- Location: send_status.py - fungsi encrypt_status() - 23-32

## 2. Evidence
Pengujian dilakukan dengan mengenkripsi status yang sama beberapa kali menggunakan implementasi RSA-OAEP yang telah diperbaiki.

Perintah:
python send_status.py PENDING
python send_status.py PENDING

Output:
(.venv) PS C:\Users\ACER\CyberSecurity\cybersecurity-2\4_practical_exam\package_C\asymmetric> python send_status.py PENDING
Status: PENDING
Ciphertext (hex):
a1e1ec3791e8ae55fab4518083c377638f04da89bcf6c65d948f0bfd8e11b2557d2df916c357d3427c8789143e4ad08f2ed758076124f900f87ce78d15b6e7e98015c9b24b0ee5b7a1cfb55c1dc19c6971aaaff2b793521a8e5c98f5175475c22fbc22176ca542504d90f081d326d47b1d16f0656f342fb132a321a91965a4336471637842b917afdf4d9d1eed646394c964eccd6967be95e880b6b289968c30f291f990609f862942640863876fd53be5f8480581e9867bd5d7ec8d6b928fdc35a2319e2bf8f68ad15cb300a9ddcac4de3e1dda76c857c0551d14ccc62ba63bb016f76aae530a8aa316fba58cbc46ca426e28827333fd391fac00fb3a0ac4d6
(.venv) PS C:\Users\ACER\CyberSecurity\cybersecurity-2\4_practical_exam\package_C\asymmetric> python send_status.py PENDING
Status: PENDING
Ciphertext (hex):
19f15de84d9052c02e66363a59a2cae67b46d8bc2a1cd9b9b6bf33f775602a477b95a2837439201cb4e0d88e6455959267f2c0de0de93e039682bb4142871c9762535216c1687c6ec8d68b9cc7d0ffe55042a47a3ad3bf6a9fc0d63d5138c92bc30da1225f6ff930886fe33f203edd318e05d2bce677b76c2c1f74faf4921601d358ee4fb6645f58ca040349c93e8d1737946cc0e28d0608e17e9e1fa713f649bb1e86a7ced047421e70f8fe4021352a0db71d7e45f7aa3738ec5d79e4c10395558f7226228f33a2286e39324b0755481d96741fa3c89bd92cc3f0b9f0782db193481d38a7fe11990734f4356668cc2f5b2323ba5597e83a47a09f5c0f9d2256

Hasil pengamatan: Ciphertext yang dihasilkan berbeda meskipun status yang dienkripsi sama, yaitu PENDING. Hal ini menunjukkan perilaku acak (randomized) dari RSA-OAEP.

Catatan: Pengujian ini membuktikan perilaku implementasi yang telah diperbaiki. Pengujian terpisah terhadap implementasi awal yang rentan masih diperlukan untuk membuktikan kelemahan sebelumnya.

## 3. Fix
Perbaikan dilakukan dengan mengganti enkripsi RSA biasa menjadi RSA-OAEP menggunakan SHA-256 untuk algoritma hash OAEP dan MGF1.

def encrypt_status(status: bytes) -> bytes:
    """Mengenkripsi status menggunakan RSA-OAEP dengan SHA-256."""
    return _PUB.encrypt(
        status,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

Verification Proof:

Jalankan perintah berikut dua kali:

python send_status.py PENDING
python send_status.py PENDING

Hasil yang diharapkan:

-Kedua eksekusi berhasil dijalankan.
-Kedua output menampilkan status PENDING.
-Ciphertext yang dihasilkan berbeda karena RSA-OAEP menggunakan padding acak.

## 4. Explanation
Enkripsi RSA tanpa padding yang aman tidak cocok untuk melindungi pesan yang mudah ditebak. Jika penyerang mengetahui kunci publik dan pilihan status yang mungkin digunakan, penyerang berpotensi mengidentifikasi pesan dengan menguji setiap kemungkinan status. RSA-OAEP mengurangi kelemahan tersebut melalui padding acak sehingga enkripsi terhadap plaintext yang sama dapat menghasilkan ciphertext berbeda. Implementasi ini menggunakan SHA-256 dan MGF1 dengan SHA-256 sebagai bagian dari mekanisme RSA-OAEP. Namun, perbaikan ini tidak menghilangkan seluruh risiko keamanan. Kunci privat harus tetap rahasia, sistem penerima harus memvalidasi status setelah dekripsi, dan aplikasi perlu melindungi diri dari penyalahgunaan pengiriman pesan serta kebocoran kunci. Perbedaan ciphertext saja tidak membuktikan bahwa seluruh sistem telah aman.