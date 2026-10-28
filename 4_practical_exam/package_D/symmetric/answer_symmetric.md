# Station Answer: Symmetric

## 1. Finding
- Weakness:Penggunaan kode acak yang berulang pad akunci AES GCM yg sama sehingga menyebabkan hasil enkripsi selalu identik daan peretas dapat
- Location: <daily_report.py>:14

## 2. Evidence
_PART_1 = bytes.fromhex("152bc03d7c65cf8e3496d7be4cab15c93ed4b3197c90566885f16daa90c44377")
_PART_2 = bytes.fromhex("00e4c2dbf6f43f71fd96de65af4b89d2080542f37c9eba2fcb9c00d6ec26119d")
_NONCE = bytes.fromhex("cb28d8e8294cf9094defc004")


def _key() -> bytes:
    return bytes(a ^ b for a, b in zip(_PART_1, _PART_2))


def encrypt(plaintext: bytes) -> bytes:
    return AESGCM(_key()).encrypt(_NONCE, plaintext, None)


def decrypt(ciphertext: bytes) -> bytes:
    return AESGCM(_key()).decrypt(_NONCE, ciphertext, None)


## 3. Fix
PART_1 = bytes.fromhex("152bc03d7c65cf8e3496d7be4cab15c93ed4b3197c90566885f16daa90c44377")
_PART_2 = bytes.fromhex("00e4c2dbf6f43f71fd96de65af4b89d2080542f37c9eba2fcb9c00d6ec26119d")


def _key() -> bytes:
    return bytes(a ^ b for a, b in zip(_PART_1, _PART_2))


def encrypt(plaintext: bytes) -> bytes:
    #Encrypts the given plaintext using AES-GCM with a random nonce.
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(data: bytes) -> bytes:
    if len(data) < 12 + 16:  # Minimum length: 12-byte nonce + 16-byte Auth Tag
        raise ValueError("Data terlalu pendek/rusak.")

    nonce = data[:12]
    ciphertext = data[12:]
    return AESGCM(_key()).decrypt(nonce, ciphertext, None)

## 4. Explanation
Penggunaan nonce yang statis/berulang dalam algoritma enkripsi berbasis Galois/Counter Mode (AES-GCM) sangat fatal di lingkungan produksi. AES-GCM secara internal menggunakan keystream untuk melakukan operasi XOR dengan plaintext; jika nonce berulang pada kunci yang sama, keystream yang dihasilkan akan identik, sehingga penyerang dapat memulihkan isi teks asli tanpa harus menebak kunci enkripsi (serangan Reused Key/Nonce Attack). Selain merusak kerahasiaan data, kelemahan ini juga dapat dimanfaatkan untuk memalsukan Authentication Tag (GHASH key leakage), yang merusak aspek integritas data sistem.