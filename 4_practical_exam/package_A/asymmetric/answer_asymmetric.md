# Station Answer: asymmetric

## 1. Finding
- Weakness: Penggunaan enkripsi RSA deterministik tanpa skema padding acak (Bare RSA / Textbook RSA), serta ruang sampel pesan  yang sangat kecil (hanya 3 kemungkinan status). Hal ini memungkinkan penyerang memulihkan pesan rahasia dengan membandingkan ciphertext terenkripsi terhadap tabel enkripsi pra-komputasi dari seluruh kemungkinan status.
- Location: send_status.py:21

## 2. Evidence
python3 send_status.py PENDING;  python3 send_status.py PENDING 

Output:
Status: PENDING
Ciphertext (hex):
3c7163902cdf5fbe93688421676299f9509557338eea06ca60a648a977910eaab9dfa15c3d94c008ad6e98233c4336f019b5330da03895ddb8ec7e4f2d030d0d3d1d5c8bd0c7e9985510d3663970d742e6f9e3d76635d2f92daa79f359205ab1a1ef9ebf0cbcd987f53552ed9c995b6b94df01c663b60e8c19caf1cbda051518060240ac3694c563b163c3761ff0df9ff88c8a65d1bca08691c2f28a3bff7224970a0977e6da345465cc1f4504dbb7ad64cb8787586bd3f7c222c6f5d9e77bdf73ccec111a6a24b143aa31ffcd0fbfe8e0779637364070c5d8f703443efdc1b1fc31a8ed70721c57091c856e0bb63df81a29426c1c97c2075c7dbf8389b59ce3
Status: PENDING
Ciphertext (hex):
3c7163902cdf5fbe93688421676299f9509557338eea06ca60a648a977910eaab9dfa15c3d94c008ad6e98233c4336f019b5330da03895ddb8ec7e4f2d030d0d3d1d5c8bd0c7e9985510d3663970d742e6f9e3d76635d2f92daa79f359205ab1a1ef9ebf0cbcd987f53552ed9c995b6b94df01c663b60e8c19caf1cbda051518060240ac3694c563b163c3761ff0df9ff88c8a65d1bca08691c2f28a3bff7224970a0977e6da345465cc1f4504dbb7ad64cb8787586bd3f7c222c6f5d9e77bdf73ccec111a6a24b143aa31ffcd0fbfe8e0779637364070c5d8f703443efdc1b1fc31a8ed70721c57091c856e0bb63df81a29426c1c97c2075c7dbf8389b59ce3

## 3. Fix
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

with open(os.path.join(_DIR, "public_key.pem"), "rb") as _f:
    _PUB_KEY = serialization.load_pem_public_key(_f.read())


def encrypt_status(status: bytes) -> bytes:
    """RSA Encryption menggunakan OAEP padding (Probabilistic Encryption)."""
    return _PUB_KEY.encrypt(
        status,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
Verification Proof:
Status: PENDING
Ciphertext (hex):
1231b05331821cc1ae6c8f24ca274269a86768e54dd23bbabfded02cbadcf0b08d7ce9403df42aa974f415237d82e83f2364abdf278c8d78dcc99d9c37680b50b3a1351e6c3d5b9880e1408b9b88cd7cd456d9daecdcbd4629d6863c5aaaef17859ba39b4daf1772721cd772ac4fb0e9a11ba69ddc8be29a5720b12e9dc839c77bccdebdb994c4af0f1148934e3c9c1ae7dac6ee5c13b055d70833a0378b3138d8ee30ec362593496cdebc7ff2d6f23d46f840b2c8b9ae06c878158841c5f96192e3e2ccbe92394bc8425e91207ae27d79e25feea5252cecb0e792887bd7a4e1238da9890fc58616c9499f588b57e1b9e75e693c80250e5bdf9351d170f59fbb
Status: PENDING
Ciphertext (hex):
51ead6a331b532aad2f67d86d26c90a94b5a3d477ef659bdd9f17c28151389720b24eb80c3c74b822ca772058ac24499350ddde8e5a92fe8a5e12f714fb3b853a56ae86e463beaa999e0fa5202d49a0b1cbad14771d92fe7b88294d535083d40f89d988c211fe5fd0517289b4c8a088b8cee980b96b9b16e0258957fc00ff07c63e5a3cc3b8591d8551b1231e5d09eb81084151ab06471a40cf98d9634628735613def74138c7c36d43f3f23d964853cb324ef8c7e1d980c0f19fe949445a0239cb983a55c0b483a65067cafc7e1a90a8fe2ebba4c944a4fd145f3568a0131666d877b44dc49bd9a5d15da34ba017a0be6bfad944f76b1d747621e0126ce3aa4

## 4. Explanation
Penggunaan RSA tanpa padding sangat berbahaya di lingkungan produksi karena sifat enkripsinya yang deterministik, di mana pesan yang sama akan selalu menghasilkan nilai ciphertext yang identik setiap kali dienkripsi. Ketika enkripsi jenis ini digunakan pada ruang status pesan yang terbatas (seperti hanya 3 nilai status pada aplikasi ini), penyerang tidak perlu membobol atau memfaktorkan kunci RSA; mereka cukup mengeksekusi enkripsi pra-komputasi untuk seluruh nilai status lalu mencocokkan ciphertext yang diintersepsi untuk memulihkan pesan rahasia secara instan.