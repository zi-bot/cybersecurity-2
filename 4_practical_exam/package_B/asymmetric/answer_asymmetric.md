# Answer Sheet — Asymmetric Station

## 1. Finding
Skrip `send_status.py` menggunakan RSA tanpa padding seperti RSA-OAEP. Karena ruang pesan plaintext space sangat kecil cuma `PROCESSING`, `PENDING`, dan `SHIPPED`, sistem jadinya mudah terkena serangan. kalau tidak ada salt/padding, enkripsi plaintext yang sama akan selalu menghasilkan ciphertext yang persis sama.

## 2. Evidence
Skrip `test_program.py` membuktikan kalau ini dapat dipecahkan dengan mudah tanpa menggunakan kunci privat (private key). Menggunakan enkripsi tiga opsi status yang valid yaitu `PROCESSING`, `PENDING`, `SHIPPED`. Menggunakan kunci publik dan mencocokkan nilai ciphertext pada `order_status.csv`, status asli dari setiap pesanan berhasil dibaca.

## 3. Fix
Gunakan standar enkripsi RSA dengan padding yang aman seperti OAEP (Optimal Asymmetric Encryption Padding) memanfaatkan modul `cryptography.hazmat.primitives.asymmetric.padding`.

Contoh perbaikan fungsi enkripsi pada `send_status.py`:

```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

_OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

def encrypt_status(status: bytes) -> bytes:
    """RSA-OAEP encryption: randomized, so ciphertext differs every call."""
    return _PUB_KEY.encrypt(status, _OAEP)


## 4. Explanation
   RSA standar bersifat deterministik (pesan yang sama menghasilkan enkripsi yang persis sama). Dengan menambahkan padding OAEP, setiap proses enkripsi disisipkan elemen acak sehingga aman dari serangan pencocokan kamus.
   
