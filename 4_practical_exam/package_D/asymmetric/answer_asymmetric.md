# Station Answer: Asymmetric

## 1. Finding
- Weakness: Penggunaan Bare RSA tanpa padding, karena status pesan hanya 3 sehingga peretas dapat dengan mudah mencoba mengenkripsi ketiga kata tersebut lalu mencocokkannya dengan data yang ada di order_status.csv tanpa membutuhkan private key
- Location: send_status.py:s22

## 2. Evidence
def encrypt_status(status: bytes) -> bytes:
    """'Bare' RSA: c = m^e mod n."""
    k = (_PUB.n.bit_length() + 7) // 8
    m = int.from_bytes(status.rjust(k, b"\x00"), "big")
    return pow(m, _PUB.e, _PUB.n).to_bytes(k, "big")n>

Output:
PS C:\Cyber Security\cybersecurity-2> python 4_practical_exam/package_D/asymmetric/send_status.py SHIPPED
Status: SHIPPED
Ciphertext (hex):
11423c9511de2d350e7a1bae52aa529372507cc0c83bcf0c524231dbb332c6fe0dbb47bc29b2020d8a9486681a4b146fe638d7b9a884a83ac59090a09cacb02e6fcb7457729ed9c2956514808017b01459d9aa0109c5295d08917df29913d86e73d97028e2f3597605e55b4805f8e90a9bbaa8e28f0f238c9def3d0db829cbfdf7e8c1c37efdba7e60df77a53c7c62889b7830a46a77a4d860e4a61ee1fe4c421bb1f53d2a4564b9a3863f3722ac39608c7edcf3d5bc99a5558b9ff0b4d70242abbd5c3c0958b2406cefa4b739edfb108a4cdce432369d9fc6ccae113ee920d7d5fc6d9ad8670c379c6a8835599e1be90575d7356ee277249f7ce21c5d0327cf

output tersebut sama dengan data di order_status.csv sehingga peretas dapat mencoba mencocokkannya

## 3. Fix
def encrypt_status(status: bytes) -> bytes:
    """Modern RSA encryption with OAEP padding. The ciphertext is returned as bytes."""
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa

    public_key = rsa.RSAPublicNumbers(_PUB.e, _PUB.n).public_key(default_backend())
    ciphertext = public_key.encrypt(
        status,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ciphertext>

Verification Proof:
PS C:\Cyber Security\cybersecurity-2> python 4_practical_exam/package_D/asymmetric/send_status.py SHIPPED
Status: SHIPPED
Ciphertext (hex):
669f5e1117a14e23cb21c4cd0e9c70c242d8fc4608ecf9df9215668e5866b637ed8ed7f01956b98054c7fd2cbf5c162208f010281b2c4f8e6ce881bda22535105576325d0e1d626d396f19d08164a7277c480b97f96216b8c8e8f94630b3fb7dfe98b55036387d0b55cc86e072dbd3d541d156de7648419becf90cc6cd26e5ef3cc26b1c2cec1b5ef921528592a6ebcad566efb9359b2e67a84a717d6730a2f99bf317074bf37fea99427022eeb4bb86989e75b8cf88d71bcacb85ea68a0f0bc754388f647b21f7de46e02bc9af1df2818af04127ab66101aa43c94d9d7f7118664bd868f514df33441aa7a7e2e982981beb4d807f078183bf76deacdb95d07b

output tersebut merupakan hasil yang sama dari sebelumnya tetapi kodenya diacak 

## 4. Explanation
Metode lama sangat berbahaya karena setiap kali pesan yang sama dikirim, hasil kodenya selalu persis sama, sehingga orang asing dapat menebak isi pesan hanya dengan mencocokkan kodenya ke dalam tabel catatan. Dengan memperbaikinya menggunakan sistem RSA-OAEP, sistem secara otomatis menambahkan bumbu acak ke setiap pesan sebelum dienkripsi. Hasilnya, kata yang sama akan menghasilkan kode yang selalu berubah-ubah setiap kali dikirim, sehingga peretas tidak bisa lagi membocorkan rahasia pesan menggunakan tabel pencocokan kode.