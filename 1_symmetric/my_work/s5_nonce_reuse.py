
import pathlib
import sys

TRACK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRACK / "starter"))

import s1_vault_gcm as vault

# Baca dua ciphertext dan plaintext pertama yang bocor
c1 = (TRACK / "artifacts" / "reused_nonce_1.enc").read_bytes()
c2 = (TRACK / "artifacts" / "reused_nonce_2.enc").read_bytes()
p1 = (TRACK / "artifacts" / "reused_nonce_1.txt").read_bytes()

# Pulihkan pesan kedua tanpa mengetahui kuncinya
n = len(p1)
p2 = bytes(c1[i] ^ c2[i] ^ p1[i] for i in range(n))

print("Recovered message 2:")
print(p2.decode())

# Uji perbaikan: gunakan nonce acak dari AES-GCM

message1 = b"STATUS=SHIPPED"
message2 = b"STATUS=PENDING"

key = vault.create_key()
package1 = vault.encrypt_data(key, message1)
package2 = vault.encrypt_data(key, message2)

# Lewati nonce 12 byte dan tag 16 byte
body1 = package1[12:-16]
body2 = package2[12:-16]

# Coba pulihkan pesan kedua menggunakan XOR
recovered = bytes(
    body1[i] ^ body2[i] ^ message1[i]
    for i in range(len(message1))
)

print("Random nonce prevents recovery:", recovered != message2)
