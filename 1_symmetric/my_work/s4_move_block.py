
import pathlib
import sys

TRACK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRACK / "starter"))
sys.path.insert(0, str(TRACK / "weak_code"))

import weak_ecb
import s1_vault_gcm as vault
from cryptography.exceptions import InvalidTag

# Uji ECB: ubah salah satu blok ciphertext
data = (TRACK / "artifacts" / "order_ecb_a.enc").read_bytes()
blocks = [data[i:i + 16] for i in range(0, len(data), 16)]

blocks[1] = blocks[4]
modified_data = b"".join(blocks)

print("ECB after moving a block:")
print(weak_ecb.decrypt_ecb(modified_data))

# Uji AES-GCM: ubah urutan blok ciphertext
key = vault.create_key()
plaintext = b"EMPTY-----------" * 5
package = vault.encrypt_data(key, plaintext)

nonce = package[:12]
body = package[12:]

# Tukar dua blok 16-byte pada ciphertext body
body_blocks = [body[i:i + 16] for i in range(0, len(body), 16)]
body_blocks[0], body_blocks[1] = body_blocks[1], body_blocks[0]
modified_package = nonce + b"".join(body_blocks)

print("AES-GCM after moving a block:")
try:
    vault.decrypt_data(key, modified_package)
    print("ERROR: modified ciphertext was accepted")
except InvalidTag:
    print("InvalidTag")
