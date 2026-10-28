
import pathlib
import sys

TRACK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRACK / "starter"))

import s1_vault_gcm as vault

plaintext = b"EMPTY-----------" * 5

key = vault.create_key()
gcm_a = vault.encrypt_data(key, plaintext)
gcm_b = vault.encrypt_data(key, plaintext)

(TRACK / "my_work" / "gcm_a.enc").write_bytes(gcm_a)
(TRACK / "my_work" / "gcm_b.enc").write_bytes(gcm_b)

print("Same plaintext encrypted twice with AES-GCM")
print("Files saved: gcm_a.enc and gcm_b.enc")
