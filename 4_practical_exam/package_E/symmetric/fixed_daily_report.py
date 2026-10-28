import os
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(passphrase.encode())

def encrypt(passphrase: str, plaintext: bytes) -> bytes:
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext

def decrypt(passphrase: str, data: bytes) -> bytes:
    salt = data[:16]
    nonce = data
    ciphertext = data[28:]
    key = derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

if __name__ == "__main__":
    msg1 = b"Report A: 100 items"
    msg2 = b"Report A: 100 items"
    passphrase = "SecureWarehousePassword123!"
    
    ct1 = encrypt(passphrase, msg1)
    ct2 = encrypt(passphrase, msg2)
    
    print("CT1 Hex:", ct1.hex()[:32])
    print("CT2 Hex:", ct2.hex()[:32])
    print("Identical Ciphertext:", ct1 == ct2)
    print("Decrypted CT1:", decrypt(passphrase, ct1).decode())