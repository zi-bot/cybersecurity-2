import os
import hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def hash_pin_secure(pin: str, salt: bytes = None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    derived_key = kdf.derive(pin.encode())
    return salt, derived_key

def verify_pin_secure(pin: str, salt: bytes, expected_key: bytes) -> bool:
    _, derived_key = hash_pin_secure(pin, salt)
    return hmac.compare_digest(derived_key, expected_key)

if __name__ == "__main__":
    # Test PIN sama untuk dua pengguna berbeda
    pin1 = "9012"
    pin2 = "9012"
    
    salt1, key1 = hash_pin_secure(pin1)
    salt2, key2 = hash_pin_secure(pin2)
    
    print("User 1 Hash (hex):", key1.hex()[:32])
    print("User 2 Hash (hex):", key2.hex()[:32])
    print("Identical Hash:", key1 == key2)
    print("Valid Verification:", verify_pin_secure("9012", salt1, key1))
    print("Invalid Verification:", verify_pin_secure("0000", salt1, key1))