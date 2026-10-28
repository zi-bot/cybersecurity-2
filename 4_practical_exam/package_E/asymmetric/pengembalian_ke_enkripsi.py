from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization

def load_public_key(pem_path: str):
    with open(pem_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def encrypt_status_secure(public_key, status: bytes) -> bytes:
    return public_key.encrypt(
        status,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

if __name__ == "__main__":
    pub_key = load_public_key("public_key.pem")
    status = b"PENDING"
    
    ct1 = encrypt_status_secure(pub_key, status)
    ct2 = encrypt_status_secure(pub_key, status)
    
    print("CT1 Hex:", ct1.hex()[:32])
    print("CT2 Hex:", ct2.hex()[:32])
    print("Identical Ciphertext:", ct1 == ct2)