
import hashlib
import secrets
import hmac

ITERATIONS = 600_000


def store_pin(pin: str) -> str:
    salt = secrets.token_bytes(16)

    pin_hash = hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode(),
        salt,
        ITERATIONS
    )

    return f"{salt.hex()}:{pin_hash.hex()}"


def check_pin(pin: str, stored: str) -> bool:
    try:
        salt_hex, expected_hash = stored.split(":")
        salt = bytes.fromhex(salt_hex)

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            pin.encode(),
            salt,
            ITERATIONS
        )

        return hmac.compare_digest(
            actual_hash.hex(),
            expected_hash
        )
    except (ValueError, TypeError):
        return False


if __name__ == "__main__":
    pin = input("Masukkan PIN 4 digit: ")

    if len(pin) != 4 or not pin.isdigit():
        print("PIN harus terdiri dari 4 digit.")
    else:
        stored = store_pin(pin)
        print("Data PIN tersimpan:", stored)
        print("Verifikasi:", check_pin(pin, stored))
