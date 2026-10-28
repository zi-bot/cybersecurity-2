
import pathlib
import sys
import tempfile

TRACK = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TRACK / "starter"))

import s1_vault_gcm as vault
from cryptography.exceptions import InvalidTag


def main():
    key = vault.create_key()
    wrong_key = vault.create_key()
    package = vault.encrypt_data(key, b"Dummy order data")

    try:
        vault.decrypt_data(wrong_key, package)
        print("wrong key: NOT REJECTED")
    except InvalidTag:
        print("wrong key: InvalidTag")

    try:
        vault.decrypt_data(key, b"x" * 10)
        print("short package: NOT REJECTED")
    except ValueError:
        print("short package: ValueError")

    with tempfile.TemporaryDirectory() as temp:
        source = pathlib.Path(temp) / "broken.enc"
        destination = pathlib.Path(temp) / "output.txt"
        source.write_bytes(b"x" * 40)

        try:
            vault.decrypt_file(key, str(source), str(destination))
        except (InvalidTag, ValueError):
            pass

        print("no output file left:", not destination.exists())


if __name__ == "__main__":
    main()
