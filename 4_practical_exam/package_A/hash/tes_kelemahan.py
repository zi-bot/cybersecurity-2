import hashlib

target_hash = "0a09d556dcbca8fde090b62a55ec1d6d:2efbce6667f6d97d7094f03757a1f67b25453457d79da6fec5aa1f304c222325"

recovered_pin = None
for i in range(10000):
    candidate = f"{i:04d}"
    if hashlib.sha1(candidate.encode()).hexdigest() == target_hash:
        recovered_pin = candidate
        break

print("Recovered PIN:", recovered_pin)