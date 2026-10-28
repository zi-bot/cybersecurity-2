import pathlib
import sys

TRACK = pathlib.Path(__file__).resolve().parents[1]

sys.path.insert(0, str(TRACK / "starter"))
sys.path.insert(0, str(TRACK / "weak_code"))

import h1_salted_hash as salted
import h3_kdf
import weak_hash_no_salt as weak

md5_time = h3_kdf.time_per_guess(weak.store_password, count=20000)
kdf_time = h3_kdf.time_per_guess(salted.make_hash, count=3)

print(f"md5: {md5_time:.6f} s per guess")
print(f"KDF: {kdf_time:.6f} s per guess")
print(f"KDF is about {kdf_time / md5_time:.0f} times slower")